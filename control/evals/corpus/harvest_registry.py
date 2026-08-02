#!/usr/bin/env python3
"""Harvest real, live MCP tool definitions for the benign side of the
tool-poisoning corpus.

The public MCP registry (https://registry.modelcontextprotocol.io) only
catalogs *servers* (name, description, version, connection URL) — its own
OpenAPI spec describes it as serving "metadata about MCP servers," and its
ServerDetail schema has no `tools` or `inputSchema` field at all. To get
real per-tool name/description/inputSchema, this script:

  1. Pages through the registry's /v0.1/servers?version=latest listing.
  2. For each server exposing a `streamable-http` remote, speaks just enough
     MCP (initialize -> notifications/initialized -> tools/list) to pull its
     actual, live tool definitions.
  3. Records every attempt — success or failure — to a log file, so the
     corpus README can document attrition honestly instead of silently
     dropping unreachable servers.

Nothing here is invented: every sample written to the harvest log came back
verbatim (name/description/inputSchema) from a real server's tools/list
response. Only `streamable-http` remotes are attempted (not stdio packages,
which would mean executing arbitrary third-party code, and not `sse`
remotes, the older dual-endpoint transport this script doesn't implement).

Usage:
    python3 harvest_registry.py --target 100 --out harvest_log.jsonl
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

try:
    import certifi

    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:  # pragma: no cover - fall back to the system trust store
    SSL_CONTEXT = ssl.create_default_context()

REGISTRY_BASE = "https://registry.modelcontextprotocol.io"
CLIENT_INFO = {"name": "portcullis-corpus-builder", "version": "0.1.0"}
PROTOCOL_VERSION = "2025-06-18"
REQUEST_TIMEOUT = 8  # seconds
MAX_TOOLS_PER_SERVER = 3  # cap so ~100 samples span many servers, not one


@dataclass
class Attempt:
    server_name: str
    server_version: str
    remote_url: str
    registry_source: str
    outcome: str  # "ok" | "skipped_no_remote" | "error:<stage>"
    detail: str = ""
    tools_harvested: int = 0


def http_post_json(url: str, payload: dict, session_id: str | None) -> tuple[dict, dict]:
    """POST a JSON-RPC message and return (parsed_body, response_headers).

    Handles both a plain application/json response and a Streamable HTTP
    text/event-stream response (parses the JSON out of the SSE "data:"
    lines).
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **({"Mcp-Session-Id": session_id} if session_id else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=SSL_CONTEXT) as resp:
        raw = resp.read()
        headers = dict(resp.headers.items())
        content_type = resp.headers.get("Content-Type", "")

    if not raw:
        return {}, headers

    if "text/event-stream" in content_type:
        data_lines = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
        if not data_lines:
            return {}, headers
        # A single request/response exchange on Streamable HTTP carries one
        # JSON-RPC message per SSE event; take the last complete one.
        parsed = json.loads(data_lines[-1])
        return parsed, headers

    return json.loads(raw.decode("utf-8", errors="replace")), headers


def try_harvest_server(name: str, version: str, remote_url: str, registry_source: str) -> tuple[Attempt, list[dict]]:
    """Attempt initialize -> notifications/initialized -> tools/list against
    one live remote. Returns the attempt record and any tool samples pulled.
    """
    try:
        init_body, init_headers = http_post_json(
            remote_url,
            {
                "jsonrpc": "2.0",
                "id": "corpus-initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": CLIENT_INFO,
                },
            },
            session_id=None,
        )
    except Exception as exc:  # noqa: BLE001 - real-world registry URLs are messy; any failure means "skip this server"
        return Attempt(name, version, remote_url, registry_source, "error:initialize", f"{type(exc).__name__}: {exc}"), []

    if isinstance(init_body, dict) and init_body.get("error"):
        return Attempt(name, version, remote_url, registry_source, "error:initialize_rejected", json.dumps(init_body["error"])), []

    session_id = init_headers.get("Mcp-Session-Id") or init_headers.get("mcp-session-id")

    try:
        # Notification: no response body expected either way.
        http_post_json(
            remote_url,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            session_id=session_id,
        )
    except Exception:  # noqa: BLE001 - many servers 202/close with an empty body here; that's fine either way.
        pass

    try:
        list_body, _ = http_post_json(
            remote_url,
            {"jsonrpc": "2.0", "id": "corpus-tools-list", "method": "tools/list", "params": {}},
            session_id=session_id,
        )
    except Exception as exc:  # noqa: BLE001 - real-world registry URLs are messy; any failure means "skip this server"
        return Attempt(name, version, remote_url, registry_source, "error:tools_list", f"{type(exc).__name__}: {exc}"), []

    if isinstance(list_body, dict) and list_body.get("error"):
        return Attempt(name, version, remote_url, registry_source, "error:tools_list_rejected", json.dumps(list_body["error"])), []

    result = list_body.get("result", {}) if isinstance(list_body, dict) else {}
    tools = result.get("tools", [])
    if not tools:
        return Attempt(name, version, remote_url, registry_source, "error:no_tools", "tools/list returned an empty array"), []

    samples = []
    for tool in tools[:MAX_TOOLS_PER_SERVER]:
        if "name" not in tool or "description" not in tool:
            continue
        samples.append(
            {
                "tool_name": tool.get("name"),
                "tool_description": tool.get("description"),
                "input_schema": tool.get("inputSchema", {}),
                "server_name": name,
                "server_version": version,
                "remote_url": remote_url,
                "registry_source": registry_source,
            }
        )

    return Attempt(name, version, remote_url, registry_source, "ok", tools_harvested=len(samples)), samples


def iter_latest_servers():
    """Yield (name, version, remote_url_or_None) for every server in the
    registry's latest-version listing, following pagination cursors."""
    cursor = None
    while True:
        url = f"{REGISTRY_BASE}/v0.1/servers?version=latest&limit=100"
        if cursor:
            url += f"&cursor={urllib.parse.quote(cursor)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=SSL_CONTEXT) as resp:
            page = json.loads(resp.read().decode("utf-8"))

        for entry in page.get("servers", []):
            server = entry.get("server", {})
            name = server.get("name", "")
            version = server.get("version", "")
            remote_url = None
            for remote in server.get("remotes", []) or []:
                if remote.get("type") == "streamable-http" and remote.get("url"):
                    remote_url = remote["url"]
                    break
            yield name, version, remote_url

        cursor = page.get("metadata", {}).get("nextCursor")
        if not cursor:
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, default=100, help="stop once this many tool samples are harvested")
    parser.add_argument("--max-servers", type=int, default=500, help="give up after attempting this many servers")
    parser.add_argument("--out", default="harvest_log.jsonl", help="path to write the full attempt log (one JSON object per line)")
    parser.add_argument("--samples-out", default="harvest_samples.jsonl", help="path to write harvested tool samples")
    args = parser.parse_args()

    servers_attempted = 0
    samples_harvested = 0
    ok_count = 0

    registry_list_source = f"{REGISTRY_BASE}/v0.1/servers?version=latest"

    # Write incrementally (flushing after every line) rather than buffering
    # in memory and writing once at the end: real-world registry data is
    # messy (malformed URLs, unexpected transports), and a script that dies
    # partway through should not lose every attempt made before the crash.
    with open(args.out, "w") as log_f, open(args.samples_out, "w") as samples_f:
        for name, version, remote_url in iter_latest_servers():
            if samples_harvested >= args.target or servers_attempted >= args.max_servers:
                break

            if not remote_url:
                attempt = Attempt(name, version, "", registry_list_source, "skipped_no_streamable_http_remote")
                log_f.write(json.dumps(attempt.__dict__) + "\n")
                log_f.flush()
                continue

            servers_attempted += 1
            attempt, new_samples = try_harvest_server(name, version, remote_url, registry_list_source)
            log_f.write(json.dumps(attempt.__dict__) + "\n")
            log_f.flush()

            for s in new_samples:
                samples_f.write(json.dumps(s) + "\n")
            samples_f.flush()
            samples_harvested += len(new_samples)
            if attempt.outcome == "ok":
                ok_count += 1

            status = f"{attempt.outcome}"
            if attempt.outcome == "ok":
                status += f" ({attempt.tools_harvested} tools)"
            print(f"[{servers_attempted:4d}] {name}@{version} -> {status}")

    print(f"\nServers attempted: {servers_attempted}")
    print(f"Servers that yielded tools: {ok_count}")
    print(f"Tool samples harvested: {samples_harvested}")
    print(f"Attempt log written to: {args.out}")
    print(f"Samples written to: {args.samples_out}")


if __name__ == "__main__":
    main()
