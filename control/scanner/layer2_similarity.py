"""Layer 2: embedding similarity against the known-attack corpus.

Embeds the attack corpus (../evals/corpus/corpus.jsonl, malicious rows only)
into pgvector using an HNSW index with cosine distance, per the task spec.
Scores an incoming description by its max cosine similarity to any known
attack. The threshold is configurable and, like layer 1, deliberately not
tuned against the full corpus yet (see cascade.py / task constraint) — the
default below is a placeholder.

Both the embedding provider and the vector store sit behind small
interfaces (Embedder / VectorStore) so this module's own tests run without
a live Postgres instance or a network call: production wires
SentenceTransformerEmbedder + PgVectorStore; tests use a fake embedder and
an in-memory store. Embeddings run locally via sentence-transformers
(all-MiniLM-L6-v2) rather than a hosted embeddings API — no API key
required, no per-call network dependency once the model weights are cached.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, Sequence

DEFAULT_TABLE = "attack_embeddings"
# all-MiniLM-L6-v2's embedding dimensionality; PgVectorStore needs the exact
# dimension to declare the pgvector column.
DEFAULT_EMBEDDING_DIM = 384


class Embedder(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one embedding vector per input text, same order."""
        ...


class VectorStore(Protocol):
    def upsert(self, id: str, embedding: Sequence[float], attack_class: str) -> None: ...

    def max_similarity(self, embedding: Sequence[float]) -> tuple[float, str | None, str | None]:
        """Returns (similarity, nearest_id, nearest_attack_class).

        similarity is a cosine similarity in [-1, 1] (higher = closer).
        Returns (-1.0, None, None) when the store is empty.
        """
        ...


@dataclass(frozen=True)
class Layer2Result:
    verdict: str  # "malicious" | "benign"
    similarity: float
    nearest_id: str | None
    nearest_attack_class: str | None
    threshold: float


class Layer2Similarity:
    def __init__(self, embedder: Embedder, store: VectorStore, threshold: float = 0.85):
        self.embedder = embedder
        self.store = store
        self.threshold = threshold

    def score(self, description: str) -> Layer2Result:
        embeddings = self.embedder.embed([description])
        if not embeddings:
            raise RuntimeError("embedder returned no embeddings for a single input")
        embedding = embeddings[0]

        similarity, nearest_id, nearest_class = self.store.max_similarity(embedding)
        verdict = "malicious" if similarity >= self.threshold else "benign"
        return Layer2Result(
            verdict=verdict,
            similarity=similarity,
            nearest_id=nearest_id,
            nearest_attack_class=nearest_class,
            threshold=self.threshold,
        )

    def index_corpus(self, rows: Sequence[dict]) -> int:
        """Embed and upsert a batch of corpus rows.

        Each row needs at least {id, description, attack_class}. Only
        malicious rows should ever be passed here — indexing benign
        samples would make "similar to a benign example" register as an
        attack match, which is backwards.
        """
        if not rows:
            return 0
        texts = [r["description"] for r in rows]
        embeddings = self.embedder.embed(texts)
        for row, embedding in zip(rows, embeddings):
            self.store.upsert(row["id"], embedding, row["attack_class"])
        return len(rows)


# --- in-memory VectorStore, for tests and small local runs ------------------


class InMemoryVectorStore:
    """Pure-Python VectorStore: no Postgres, no network. Used by tests to
    exercise Layer2Similarity's scoring/threshold logic in isolation, and
    usable standalone for a quick local check without provisioning pgvector.
    """

    def __init__(self):
        self._rows: dict[str, tuple[list[float], str]] = {}

    def upsert(self, id: str, embedding: Sequence[float], attack_class: str) -> None:
        self._rows[id] = (list(embedding), attack_class)

    def max_similarity(self, embedding: Sequence[float]) -> tuple[float, str | None, str | None]:
        if not self._rows:
            return -1.0, None, None
        best_similarity = -1.0
        best_id = None
        best_class = None
        for id_, (stored_embedding, attack_class) in self._rows.items():
            similarity = _cosine_similarity(embedding, stored_embedding)
            if similarity > best_similarity:
                best_similarity, best_id, best_class = similarity, id_, attack_class
        return best_similarity, best_id, best_class


def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# --- production VectorStore: pgvector via psycopg, HNSW + cosine ------------


class PgVectorStore:
    """pgvector-backed VectorStore using an HNSW index with cosine distance
    (pgvector's `vector_cosine_ops`), per the task spec.

    Takes an already-open psycopg connection (with `pgvector.psycopg.register_vector`
    applied — see `connect()` below) rather than opening one itself, so
    connection pooling/lifecycle stays the caller's responsibility.
    """

    def __init__(self, conn, dim: int = DEFAULT_EMBEDDING_DIM, table: str = DEFAULT_TABLE):
        self.conn = conn
        self.dim = dim
        self.table = table

    def ensure_schema(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {self.table} ("
                f"id TEXT PRIMARY KEY, "
                f"attack_class TEXT NOT NULL, "
                f"embedding VECTOR({self.dim}) NOT NULL)"
            )
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS {self.table}_embedding_hnsw_idx "
                f"ON {self.table} USING hnsw (embedding vector_cosine_ops)"
            )
        self.conn.commit()

    def upsert(self, id: str, embedding: Sequence[float], attack_class: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.table} (id, attack_class, embedding) VALUES (%s, %s, %s) "
                f"ON CONFLICT (id) DO UPDATE SET attack_class = EXCLUDED.attack_class, "
                f"embedding = EXCLUDED.embedding",
                (id, attack_class, list(embedding)),
            )
        self.conn.commit()

    def max_similarity(self, embedding: Sequence[float]) -> tuple[float, str | None, str | None]:
        # pgvector's `<=>` operator is cosine *distance* (1 - similarity);
        # ORDER BY it ascending finds the nearest (most similar) row first.
        with self.conn.cursor() as cur:
            cur.execute(
                f"SELECT id, attack_class, 1 - (embedding <=> %s) AS similarity "
                f"FROM {self.table} ORDER BY embedding <=> %s LIMIT 1",
                (list(embedding), list(embedding)),
            )
            row = cur.fetchone()
        if row is None:
            return -1.0, None, None
        id_, attack_class, similarity = row
        return float(similarity), id_, attack_class


def connect(dsn: str, dim: int = DEFAULT_EMBEDDING_DIM, table: str = DEFAULT_TABLE) -> PgVectorStore:
    """Open a psycopg connection, register the pgvector adapter, ensure the
    schema/HNSW index exist, and return a ready-to-use PgVectorStore.

    Imports psycopg/pgvector lazily so this module stays importable (and
    Layer2Similarity testable via InMemoryVectorStore) without either
    package installed.
    """
    import psycopg
    from pgvector.psycopg import register_vector

    conn = psycopg.connect(dsn, autocommit=False)
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    conn.commit()
    register_vector(conn)

    store = PgVectorStore(conn, dim=dim, table=table)
    store.ensure_schema()
    return store


# --- production Embedder: local sentence-transformers ------------------------


class SentenceTransformerEmbedder:
    """Production Embedder backed by a locally-run sentence-transformers
    model (default: all-MiniLM-L6-v2, 384 dimensions). Runs on-machine, no
    API key, no per-call network dependency once weights are cached (~90MB,
    downloaded from the Hugging Face Hub on first use). Imports
    sentence_transformers lazily so this module stays importable without it
    installed.
    """

    def __init__(self, model: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        embeddings = self._model.encode(list(texts), normalize_embeddings=False)
        return embeddings.tolist()
