package router

import "testing"

// FuzzSplitName fuzzes the "{namespace}.{tool}" splitter against
// arbitrary strings -- the Mcp-Name header value is attacker-controlled
// and this is the first thing Portcullis does with it after header/body
// validation. Only checks for panics and the documented invariant: when
// ok is true, re-joining namespace+"."+tool must reproduce a prefix
// relationship consistent with where the split happened (namespace is
// non-empty, tool is non-empty).
func FuzzSplitName(f *testing.F) {
	seeds := []string{
		"",
		".",
		"weather.get_forecast",
		"weather.",
		".get_forecast",
		"a.b.c",
		"...",
		"no-dot-at-all",
		string([]byte{0xff, 0xfe, '.', 0x00}),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		namespace, tool, ok := SplitName(name)
		if !ok {
			return
		}
		if namespace == "" {
			t.Fatalf("SplitName(%q) returned ok=true with an empty namespace", name)
		}
		if tool == "" {
			t.Fatalf("SplitName(%q) returned ok=true with an empty tool", name)
		}
		if namespace+"."+tool != name {
			t.Fatalf("SplitName(%q) = (%q, %q); does not reconstruct the original", name, namespace, tool)
		}
	})
}
