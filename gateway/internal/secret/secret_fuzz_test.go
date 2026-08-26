package secret

import "testing"

// FuzzExpand fuzzes the ${SECRET:NAME} syntax parser against arbitrary
// strings, using fakeProvider (defined in secret_test.go) so a resolver
// failure never masks a bug in Expand's own parsing logic. Only checks
// for panics -- fakeProvider only ever returns "not found" for an
// unrecognized name, never panics itself, so any panic here is Expand's.
func FuzzExpand(f *testing.F) {
	seeds := []string{
		"",
		"plain-value",
		"${SECRET:NAME}",
		"${SECRET:}",
		"${SECRET:" + string([]byte{0xff, 0xfe}) + "}",
		"${SECRET:NAME",
		"SECRET:NAME}",
		"${SECRET:NAME}${SECRET:OTHER}",
		"$" + "{SECRET:" + "NAME}extra",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	provider := fakeProvider{values: map[string]string{"NAME": "value"}}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Expand(s, provider)
	})
}
