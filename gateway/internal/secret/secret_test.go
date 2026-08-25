package secret

import (
	"errors"
	"testing"
)

type fakeProvider struct {
	values map[string]string
}

func (f fakeProvider) Resolve(name string) (string, error) {
	v, ok := f.values[name]
	if !ok {
		return "", errors.New("fake: not found")
	}
	return v, nil
}

func TestExpand_LiteralPassesThrough(t *testing.T) {
	got, err := Expand("plain-value", fakeProvider{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "plain-value" {
		t.Fatalf("expected literal passthrough, got %q", got)
	}
}

func TestExpand_EmptyStringPassesThrough(t *testing.T) {
	got, err := Expand("", fakeProvider{})
	if err != nil || got != "" {
		t.Fatalf("expected (\"\", nil), got (%q, %v)", got, err)
	}
}

func TestExpand_ResolvesSecretReference(t *testing.T) {
	p := fakeProvider{values: map[string]string{"MY_KEY": "s3cr3t"}}
	got, err := Expand("${SECRET:MY_KEY}", p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Fatalf("expected resolved secret, got %q", got)
	}
}

func TestExpand_PropagatesProviderError(t *testing.T) {
	_, err := Expand("${SECRET:MISSING}", fakeProvider{})
	if err == nil {
		t.Fatal("expected an error when the provider can't resolve the name")
	}
}

func TestExpand_RejectsEmptyName(t *testing.T) {
	_, err := Expand("${SECRET:}", fakeProvider{})
	if err == nil {
		t.Fatal("expected an error for an empty secret name")
	}
}

func TestExpand_PartialSyntaxIsLiteral(t *testing.T) {
	// Missing closing brace, or missing prefix -- neither is a valid
	// reference, both must be treated as literals, not errors.
	for _, s := range []string{"${SECRET:MY_KEY", "SECRET:MY_KEY}", "$SECRET:MY_KEY"} {
		got, err := Expand(s, fakeProvider{})
		if err != nil {
			t.Fatalf("expected literal passthrough for %q, got error: %v", s, err)
		}
		if got != s {
			t.Fatalf("expected %q unchanged, got %q", s, got)
		}
	}
}

func TestEnvProvider_ResolvesSetVariable(t *testing.T) {
	t.Setenv("PORTCULLIS_TEST_SECRET", "hello")
	got, err := (EnvProvider{}).Resolve("PORTCULLIS_TEST_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello" {
		t.Fatalf("expected %q, got %q", "hello", got)
	}
}

func TestEnvProvider_ErrorsOnUnsetVariable(t *testing.T) {
	_, err := (EnvProvider{}).Resolve("PORTCULLIS_TEST_SECRET_DEFINITELY_UNSET")
	if err == nil {
		t.Fatal("expected an error for an unset environment variable")
	}
}
