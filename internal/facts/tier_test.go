package facts

import "testing"

func TestTierOf(t *testing.T) {
	for source, want := range map[string]string{
		"api":                            TierVerified,
		"file":                           TierDeclared,
		"config":                         TierDeclared,
		"admin_export":                   TierDeclared,
		"admin_export: commit abc by @a": TierDeclared,
		"":                               "",
		"fixture":                        "",
	} {
		if got := TierOf(source); got != want {
			t.Errorf("TierOf(%q) = %q, want %q", source, got, want)
		}
	}
}

func TestIsInferred(t *testing.T) {
	inferred := []string{"found.env_class", "class"}
	for path, want := range map[string]bool{
		"found.env_class":      true,
		"found.env_class.word": true,
		"class":                true,
		"found":                false,
		"found.file":           false,
		"classes":              false,
		"":                     false,
	} {
		if got := IsInferred(path, inferred); got != want {
			t.Errorf("IsInferred(%q) = %v, want %v", path, got, want)
		}
	}
	if IsInferred("anything", nil) {
		t.Error("a fact with no inferred fields infers nothing")
	}
}

// No shipped fact marks a field inferred yet: which fields count is a product
// decision, and marking one changes verdicts.
func TestNoShippedFactIsInferred(t *testing.T) {
	for _, d := range All() {
		if len(d.Inferred) > 0 {
			t.Errorf("%s marks %v inferred", d.Name, d.Inferred)
		}
	}
}
