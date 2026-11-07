package secrets

import "testing"

const uuidToken = "6f1b9d2e-7c44-4a10-9e3b-2d5ac81f0e77"

func TestScanFindsPrefixesAndNamedVariables(t *testing.T) {
	cases := []struct {
		name, text, kind string
		want             int
	}{
		{"aws key", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG", "aws_access_key", 1},
		{"stripe", `key = "sk_live_abcdefghijklmnop"`, "stripe_live", 1},
		{"github", "ghp_abcdefghijklmnopqrstuvwxyz012345", "github_token", 1},
		{"razorpay", "RZP=rzp_live_abcdefghij12345", "razorpay_live", 1},
		{"prefix-less token, the PocketOS shape", "RAILWAY_TOKEN=" + uuidToken, "generic", 1},
		{"yaml key", "API_KEY: Zx8mQ2pL9vT4rW7yB1nC6dF3", "generic", 1},
		{"password", `DB_PASSWORD="hG7$kP2mX9qL4vB8nR3tY6wZ"`, "generic", 1},
		{"variable reference", "RAILWAY_TOKEN=${RAILWAY_TOKEN}", "", 0},
		{"shell reference", "API_KEY=$API_KEY_FROM_THE_ENVIRONMENT", "", 0},
		{"too short", "API_KEY=abc123", "", 0},
		{"low entropy", "API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", 0},
		{"placeholder", "API_KEY=<your-very-long-api-key-goes-here>", "", 0},
		{"unrelated assignment", "GREETING=" + uuidToken, "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Scan(c.text)
			if len(got) != c.want {
				t.Fatalf("got %d findings: %+v", len(got), got)
			}
			if c.want > 0 && got[0].Kind != c.kind {
				t.Fatalf("kind %s, want %s", got[0].Kind, c.kind)
			}
		})
	}
}

func TestAWSKeyKeepsIdentifier(t *testing.T) {
	got := Scan("line one\nid = AKIAIOSFODNN7ABCDEFG\n")
	if len(got) != 1 || got[0].KeyID != "AKIAIOSFODNN7ABCDEFG" || got[0].Line != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestClass(t *testing.T) {
	c := DefaultClasses()
	cases := map[string]string{
		".env.production":         "prod",
		"deploy/prod/config.yaml": "prod",
		"scripts/prod-deploy.sh":  "prod",
		".env.staging":            "staging",
		"stage/app.env":           "staging",
		"product/catalog.env":     "unknown",
		"scripts/domains.sh":      "unknown",
		"fixtures/keys.env":       "example",
		"a/testdata/x":            "example",
		"src/__tests__/k.js":      "example",
		".env.example":            "example",
		"config.sample":           "example",
		"prod/app.template":       "example",
	}
	for p, want := range cases {
		if got := c.Class(p); got != want {
			t.Errorf("%s: got %s, want %s", p, got, want)
		}
	}
}

func TestLooksLikeSecret(t *testing.T) {
	yes := []string{"AKIAIOSFODNN7ABCDEFG", "sk_live_abcdefghijklmnop", "Zx8mQ2pL9vT4rW7yB1nC6dF3"}
	no := []string{"scripts/domains.sh", "ravi@acme.com", "short", "this is a normal sentence with words in it", "https://api.acme.com/some/long/path/value"}
	for _, v := range yes {
		if !LooksLikeSecret(v) {
			t.Errorf("%s should look like a secret", v)
		}
	}
	for _, v := range no {
		if LooksLikeSecret(v) {
			t.Errorf("%s should not look like a secret", v)
		}
	}
}
