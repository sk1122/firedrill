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
		{"github fine-grained", "GH=github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJ", "github_pat", 1},
		{"github oauth", "token: gho_abcdefghijklmnopqrstuvwxyz012345", "github_oauth", 1},
		{"github user-to-server", "ghu_abcdefghijklmnopqrstuvwxyz012345", "github_user_token", 1},
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
		{"env reference", "client_secret: env.OAUTH_CLIENT_SECRET,", "", 0},
		{"process env reference", "const API_KEY = process.env.TWITTER_API_KEY;", "", 0},
		{"non-null reference", "const JWT_SECRET = env.ACCESS_TOKEN_SECRET!;", "", 0},
		{"field reference", "client_secret: this.config.clientSecret,", "", 0},
		{"optional chain", "refresh_token: parsed?.tokens?.refresh_token || '',", "", 0},
		{"call", "const refresh_token = generateRefreshToken();", "", 0},
		{"schema chain", "BUILDER_SECRET: z.string().optional(),", "", 0},
		{"unquoted value with no dot is still a value", "api_token: Zx8mQ2pL9vT4rW7yB1nC6dF3", "generic", 1},
		{"jwt is kept though it looks dotted", "ID_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz", "generic", 1},
		{"quoted dotted literal is a value", `const API_KEY = "Zx8mQ2pL9.vT4rW7yB1nC6dF3"`, "generic", 1},
		{"escaped newline ends the value", `"readme": "Set SOME_TOKEN=abc\n\nThenTheRestOfTheReadmeText123456"`, "", 0},
		{"placeholder word your", "API_KEY=your-secret-api-key-goes-here-123", "", 0},
		{"placeholder word replace", "AUTH_SECRET=replace_me_with_a_Real_Value_99", "", 0},
		{"placeholder word xxx", "STRIPE_SECRET=sk_xxxxxxxxxxxxxxxxxxxxQ1w2", "", 0},
		{"schema default", "SEARCH_API_KEY: z.string().optional().default('Zx8mQ2pL9vT4rW7yB1nC6dF3'),", "generic", 1},
		{"nullish fallback", "const k = process.env.STRIPE_SECRET ?? 'Zx8mQ2pL9vT4rW7yB1nC6dF3';", "generic", 1},
		{"or fallback", `const k = process.env.GH_TOKEN || "Zx8mQ2pL9vT4rW7yB1nC6dF3"`, "generic", 1},
		{"getenv default", `key = os.getenv("OPENAI_API_KEY", "Zx8mQ2pL9vT4rW7yB1nC6dF3")`, "generic", 1},
		{"environ get default", `key = os.environ.get('DB_PASSWORD', 'Zx8mQ2pL9vT4rW7yB1nC6dF3')`, "generic", 1},
		{"default on a line with no credential name", "LABEL: z.string().default('Zx8mQ2pL9vT4rW7yB1nC6dF3'),", "", 0},
		{"placeholder default", "API_KEY: z.string().default('your-api-key-here-1234567'),", "", 0},
		{"redis key name", "const CURSOR_KEY = 'poly:builder_trade:cursor-state';", "", 0},
		{"kms alias default", "KMS_OAUTH_KEY_ID: z.string().default('alias-oauth-encryption-key'),", "", 0},
		{"url path", "public DERIVE_API_KEY = '/auth/derive-api-key-now';", "", 0},
		{"uuid token still caught", "DEPLOY_TOKEN: '" + uuidToken + "'", "generic", 1},
		{"lowercase hex still caught", "SIGNING_KEY=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "generic", 1},
		{"default and assignment of one value count once", `API_KEY = "Zx8mQ2pL9vT4rW7yB1nC6dF3" || "Zx8mQ2pL9vT4rW7yB1nC6dF3"`, "generic", 1},
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
		"fixtures/keys.env":       "unknown",
		"a/testdata/x":            "unknown",
		"testdata/prod.env":       "prod",
		"src/__tests__/k.js":      "unknown",
		".env.example":            "example",
		"config.sample":           "example",
		"prod/app.template":       "example",
		"internal/x/x_test.go":    "unknown",
		"test/keys.env":           "unknown",
		"src/tests/k.py":          "unknown",
		"tests/prod/k.env":        "prod",
		"src/latest/k.env":        "unknown",
		"contest/k.env":           "unknown",
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

func TestTestPathsAreNotExamplesByDefault(t *testing.T) {
	c := DefaultClasses()
	if got := c.Class("testdata/prod.env"); got == "example" {
		t.Fatalf("testdata/prod.env classed %s", got)
	}
	for _, p := range []string{"test/k.env", "tests/k.env", "api_test.go"} {
		if got := c.Class(p); got != "unknown" {
			t.Fatalf("%s classed %s, want unknown", p, got)
		}
	}
	if got := c.Class(".env.example"); got != "example" {
		t.Fatalf(".env.example classed %s", got)
	}
	c.ExamplePaths = append(c.ExamplePaths, "testdata/")
	if got := c.Class("testdata/prod.env"); got != "example" {
		t.Fatalf("a configured example path must still apply, got %s", got)
	}
	c.ExamplePaths = append(c.ExamplePaths, "test/")
	if got := c.Class("test/k.env"); got != "example" {
		t.Fatalf("a configured test folder must apply, got %s", got)
	}
}
