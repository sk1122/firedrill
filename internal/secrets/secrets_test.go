package secrets

import (
	"strings"
	"testing"
)

const uuidToken = "6f1b9d2e-7c44-4a10-9e3b-2d5ac81f0e77"

// Made-up credentials, built by concatenation so this file holds none the
// scanner would find in it.
const (
	fakeValue = "Zx8mQ2pL9" + "vT4rW7yB1nC6dF3"
	fakeKeyID = "AKIA" + "IOSFODNN7ABCDEFG"
	fakeLive  = "sk_live_" + "abcdefghijklmnop"
)

func TestScanFindsPrefixesAndNamedVariables(t *testing.T) {
	cases := []struct {
		name, text, kind string
		want             int
	}{
		{"aws key", "export AWS_ACCESS_KEY_ID=" + fakeKeyID, "aws_access_key", 1},
		{"stripe", `key = "` + fakeLive + `"`, "stripe_live", 1},
		{"github", "ghp_" + "abcdefghijklmnopqrstuvwxyz012345", "github_token", 1},
		{"github fine-grained", "GH=github_pat_" + "11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJ", "github_pat", 1},
		{"github oauth", "token: gho_" + "abcdefghijklmnopqrstuvwxyz012345", "github_oauth", 1},
		{"github user-to-server", "ghu_" + "abcdefghijklmnopqrstuvwxyz012345", "github_user_token", 1},
		{"razorpay", "RZP=rzp_live_" + "abcdefghij12345", "razorpay_live", 1},
		{"prefix-less token, the PocketOS shape", "RAILWAY_TOKEN=" + uuidToken, "generic", 1},
		{"yaml key", "API_KEY: " + fakeValue, "generic", 1},
		{"password", `DB_PASSWORD="` + "hG7$kP2mX9qL4vB8nR3tY6wZ" + `"`, "generic", 1},
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
		{"unquoted value with no dot is still a value", "api_token: " + fakeValue, "generic", 1},
		{"jwt is kept though it looks dotted", "ID_TOKEN=" + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz", "generic", 1},
		{"quoted dotted literal is a value", `const API_KEY = "` + "Zx8mQ2pL9.vT4rW7yB1nC6dF3" + `"`, "generic", 1},
		{"escaped newline ends the value", `"readme": "Set SOME_TOKEN=abc\n\nThenTheRestOfTheReadmeText123456"`, "", 0},
		{"placeholder word your", "API_KEY=your-secret-api-key-goes-here-123", "", 0},
		{"placeholder word replace", "AUTH_SECRET=replace_me_with_a_Real_Value_99", "", 0},
		{"placeholder word xxx", "STRIPE_SECRET=sk_xxxxxxxxxxxxxxxxxxxxQ1w2", "", 0},
		{"schema default", "SEARCH_API_KEY: z.string().optional().default('" + fakeValue + "'),", "generic", 1},
		{"nullish fallback", "const k = process.env.STRIPE_SECRET ?? '" + fakeValue + "';", "generic", 1},
		{"or fallback", `const k = process.env.GH_TOKEN || "` + fakeValue + `"`, "generic", 1},
		{"getenv default", `key = os.getenv("OPENAI_API_KEY", "` + fakeValue + `")`, "generic", 1},
		{"environ get default", `key = os.environ.get('DB_PASSWORD', '` + fakeValue + `')`, "generic", 1},
		{"default on a line with no credential name", "LABEL: z.string().default('Zx8mQ2pL9vT4rW7yB1nC6dF3'),", "", 0},
		{"placeholder default", "API_KEY: z.string().default('your-api-key-here-1234567'),", "", 0},
		{"redis key name", "const CURSOR_KEY = 'poly:builder_trade:cursor-state';", "", 0},
		{"kms alias default", "KMS_OAUTH_KEY_ID: z.string().default('alias-oauth-encryption-key'),", "", 0},
		{"url path", "public DERIVE_API_KEY = '/auth/derive-api-key-now';", "", 0},
		{"uuid token still caught", "DEPLOY_TOKEN: '" + uuidToken + "'", "generic", 1},
		{"lowercase hex still caught", "SIGNING_KEY=" + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "generic", 1},
		{"default and assignment of one value count once", `API_KEY = "` + fakeValue + `" || "` + fakeValue + `"`, "generic", 1},
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
	got := Scan("line one\nid = " + fakeKeyID + "\n")
	if len(got) != 1 || got[0].KeyID != fakeKeyID || got[0].Line != 2 {
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
	yes := []string{fakeKeyID, fakeLive, fakeValue}
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

// fakePEM is a made-up private key body, built by concatenation so no scanner
// reads this file as holding a key.
func fakePEM(escaped bool) string {
	nl := "\n"
	if escaped {
		nl = `\n`
	}
	body := strings.Repeat("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7acme", 2)
	return "-----BEGIN " + "PRIVATE KEY-----" + nl + body + nl + body + nl + "-----END " + "PRIVATE KEY-----" + nl
}

func TestScanPublicFindsWebKinds(t *testing.T) {
	keyID := "0123456789abcdef0123456789abcdef01234567"
	saJSON := `{"type":"service_account","project_id":"acme-prod","private_key_id":"` + keyID + `","private_key":"` + fakePEM(true) + `","client_email":"web@acme-prod.iam.gserviceaccount.com"}`
	cases := []struct {
		name, text, kind, keyID string
		want                    int
	}{
		{"service account key in a minified bundle", `var c=JSON.parse('` + saJSON + `');`, "gcp_sa_key", keyID, 1},
		{"service account key with escaped quotes", strings.ReplaceAll(`x="`+saJSON+`"`, `"`, `\"`), "gcp_sa_key", keyID, 1},
		{"service account key over several lines", strings.ReplaceAll(saJSON, ",", ",\n"), "gcp_sa_key", keyID, 1},
		{"a key ID with no key is not a credential", `{"private_key_id":"` + keyID + `"}`, "", "", 0},
		{"a private key alone", "const k = `" + fakePEM(false) + "`", "private_key", "", 1},
		{"browser key", `apiKey:"AIza` + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tUvw" + `"`, "google_api_key", "", 1},
		{"publishable key", `STRIPE_PUBLISHABLE_KEY:"pk_live_` + "51AcmeAbCdEfGhIjKl" + `"`, "stripe_publishable", "", 1},
		{"secret key is still server-side", `k="sk_live_` + "51AcmeAbCdEfGhIjKl" + `"`, "stripe_live", "", 1},
		{"database url with a password", `DATABASE_URL:"postgres://app:` + "Hx7pQ2mZ9vL4" + `@db.acme.internal:5432/orders"`, "database_url", "", 1},
		{"database url with no password", `u="postgres://db.acme.internal/orders"`, "", "", 0},
		{"named secret", `CLIENT_SECRET:"` + fakeValue + `"`, "generic_secret", "", 1},
		{"named key", `SEARCH_KEY:"` + fakeValue + `"`, "generic", "", 1},
		{"aws access key keeps its ID", "AKIA" + "IOSFODNN7ABCDEFG", "aws_access_key", "AKIA" + "IOSFODNN7ABCDEFG", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ScanPublic(c.text)
			if len(got) != c.want {
				t.Fatalf("got %d findings: %+v", len(got), got)
			}
			if c.want == 0 {
				return
			}
			if got[0].Kind != c.kind || got[0].KeyID != c.keyID || got[0].Value == "" {
				t.Fatalf("got %+v", got[0])
			}
		})
	}
	// One key reads the same whether escaped in a string or written out.
	a, b := ScanPublic(`x='`+fakePEM(true)+`'`), ScanPublic(fakePEM(false))
	if len(a) != 1 || len(b) != 1 || a[0].Value != b[0].Value {
		t.Fatalf("%+v %+v", a, b)
	}
}

func TestScanPublicKindsAreSplitInOnePlace(t *testing.T) {
	for _, k := range []string{"google_api_key", "stripe_publishable", "razorpay_live", "generic"} {
		if !IsClientSide(k) {
			t.Errorf("%s is made for a browser", k)
		}
	}
	for _, k := range []string{"gcp_sa_key", "private_key", "database_url", "generic_secret", "stripe_live", "aws_access_key", "github_token", "github_pat"} {
		if IsClientSide(k) {
			t.Errorf("%s is a server-side credential", k)
		}
	}
}

func TestScanLeavesRepoKindsAlone(t *testing.T) {
	// The repo scanner does not report browser keys: they are normal in a repo.
	if got := Scan(`apiKey: "AIza` + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tUvw" + `"`); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}
