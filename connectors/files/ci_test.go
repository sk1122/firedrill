package files

import (
	"reflect"
	"testing"
)

func TestUnfrozenInstalls(t *testing.T) {
	cases := map[string][]string{
		"npm ci":                                      nil,
		"npm install":                                 {"npm install"},
		"npm i --no-audit && npm test":                {"npm install"},
		"cd web && npm --prefix web install":          {"npm install"},
		"npm install -g pnpm@9":                       nil,
		"sudo npm i --global vercel":                  nil,
		"npm install --location=global acme-cli":      nil,
		"CI=true npm add left-pad":                    {"npm install"},
		"pnpm install":                                nil,
		"pnpm i --frozen-lockfile":                    nil,
		"pnpm install --no-frozen-lockfile":           {"pnpm install --no-frozen-lockfile"},
		"pnpm -C web install --frozen-lockfile=false": {"pnpm install --no-frozen-lockfile"},
		"yarn":                           {"yarn install"},
		"yarn install --frozen-lockfile": nil,
		"yarn install --immutable":       nil,
		"yarn --cwd web install":         {"yarn install"},
		"yarn build":                     nil,
		"bun install":                    {"bun install"},
		"bun install --frozen-lockfile":  nil,
		"bun ci":                         nil,
		"echo npm install":               nil,
		"npm install \\\n  --no-audit":   {"npm install"},
		"if true; then npm install; fi\nyarn install": {"npm install", "yarn install"},
		"docker build . && npx acme-cli install":      nil,
	}
	for script, want := range cases {
		if got := UnfrozenInstalls(script); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", script, got, want)
		}
	}
}

func TestWorkflowInstallsAndCloudKeys(t *testing.T) {
	cases := []struct {
		name, src string
		unfrozen  []string
		keys      []string
		oidc      bool
	}{
		{"static AWS keys", `on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          npm install
          npm install
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.DEPLOY_KEY_ID }}
          aws-secret-access-key: ${{ secrets.DEPLOY_SECRET }}
          aws-session-token: ${{ secrets.AWS_SESSION_TOKEN }}
`, []string{"npm install"}, []string{"DEPLOY_KEY_ID", "DEPLOY_SECRET"}, false},
		{"keys by name and env", `on: push
env:
  AWS_SECRET_ACCESS_KEY: ${{ secrets.CI_SECRET }}
jobs:
  a:
    steps:
      - run: aws s3 sync . s3://acme-site
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.PROD_AWS_ACCESS_KEY_ID }}
          REGION: ${{ secrets.AWS_REGION }}
      - run: echo ${{ secrets.AZURE_CREDENTIALS }} ${{ secrets.ACME_SERVICE_ACCOUNT_KEY }}
`, []string{}, []string{"ACME_SERVICE_ACCOUNT_KEY", "AZURE_CREDENTIALS", "CI_SECRET", "PROD_AWS_ACCESS_KEY_ID"}, false},
		{"gcp credentials_json", `on: push
jobs:
  a:
    steps:
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_DEPLOY }}
`, []string{}, []string{"GCP_DEPLOY"}, false},
		{"azure creds", `on: push
jobs:
  a:
    steps:
      - uses: Azure/login@v2
        with:
          creds: ${{ secrets.AZ }}
`, []string{}, []string{"AZ"}, false},
		{"aws oidc", `on: push
permissions:
  id-token: write
  contents: read
jobs:
  a:
    steps:
      - run: npm ci
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: eu-west-1
`, []string{}, []string{}, true},
		{"gcp and azure oidc in a job", `on: push
jobs:
  a:
    permissions:
      id-token: write
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/gh
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
`, []string{}, []string{}, true},
		{"role without id-token", `on: push
jobs:
  a:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
`, []string{}, []string{}, false},
		{"session token alone", `on: push
jobs:
  a:
    steps:
      - run: echo ${{ secrets.AWS_SESSION_TOKEN }}
`, []string{}, []string{}, false},
	}
	for _, c := range cases {
		w, err := ParseWorkflow("a.yml", []byte(c.src))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(w.Unfrozen, c.unfrozen) || !reflect.DeepEqual(w.CloudKeys, c.keys) || w.OIDC != c.oidc {
			t.Errorf("%s: got %v %v %v, want %v %v %v", c.name, w.Unfrozen, w.CloudKeys, w.OIDC, c.unfrozen, c.keys, c.oidc)
		}
	}
	// An env block given as an expression is not a reason to fail.
	if _, err := ParseWorkflow("b.yml", []byte("on: push\njobs:\n  a:\n    env: ${{ fromJSON(vars.ENV) }}\n    steps:\n      - run: echo\n")); err != nil {
		t.Fatal(err)
	}
}
