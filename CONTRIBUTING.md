# Contributing

Thanks for helping. There are two ways in.

## Write a drill

Most contributions are drills, and they live in the [drill hub](https://github.com/sk1122/firedrill-drills). A drill is a YAML file plus test cases; its CONTRIBUTING explains the format and the bar to merge. You don't need to know Go.

## Change the tool

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Keep Firedrill read-only. Nothing may write to a connected system, and every new call goes through the guard in `connector/guard.go`.
3. Add tests. A new fact needs a fixture test; a new connector needs a fake-server test that checks every method and path it calls; a new starter drill needs a passing, a failing and a not-applicable case in `packs/<pack>/<slug>.test.yaml`.
4. Run the checks:

   ```bash
   make check
   ```

   It runs gofmt, vet, golangci-lint, the tests and the builds for six platforms. Tests that use Postgres start it in Docker and skip when Docker isn't running.

5. Sign off every commit under the [Developer Certificate of Origin](https://developercertificate.org): `git commit -s`.

The design is in [docs/SPEC.md](docs/SPEC.md). By contributing you agree your work is licensed under Apache-2.0, and to follow the [code of conduct](CODE_OF_CONDUCT.md).
