# Semgrep

`code/rules-clean` checks that your team's own [Semgrep](https://semgrep.dev) rules report nothing at error level. Firedrill reads a results file. It never runs Semgrep or any other program.

## 1. Run Semgrep yourself

```bash
semgrep scan --config your-rules/ --json --output semgrep.json
```

## 2. Point Firedrill at the results

```yaml
semgrep:
  results: semgrep.json
```

A relative path is read from your Firedrill repo's root folder. In CI, run Semgrep in a step before `firedrill run`.

## 3. Check it

```bash
firedrill connect semgrep
```
