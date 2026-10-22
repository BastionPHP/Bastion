# Contributing

- `make test` must pass (Go unit tests + JS engine parity). Run `make integration` if you touch discovery, package lookup or scanning (needs Docker and root).
- **Advisory data** (`internal/advisory/data/`): every fixed version must link to an official source (php.net, the vendor's tracker). Never add a value you could not verify — leave it out and let Bastion say `unknown`.
- **Engine changes** must keep `site/assets/engine.js` in sync; add a case to `testdata/vectors.json` or `testdata/paste.json` so both implementations are tested.
- **Trace rules** (`internal/trace/rules/content.json`): run the rule over a large body of legitimate code first (CI does WordPress, Drupal, Laravel, phpseclib). Test fixtures must be inert (`if (false)`), as in `internal/trace/trace_test.go`.
- Bastion stays read-only. Features that change a system belong behind an explicit, separate command and need discussion first.
- Do not contribute exploit code.
