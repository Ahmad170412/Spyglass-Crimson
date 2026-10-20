# Contributing to Spyglass-Crimson

Thanks for your interest. This project is a **passive** OSINT tool, and the
contribution guidelines exist mostly to protect that property.

**Read [ETHICS.md](ETHICS.md) before you start.** If your change would send
traffic to a target, weaken the authorization gate, or help identify private
individuals, it will be declined — no matter how well written it is.

---

## Ways to Help

- **Add a data source** — the highest-value contribution. See
  [Adding a source](#adding-a-data-source).
- **Fix a bug** — check [open issues](https://github.com/Ahmad170412/Spyglass-Crimson/issues)
  for anything labelled `good first issue`.
- **Improve the docs** — a clearer README section or a fixed typo is a real
  contribution.
- **Report a false negative** — if a source missed something it should have
  found, that is a valuable bug report.

---

## Getting Set Up

```bash
git clone https://github.com/Ahmad170412/Spyglass-Crimson.git
cd Spyglass-Crimson
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

The suite must pass before you open a pull request. It is fully mocked and
never touches the network, so it runs offline and in a couple of seconds.

---

## Workflow

1. **Fork** the repository.
2. **Branch** off `main`: `git checkout -b feat/my-change`.
3. **Make** your change, with tests.
4. **Run the gate**: `pytest` — all tests green, no network access.
5. **Commit** with a clear message explaining *why*, not just *what*.
6. **Open a pull request** against `main`.

### Commit messages

```
sources: add HackerTarget as a core DNS source

HackerTarget's free reverse-DNS endpoint fills a real gap: it resolves
PTR records for addresses whose zones are not published, which the DoH
resolver path misses silently.
```

Short imperative summary, blank line, then the reasoning. Explain the *why* —
a future reader needs to know what problem the change solved.

---

## Adding a Source

A source is one module in `spyglass/sources/` plus a registry entry.

1. **Subclass `Source`** in `spyglass/sources/base.py`:

   ```python
   class MySource(Source):
       id = "mysource"
       label = "My Source"
       layer = "core"          # or "enrichment"
       description = "One line describing what it contributes."
       accepts = ("domain",)   # or ("ip",), ("domain", "ip")
       requires_key = False
       key_env = None          # e.g. "SPYGLASS_MYSOURCE_KEY"
       docs_url = "https://..."

       def run(self, target: Target, ctx: SourceContext) -> SourceResult:
           data = ctx.http.get_json("https://example.com/api", params={"q": target.value})
           return SourceResult(status="ok", record_count=1, data=data)
   ```

2. **Register it** in `spyglass/sources/registry.py` with its metadata.

3. **Extract entities** in `extract_entities()` in `spyglass/orchestrator.py` if
   the source produces anything worth normalising. Reuse the existing entity
   kinds (`hostname`, `ip`, `certificate`, `registration`, `dns`, `asn`, `host`,
   `enrichment`) rather than inventing new ones.

4. **Write tests** in `tests/test_<source>.py`. Mock the HTTP call — the suite
   must never hit the network:

   ```python
   @respx.mock
   def test_my_source_normalizes(ctx, settings):
       respx.get("https://example.com/api").mock(
           return_value=httpx.Response(200, json={"result": "value"})
       )
       res = MySource().run(parse_ip_target("1.1.1.1"), ctx)
       assert res.status == "ok"
       assert res.record_count == 1
   ```

5. **Respect the budget.** Use `ctx.http` (it carries the cache and timeout) —
   do not construct your own `httpx` client.

### If it needs an API key

- Set `requires_key = True` and `key_env`.
- Add the variable to `PROVIDERS` in `spyglass/credentials.py`.
- Raise `SourceError("No <name> API key configured")` when the key is absent, so
  the run records an honest skip reason instead of failing.
- Add the variable to the README configuration table.

---

## Testing Guidelines

- **No live network calls.** Use `respx` or `monkeypatch` on `HttpClient`.
  A test that reaches the internet is a failing test.
- **One behaviour per test.** Name it for the behaviour, not the function.
- **Test the failure path.** A source that only has a happy-path test is not
  finished — cover the rejected key, the empty result, and the error response.
- **Assert on normalised output**, not on raw upstream payloads.

---

## Style

- Python: 4-space indent, `from __future__ import annotations` at the top of
  every module, type hints on public functions, no new runtime dependencies
  without discussion.
- Keep the dashboard in its existing language: plain ES2020 in
  `static/js/app.js`, no framework, no build step.
- Match the surrounding code. Read a neighbouring file before writing a new one.

---

## Reporting Bugs

Open an issue with:

- What you did, what you expected, and what happened instead
- Your OS, Python version, and Spyglass-Crimson version
- The relevant part of the output, with **any API keys removed**

If the bug involves a credential, follow [SECURITY.md](SECURITY.md) instead.

---

## Code of Conduct

Be decent to each other. Assume good faith, critique the code and not the
person, and accept that maintainers may decline a change that conflicts with
the project's passive-only and privacy guarantees. Behaviour that harasses
others is not tolerated in issues or pull requests.

---

**By contributing, you affirm that your work is lawful and that it will not
send traffic to a target.**
