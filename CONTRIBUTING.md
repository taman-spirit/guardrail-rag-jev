# Contributing

Issues and pull requests are welcome.

## Run the tests

No API key and no network are needed: tests decide against scripted answers.

```bash
pip install -e './python[dev,langchain,llamaindex]'
cd python && python -m pytest -q
cd clients/go && go test ./...
```

## Change a policy

`policies/` is the source of truth. After editing it, run `scripts/sync-policies.sh` to copy it into
the Python package; `tests/test_policy.py` fails when the two differ.

A threshold is a number someone chose, not a measurement. A change to one should come with the
labelled cases it was calibrated on, and with the provider it was calibrated for.

## Add a provider

Implement `name`, `capabilities` and `decide(state, questions, timeout=...)` returning canonical
answers (see `providers/base.py`). Declare what the model cannot do in `Capabilities` rather than
emulating it: `Normalizing` fills the gaps the same way for every provider. Add it to
`build_provider`, or load it as `type: plugin`.

## Add a law pack

A pack is a patch on the base policy (`policies/packs/*.json`): categories, signals, rules, response
texts, detectors. Use `+` keys (`except_categories+`) to add to lists another pack may also extend.
Every pack states its legal basis (`law`) and the not-legal-advice `disclaimer`.
