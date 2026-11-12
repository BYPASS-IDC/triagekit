# TriageKit Testbench

Local **scanner self-tests** using intentional fixtures (not remote attacks).

## Run

```bash
cd triagekit
python testbench/scripts/run_testbench.py
```

## Layout

- `fixtures/` — synthetic vulnerable and safe samples (Python, Rust, Swift, C#, C++, Java)
- `expected/` — minimum detections / safe ceilings
- `scripts/run_testbench.py` — builds nothing network-facing; only scans fixtures

Optional: compile fixtures with your local toolchain for manual review — the automated bar is **static detection accuracy**.
