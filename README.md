# bicep-drift-agent

Detects drift between a Bicep file and deployed Azure state. Built as a learning project for agentic AI workflows.

## What it does

1. Compiles a Bicep file to ARM JSON
2. Queries live Azure state via the ARM API
3. Diffs the two
4. Reports what's drifted and how

## Project phases

**Phase 1 (now): Standalone tools**
Get the three core functions working and returning real data.
No agent loop yet. Just Python functions calling Azure.

**Phase 2 (next): Agent loop**
Wrap the tools for the Anthropic API. Let Claude reason over the diff,
classify severity, and write a proper report.

**Phase 3 (later): Expand scope**
- Parameter resolution (ARM expressions → real values)
- Type-specific property comparison (VM, storage, networking)
- PR creation with drift report
- CI/CD integration

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Fill in ANTHROPIC_API_KEY and AZURE_SUBSCRIPTION_ID
```

Azure auth uses `DefaultAzureCredential` — if you're already logged in via `az login`, it just works.

## Run it

```bash
python run_drift_check.py ./path/to/main.bicep your-resource-group-name
```

## Project structure

```
bicep-drift-agent/
├── tools/
│   ├── compile_bicep.py     # az bicep build → ARM JSON
│   ├── get_live_state.py    # ARM API → live resource state
│   └── diff_states.py       # desired vs actual comparison
├── agent/                   # Phase 2 — agent loop goes here
├── reports/                 # Output JSON files (gitignored)
├── tests/
├── run_drift_check.py       # Phase 1 entry point
├── requirements.txt
└── .env.example
```

## The interesting hard problem

ARM templates use expressions like `[parameters('vmName')]` for names and values.
Live state has resolved values. The normalisation layer that bridges these is where
most of the real engineering lives. Phase 1 does best-effort matching; Phase 2 
adds parameter resolution.

## Testing the tools individually

```bash
# Test Bicep compilation
python -m tools.compile_bicep ./path/to/main.bicep

# Test live state query
python -m tools.get_live_state your-resource-group

# Then run the full check
python run_drift_check.py ./path/to/main.bicep your-resource-group
```
