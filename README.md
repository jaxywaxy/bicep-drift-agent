# bicep-drift-agent

Detects drift between a Bicep file and deployed Azure state. Built as a learning project for agentic AI workflows.

## What it does

1. Compiles a Bicep file to ARM JSON
2. Queries live Azure state via the ARM API
3. Diffs the two
4. Reports what's drifted and how

## Project phases

### Phase 1 (✅ Done): Standalone tools

- ✅ Compiles Bicep → ARM JSON
- ✅ Queries live Azure state
- ✅ Normalizes both shapes for comparison
- ✅ Generates drift reports
- ✅ Resolves parameters and variables
- ✅ Flattens nested deployments
- ✅ Filters out module references
- 📝 Limitation: Can't fully resolve complex ARM functions (format with runtime values, uniqueString, etc.)

### Phase 2 (Next): Agent loop

Wrap the tools for the Anthropic API. Let Claude reason over the diff, classify severity, and write a proper report. Handle unresolvable expressions and complex resource relationships.

### Phase 3 (Later): Expand scope

- Type-specific property comparison (VM, storage, networking)
- PR creation with drift report
- CI/CD integration
- Drift remediation suggestions

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

### With parameter values

If your Bicep template uses parameters (like `environment=prod`), pass them via the `.env` file:

```bash
# .env
ARM_PARAMETERS={"environment":"prod","location":"australiaeast"}
```

Or set it inline:

```bash
export ARM_PARAMETERS='{"environment":"prod"}' && python run_drift_check.py ./main.bicep my-rg
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

## The normalizer: Solving the shape mismatch

ARM templates use expressions like `[parameters('vmName')]` and `[format('prefix-{0}', parameters('env'))]`.
Live Azure state has fully resolved values like `prefix-prod`.

The **normalizer** (`tools/normalizer.py`) bridges this gap by:

1. **Extracting parameters** from the template with their default values
2. **Merging parameter overrides** from the environment
3. **Resolving expressions** in resource names:
   - `[parameters('foo')]` → looks up parameter value
   - `[variables('bar')]` → looks up variable value
   - `[format('template-{0}', param)]` → substitutes arguments
   - `[uniqueString(...)]` → placeholder (can't resolve at compile time)
4. **Flattening nested deployments** recursively
5. **Filtering out module references** that don't map to real resources

Remaining limitations:

- Runtime functions like `uniqueString()`, `copyIndex()` can't be resolved without execution context
- Complex nested functions still partially unresolved
- This is why Phase 2 needs an agent — to reason about unresolvable expressions

## Testing the tools individually

```bash
# Test Bicep compilation
python -m tools.compile_bicep ./path/to/main.bicep

# Test live state query
python -m tools.get_live_state your-resource-group

# Then run the full check
python run_drift_check.py ./path/to/main.bicep your-resource-group
```
end# Test change
