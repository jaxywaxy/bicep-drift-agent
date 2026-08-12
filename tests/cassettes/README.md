# Recorded Azure payloads

Each `.json` here is what a real subscription actually returned, for a real API
version, on the date in its `metadata`. Tests replay these instead of
hand-written fixtures, which encode our *beliefs* about Azure and therefore pass
when a belief is wrong.

Use them via `tests/cassette_support.CassetteTestCase`.

## Re-recording

Needs a deployed verification estate (`TEST_ESTATE.md`) and `az login`:

```bash
export AZURE_SUBSCRIPTION_ID=<the estate's subscription>
DRIFT_RECORD_CASSETTE=fresh.json \
DRIFT_CASSETTE_NOTE="lz prod estate, <date>" \
  python analyze_drift.py ../azure-landingzone-bicep/envs/prod/main.bicep "jacquiprod-*"
```

Recording appends, so several scans can build one corpus.

## Before replacing a committed cassette, diff it

```bash
python -m tools.recording.decay lz-prod-subscription.json fresh.json
```

This reports **shape** changes only — fields Azure stopped returning, started
returning, or retyped — and ignores values, which differ freely between two
recordings of the same estate. Exit code 1 means something moved.

A field Azure **stopped returning** is the one to stop and think about: it is
indistinguishable from a deletion to every comparator downstream, and it is how
a comparator proven correct in one month becomes wrong in the next with nothing
failing.

## What is and is not in these files

- Subscription, tenant and principal GUIDs are **pseudonyms**, hashed one-way
  with no mapping stored anywhere. Set `AZURE_SUBSCRIPTION_ID` to the
  `subscription_alias` in the metadata, which `CassetteTestCase` does for you.
- Built-in **role definition** GUIDs are public Azure constants and are kept
  as-is, or `Owner` stops resolving and stops counting as privileged.
- Resource **names are real**, and deliberately so — name correspondence is the
  behaviour these fixtures exist to test. Record only from a verification
  estate, never a client's.
- Request headers are not recorded at all, so no bearer token is present.
