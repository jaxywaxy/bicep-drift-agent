# Recorded Azure payloads

Each `.json` here is what a real subscription actually returned, for a real API
version, on the date in its `metadata`. Tests replay these instead of
hand-written fixtures, which encode our *beliefs* about Azure and therefore pass
when a belief is wrong.

Use them via `tests/cassette_support.CassetteTestCase`.

## Re-recording

Needs `az login` and a deployed estate you own — the committed corpus was
recorded from the prod landing zone below, not from a fixture (`TEST_ESTATE.md`
covers standing one of those up):

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
  behaviour these fixtures exist to test, and the metadata note names the estate
  they came from. Record only from an estate you own and can publish, never a
  client's: the GUID hashing is not anonymity, and a cassette recorded from a
  client would commit their names and topology.
- Request headers are not recorded at all, so no bearer token is present.
- Responses over `DRIFT_CASSETTE_MAX_BYTES` (1MB) are **skipped**, and listed
  under `oversize_skipped` in the metadata. In practice that is the Activity
  Log, which returned 35,075 events for one subscription — 174MB. It is not
  truncated, because a fixture that lies about how much Azure returned is worse
  than an absent one; a replay needing it misses loudly. Attribution keeps its
  hand-written fixtures, where the event shape is small and stable.
