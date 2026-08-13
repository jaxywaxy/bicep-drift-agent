"""Base class for tests that run against a recorded Azure payload.

Not named `test_*`, so unittest discovery does not collect it.

A cassette-backed test drives the real pipeline against bytes a real
subscription returned, rather than against a payload someone typed. The setup
is three easy things to get wrong, so it lives here once:

1. the replay session has to be torn down even when the test fails, or every
   later test in the process silently runs against a cassette;
2. `AZURE_SUBSCRIPTION_ID` has to be the cassette's *pseudonym*, because the
   real id was never written to disk - matched against a template still naming
   the real subscription, nothing corresponds and the run reports the whole
   estate as simultaneously missing and extra;
3. a missing cassette has to fail loudly, not skip. A silently skipped suite is
   how the backup comparators shipped dead for a month.
"""

import os
import unittest
from pathlib import Path
from unittest import mock

from tools import recording
from tools.recording.cassette import Cassette

CASSETTE_DIR = Path(__file__).resolve().parent / "cassettes"


class CassetteTestCase(unittest.TestCase):
    """Replays `CASSETTE` for the duration of each test.

    Subclasses set `CASSETTE` to a filename under `tests/cassettes/` and then
    call collectors, comparators or whole pipeline stages normally. No network
    call is made and no Azure credential is needed; a request the cassette does
    not cover raises `CassetteMiss` rather than returning empty.
    """

    #: Filename under tests/cassettes/. Required.
    CASSETTE: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        if not cls.CASSETTE:
            raise AssertionError(f"{cls.__name__} must set CASSETTE")
        cls.cassette_path = CASSETTE_DIR / cls.CASSETTE
        if not cls.cassette_path.exists():
            # Deliberately an error, not a skip.
            raise AssertionError(
                f"Missing cassette {cls.cassette_path}. Re-record it; do not "
                "skip, because a suite that skips itself reports success."
            )

    def setUp(self) -> None:
        cassette = Cassette.load(self.cassette_path)
        self.subscription_id = cassette.metadata.get("subscription_alias")
        if not self.subscription_id:
            raise AssertionError(
                f"{self.CASSETTE} records no subscription_alias, so a replay "
                "cannot know which pseudonym is the subscription. Re-record it "
                "with AZURE_SUBSCRIPTION_ID set."
            )
        patcher = mock.patch.dict(
            os.environ, {"AZURE_SUBSCRIPTION_ID": self.subscription_id}
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        recording.start_replay(self.cassette_path)
        self.addCleanup(recording.stop)

    def assertRecorded(self, method: str, url: str) -> None:
        """Assert the cassette actually covers a request.

        Worth stating explicitly in a test whose point is that some collector
        ran: a collector that silently did nothing passes an assertion about its
        empty output just as well as one that worked.
        """
        recording.current_cassette().lookup(method, url)
