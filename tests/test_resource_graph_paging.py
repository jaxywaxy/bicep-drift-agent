"""Resource Graph bounds a response; the rest arrives only via `skip_token`.

An unpaginated read is not a slow scan or a partial one that announces itself.
Rows never read do not enter live state, and a declared resource with no live
counterpart is `missing_in_azure` - so an estate past the page bound produces a
confident report that most of it has been DELETED, with no error and a green
suite.

Nothing here can be caught by a verification estate. Below the bound a paged
read and an unpaged one return identical results, and every fixture estate sits
below it by construction (docs/ARCHITECTURE.md, "Assumed estate size", where the
largest estate is an assumption of 1,000 - exactly the boundary). The only place
this behaviour can be pinned is a faked multi-page response, which is what these
tests are.

`policy.py` and `rbac.py` already paged; the main resource sweep - the query
that reads the whole estate - did not.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.live_state import resource_graph


def _page(rows, skip_token=None, truncated=None):
    """One Resource Graph response: rows, plus a token when more remain."""
    return mock.Mock(data=rows, skip_token=skip_token, result_truncated=truncated)


class PaginationTests(unittest.TestCase):

    def _run(self, pages):
        """Drive _run_paginated_query over a scripted list of responses."""
        client = mock.Mock()
        client.resources.side_effect = pages
        rows = resource_graph._run_paginated_query(client, "sub", "Resources")
        return rows, client

    def test_every_page_is_read_not_just_the_first(self):
        rows, _ = self._run([
            _page([{"id": "/r/1"}], skip_token="tok-1"),
            _page([{"id": "/r/2"}], skip_token="tok-2"),
            _page([{"id": "/r/3"}]),
        ])
        self.assertEqual([r["id"] for r in rows], ["/r/1", "/r/2", "/r/3"])

    def test_the_continuation_token_is_sent_back(self):
        """Without this the second request re-reads page one, forever."""
        _, client = self._run([
            _page([{"id": "/r/1"}], skip_token="tok-1"),
            _page([{"id": "/r/2"}]),
        ])
        first, second = [c.args[0] for c in client.resources.call_args_list]
        self.assertIsNone(first.options)
        self.assertEqual(second.options, {"skip_token": "tok-1"})

    def test_a_single_page_still_issues_one_request(self):
        rows, client = self._run([_page([{"id": "/r/1"}])])
        self.assertEqual(len(rows), 1)
        self.assertEqual(client.resources.call_count, 1)

    def test_an_empty_result_is_empty_not_an_error(self):
        rows, _ = self._run([_page([])])
        self.assertEqual(rows, [])


class PagingOrderTests(unittest.TestCase):
    """Resource Graph's paging is consistent only when the query sorts on a
    unique column. Unsorted, the service may repeat one row across pages and
    OMIT another - and the omission is the dangerous half, because a row never
    read is a resource reported missing."""

    def test_an_unsorted_query_is_given_a_deterministic_sort(self):
        self.assertEqual(
            resource_graph._ordered_for_paging("Resources"),
            "Resources | order by id asc",
        )

    def test_a_query_that_already_sorts_is_left_alone(self):
        kql = "ResourceContainers | order by name asc"
        self.assertEqual(resource_graph._ordered_for_paging(kql), kql)

    def test_the_sort_reaches_the_service(self):
        client = mock.Mock()
        client.resources.side_effect = [_page([])]
        resource_graph._run_paginated_query(client, "sub", "Resources")
        sent = client.resources.call_args_list[0].args[0]
        self.assertIn("order by id asc", sent.query)


class HardTruncationTests(unittest.TestCase):
    """`resultTruncated` with no continuation token is a bound we cannot page
    past. The rows are gone, so the report is WRONG rather than merely short -
    the one case that must not pass quietly."""

    def _warnings(self, pages):
        client = mock.Mock()
        client.resources.side_effect = pages
        with self.assertLogs(resource_graph.logger, level="WARNING") as caught:
            resource_graph._run_paginated_query(client, "sub", "Resources")
        return "\n".join(caught.output)

    def test_truncation_without_a_token_warns(self):
        out = self._warnings([_page([{"id": "/r/1"}], truncated="true")])
        self.assertIn("TRUNCATED", out)
        self.assertIn("missing_in_azure", out)

    def test_the_sdk_enum_form_is_recognised_too(self):
        """The SDK may hand back an enum rather than the bare string."""
        out = self._warnings([
            _page([{"id": "/r/1"}], truncated=mock.Mock(value="true")),
        ])
        self.assertIn("TRUNCATED", out)

    def test_a_complete_read_warns_about_nothing(self):
        client = mock.Mock()
        client.resources.side_effect = [_page([{"id": "/r/1"}], truncated="false")]
        with self.assertNoLogs(resource_graph.logger, level="WARNING"):
            resource_graph._run_paginated_query(client, "sub", "Resources")


class ResourceGroupCollectorPagesTooTests(unittest.TestCase):
    """The RG collector shares the paged path: a subscription's resource groups
    can exceed one page like anything else, and a resource group read as absent
    takes every resource inside it down with it as an orphan."""

    def test_the_injected_query_returns_rows_across_pages(self):
        from tools.live_state.collectors.resource_groups import query_resource_groups

        client = mock.Mock()
        client.resources.side_effect = [
            _page([{"name": "rg-a", "id": "/subscriptions/s/resourceGroups/rg-a"}],
                  skip_token="tok-1"),
            _page([{"name": "rg-b", "id": "/subscriptions/s/resourceGroups/rg-b"}]),
        ]
        out = query_resource_groups(
            lambda kql: resource_graph._run_paginated_query(client, "sub", kql), "sub")
        self.assertEqual([g["name"] for g in out], ["rg-a", "rg-b"])


if __name__ == "__main__":
    unittest.main()
