from __future__ import annotations

import httpx
import pytest
import respx

from spyglass.models import SourceError
from spyglass.sources.spamhaus import DROP_V4, DROP_V6, SpamhausDropSource
from spyglass.sources.tor import TOR_EXIT_LIST, TorExitSource
from spyglass.validation import parse_ip_target


@respx.mock
def test_tor_reports_exit_node(ctx):
    respx.get(TOR_EXIT_LIST).mock(
        return_value=httpx.Response(200, text="203.0.113.9\n198.51.100.7\n")
    )
    result = TorExitSource().run(parse_ip_target("203.0.113.9"), ctx)
    assert result.status == "ok"
    assert result.data["is_tor_exit"] is True
    assert result.data["list_size"] == 2
    assert result.record_count == 1


@respx.mock
def test_tor_absent_address_is_empty(ctx):
    respx.get(TOR_EXIT_LIST).mock(return_value=httpx.Response(200, text="203.0.113.9\n"))
    result = TorExitSource().run(parse_ip_target("198.51.100.7"), ctx)
    assert result.status == "empty"
    assert result.data["is_tor_exit"] is False


@respx.mock
def test_tor_list_is_cached(ctx):
    route = respx.get(TOR_EXIT_LIST).mock(
        return_value=httpx.Response(200, text="203.0.113.9\n")
    )
    source = TorExitSource()
    source.run(parse_ip_target("203.0.113.9"), ctx)
    source.run(parse_ip_target("203.0.113.10"), ctx)
    assert route.call_count == 1


@respx.mock
def test_tor_unavailable_list_is_an_error(ctx):
    respx.get(TOR_EXIT_LIST).mock(return_value=httpx.Response(503))
    with pytest.raises(SourceError):
        TorExitSource().run(parse_ip_target("203.0.113.9"), ctx)


DROP = (
    '{"cidr":"203.0.113.0/24","sblid":"SBL-TEST","rir":"arin"}\n'
    '{"cidr":"198.51.100.0/24","sblid":"SBL-TEST-2","rir":"arin"}\n'
)


@respx.mock
def test_spamhaus_reports_match(ctx):
    respx.get(DROP_V4).mock(return_value=httpx.Response(200, text=DROP))
    respx.get(DROP_V6).mock(return_value=httpx.Response(200, text=""))
    result = SpamhausDropSource().run(parse_ip_target("203.0.113.9"), ctx)
    assert result.status == "ok"
    assert result.data["listed"] is True
    assert result.data["matches"][0]["sblid"] == "SBL-TEST"
    assert result.data["dataset_size"] == 2


@respx.mock
def test_spamhaus_no_match_is_empty(ctx):
    respx.get(DROP_V4).mock(return_value=httpx.Response(200, text=DROP))
    respx.get(DROP_V6).mock(return_value=httpx.Response(200, text=""))
    result = SpamhausDropSource().run(parse_ip_target("192.0.2.1"), ctx)
    assert result.status == "empty"
    assert result.data["listed"] is False


@respx.mock
def test_spamhaus_degraded_dataset_is_partial(ctx):
    respx.get(DROP_V4).mock(return_value=httpx.Response(503))
    respx.get(DROP_V6).mock(
        return_value=httpx.Response(200, text='{"cidr":"2001:db8::/32","sblid":"SBL6","rir":"arin"}\n')
    )
    result = SpamhausDropSource().run(parse_ip_target("192.0.2.1"), ctx)
    assert result.status == "partial"
    assert result.data["degraded"] == ["drop_v4.json"]


@respx.mock
def test_spamhaus_matches_v6(ctx):
    respx.get(DROP_V4).mock(return_value=httpx.Response(200, text=""))
    respx.get(DROP_V6).mock(
        return_value=httpx.Response(200, text='{"cidr":"2001:db8::/32","sblid":"SBL6","rir":"arin"}\n')
    )
    result = SpamhausDropSource().run(parse_ip_target("2001:db8::1"), ctx)
    assert result.status == "ok"
    assert result.data["matches"][0]["cidr"] == "2001:db8::/32"


@respx.mock
def test_tor_ipv6_is_partial_not_a_false_negative(ctx):
    route = respx.get(TOR_EXIT_LIST)
    result = TorExitSource().run(parse_ip_target("2001:db8::1"), ctx)
    assert result.status == "partial"
    assert result.data["is_tor_exit"] is False
    assert "IPv4-only" in result.data["note"]
    assert not route.called
