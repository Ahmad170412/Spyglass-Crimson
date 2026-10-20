from __future__ import annotations

import ipaddress

import pytest

from spyglass.validation import (
    ValidationError,
    expand_network,
    normalize_domain,
    parse_ip_target,
    parse_website,
    reverse_pointer,
)


def test_normalize_domain_and_url():
    assert normalize_domain("Example.COM.") == "example.com"
    assert parse_website("https://Example.COM/path?q=1").host == "example.com"
    assert parse_website("example.com:8443").host == "example.com"
    assert parse_website("//example.com/a").host == "example.com"
    assert parse_website("bücher.example").host == "xn--bcher-kva.example"


def test_website_rejects_non_domains():
    for value in ("", "localhost", "not a domain", "1.2.3.4", "http://user:pass@example.com"):
        with pytest.raises(ValidationError):
            parse_website(value)


def test_ip_targets():
    assert parse_ip_target("104.21.48.61").kind == "ip"
    assert parse_ip_target("2606:4700:4700::1111").kind == "ip"
    cidr = parse_ip_target("104.16.0.0/20")
    assert cidr.kind == "cidr"
    assert str(cidr.network) == "104.16.0.0/20"
    asn = parse_ip_target("AS13335")
    assert asn.kind == "asn"
    assert asn.asn == 13335
    assert asn.label == "AS13335"


def test_ip_target_rejects_bad_values():
    for value in ("", "999.1.1.1", "104.16.0.0/0", "AS0", "not-an-ip"):
        with pytest.raises(ValidationError):
            parse_ip_target(value)


def test_expand_network_is_bounded_and_deterministic():
    first = expand_network(ipaddress.ip_network("192.0.2.0/24"), limit=5)
    second = expand_network(ipaddress.ip_network("192.0.2.0/24"), limit=5)
    assert first.addresses == ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"]
    assert first == second
    assert first.total == 254
    assert first.truncated is True

    single = expand_network(ipaddress.ip_network("192.0.2.7/32"), limit=5)
    assert single.addresses == ["192.0.2.7"]
    assert single.total == 1
    assert single.truncated is False

    v6 = expand_network(ipaddress.ip_network("2001:db8::/120"), limit=3)
    assert len(v6.addresses) == 3
    assert v6.truncated is True


def test_reverse_pointer():
    assert reverse_pointer("1.1.1.1") == "1.1.1.1.in-addr.arpa"
    assert reverse_pointer("2606:4700:4700::1111").endswith(".ip6.arpa")
    with pytest.raises(ValidationError):
        reverse_pointer("nope")
