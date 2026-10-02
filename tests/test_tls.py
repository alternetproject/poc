import ssl

import pytest

from alternet.client import fetch
from alternet.lab import DEMO_BODY, Lab


@pytest.fixture(autouse=True)
def strict_verification(monkeypatch):
    create_context = ssl.create_default_context

    def strict_context(*args, **kwargs):
        context = create_context(*args, **kwargs)
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        return context

    monkeypatch.setattr(ssl, "create_default_context", strict_context)


@pytest.mark.parametrize("route", ["direct", "relay", "gateway"])
def test_generated_certificates_pass_strict_verification(lab, route):
    if route == "direct":
        config = lab.config("A")
        expected = ("A",)
    elif route == "relay":
        relay = lab.start_node(lab.config("C"))
        config = lab.config("A", peers=(relay.address,), blocked=True)
        expected = ("A", "C")
    else:
        _, url = lab.start_discovery("entry", ())
        config = lab.discovery_client((url,))
        expected = ("A", "entry")
    result = fetch(config, lab.url, ca_file=str(lab.ca))
    assert result.route == expected
    assert result.status == 200
    assert result.body == DEMO_BODY


def test_strict_verification_still_rejects_wrong_hostname():
    with Lab(cert_hostname="wrong.example") as lab:
        relay = lab.start_node(lab.config("C"))
        config = lab.config("A", peers=(relay.address,), blocked=True)
        with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"):
            fetch(config, lab.url, ca_file=str(lab.ca))


def test_strict_verification_still_rejects_untrusted_ca(lab):
    relay = lab.start_node(lab.config("C"))
    config = lab.config("A", peers=(relay.address,), blocked=True)
    with pytest.raises(ssl.SSLCertVerificationError):
        fetch(config, lab.url)
