import pytest

from alternet.config import Address, Config, InvalidAddressError


def test_address():
    # instantiated with constructor args
    addr = Address('www.example.com', 8888)
    assert addr.host == 'www.example.com'
    assert addr.port == 8888

    # instantiated with classmethod parse()
    addr = Address.parse('www.example.com:8080')
    assert addr.host == 'www.example.com'
    assert addr.port == 8080

    # type check
    with pytest.raises(InvalidAddressError) as ex:
        addr = Address.parse(b'www.example.com:8080')
    assert 'must be str' in str(ex)

    # invalid chars check
    with pytest.raises(InvalidAddressError) as ex:
        addr = Address.parse('www  example.com:8080')  # note space
    assert 'cannot contain whitespace' in str(ex)

    # unwanted data in hostname
    for netloc in (
        'user:pass@www.example.com:8080',
        'user@www.example.com:8080',
        'www.example.com:8080/path',
        'www.example.com:8080/',
        'www.example.com:8080?query=search',
        'www.example.com:8080#frag',
        ):
        with pytest.raises(InvalidAddressError) as ex:
            addr = Address.parse(netloc)
        assert 'invalid host:port address' in str(ex)

    # port out of range -- this error comes from urlsplit()
    with pytest.raises(ValueError) as ex:
        addr = Address.parse('www.example.com:808080')
    assert 'Port out of range 0-65535' in str(ex)

    # port 0 without allow_zero
    with pytest.raises(InvalidAddressError) as ex:
        addr = Address.parse('www.example.com:0')
    assert 'invalid port: 0' in str(ex)
    # port 0 with allow_zero
    addr = Address.parse('www.example.com:0', True)
    assert addr.host == 'www.example.com'
    assert addr.port == 0

