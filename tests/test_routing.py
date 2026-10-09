import time
from unittest import mock

import pytest

from alternet import routing


def test_remaining():

    tick = time.monotonic()

    with mock.patch('alternet.routing.time.monotonic', return_value=tick):
        # still have time
        remains = routing.remaining(tick + 1.2345)
        assert remains == pytest.approx(1.2345)

        # out of time!
        with pytest.raises(TimeoutError) as ex:
            remains = routing.remaining(tick - 0.1)
        assert 'route establishment deadline expired' in str(ex)


