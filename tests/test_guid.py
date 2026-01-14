# -*- encoding: utf-8

import sys

import pytest

if sys.platform == "win32":
    from lswifi import guid


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
class TestGUID:
    def test_guid_repr(self):
        """Test that __repr__ returns expected format."""
        g = guid.GUID()
        result = repr(g)
        assert result.startswith('GUID("')
        assert result.endswith('")')
