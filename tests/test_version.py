# -*- encoding: utf-8

import pytest

from lswifi import __version__


class TestVersion:
    def test_title(self):
        assert __version__.__title__ == "lswifi"

    def test_version_format(self):
        """Version should be a string in semver-like format."""
        version = __version__.__version__
        assert isinstance(version, str)
        parts = version.split(".")
        assert len(parts) >= 2

    def test_metadata_strings(self):
        """All metadata fields should be non-empty strings."""
        assert isinstance(__version__.__description__, str)
        assert isinstance(__version__.__url__, str)
        assert isinstance(__version__.__author__, str)
        assert isinstance(__version__.__author_email__, str)
        assert isinstance(__version__.__license__, str)
        assert len(__version__.__description__) > 0
        assert len(__version__.__url__) > 0

    def test_license(self):
        assert __version__.__license__ == "BSD-3-Clause"
