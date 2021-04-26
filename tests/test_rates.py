# -*- encoding: utf-8

import sys

import pytest

from lswifi.schemas import rates

# sys.path.insert(0, "../lswifi/")



class TestRates(object):

    def test_format_rate_(self):
        assert rates.format_rate(1.0) == "1"
        assert rates.format_rate(5.5) == "5.5"
        assert rates.format_rate(24.0) == "24"
        assert rates.format_rate(24) == "24"

    def test_get_basic_rates(self):
        assert (
            rates.get_basic_rates(
                [32770, 32772, 32779, 32790, 32780, 18, 32792, 36, 32816, 72, 96, 108]
            )
            == "1 2 5.5 11 6 12 24"
        )

    def test_get_data_rates(self):
        assert (
            rates.get_data_rates([32780, 18, 32792, 36, 32816, 72, 96, 108])
            == "9 18 36 48 54"
        )

    def test_get_rateset(self):
        assert (
            rates.get_rateset(
                [32770, 32772, 32779, 32790, 32780, 18, 32792, 36, 32816, 72, 96, 108]
            )
            == "1(B) 2(B) 5.5(B) 6(B) 11(B) 12(B) 24(B) 9 18 36 48 54"
        )

        assert rates.get_rateset([32816, 72, 96, 108]) == "24(B) 36 48 54"

    def test_rate_in_mbps(self):
        assert rates.rate_to_mbps(36) == 18.0
        assert rates.rate_to_mbps(11) == 5.5
