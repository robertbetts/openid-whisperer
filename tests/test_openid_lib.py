from openid_whisperer import openid_lib
import datetime


def test_get_now_seconds_epoch():
    secs = openid_lib.get_now_seconds_epoch()
    assert secs > 0


def test_get_date_seconds_epoch():
    now = datetime.datetime.now()
    secs = openid_lib.get_seconds_epoch(now)
    assert secs > 0
