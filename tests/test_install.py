"""Tests for the units the installer writes.

The timer's schedule is not cosmetic: the detectors count in scans, so an
interval that quietly runs long costs sampling coverage on every host that
installs this.
"""

import pytest

from agentwatchdog import install


@pytest.mark.parametrize(
    ("interval", "expected"),
    [
        (10, "OnCalendar=*:*:0/10"),
        (30, "OnCalendar=*:*:0/30"),
        (60, "OnCalendar=*:*:00"),
        (120, "OnCalendar=*:0/2:00"),
        (300, "OnCalendar=*:0/5:00"),
        (3600, "OnCalendar=*:00:00"),
    ],
)
def test_common_intervals_are_anchored_to_the_clock(interval, expected):
    assert install.timer_schedule(interval) == expected


def test_an_interval_that_does_not_divide_the_clock_falls_back():
    schedule = install.timer_schedule(90)

    assert "OnUnitActiveSec=90" in schedule
    assert "OnCalendar" not in schedule


def test_no_schedule_uses_a_step_equal_to_its_own_field():
    """systemd rejects "0/60" outright, and an unparsable timer never fires."""
    for interval in (10, 30, 60, 120, 300, 3600):
        assert "0/60" not in install.timer_schedule(interval)


def test_the_timer_does_not_let_systemd_stretch_the_interval():
    """The previous default deferred every run by up to five seconds.

    Measured over eight days that turned a 60s timer into 1334 scans a day
    instead of 1440.
    """
    unit = install.TIMER_TEMPLATE.format(interval=60, schedule=install.timer_schedule(60))

    assert "AccuracySec=1s" in unit
    assert "OnUnitActiveSec" not in unit
