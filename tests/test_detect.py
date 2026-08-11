"""Tests for the detectors.

Detectors are plain functions over a context, so these need no filesystem, no
clock and no live processes — a context is built by hand and the findings are
read back. Each detector gets a case that should fire and a case that should
not; the second kind is the one that keeps the tool installed.
"""

import pytest

from agentwatchdog import config, detect, state

NOW = 1_700_000_000


def event(**overrides):
    """An agent process event, defaulting to something entirely unremarkable."""
    base = {
        "agent": "claude-code",
        "agent_name": "Claude Code",
        "pid": 4242,
        "ppid": 4241,
        "starttime_ticks": 999,
        "user": "root",
        "uid": 0,
        "loginuid": None,
        "tty": "pts/0",
        "cwd": "/srv/app",
        "duration_sec": 60,
        "pcpu": 5.0,
        "pmem": 2.0,
        "rss_kb": 100_000,
        "persistent": False,
        "process_tree": [{"pid": 4242, "comm": "claude"}],
    }
    base.update(overrides)
    return base


def context(processes=(), invocations=(), cfg=None, cores=4, load5=0.5):
    settings = config.load("/nonexistent")
    settings.update(cfg or {})
    return detect.Context(
        now=NOW,
        cfg=settings,
        processes=list(processes),
        invocations=list(invocations),
        cores=cores,
        load5=load5,
    )


def types(findings):
    return [finding.type for finding in findings]


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------


def test_unexpected_user_is_silent_without_an_allow_list():
    findings = list(detect.identity.detect(context([event(user="mallory")])))

    # The default. An unfamiliar host gives us no basis to judge any account.
    assert findings == []


def test_unexpected_user_fires_when_an_allow_list_exists():
    findings = list(
        detect.identity.detect(
            context([event(user="mallory")], cfg={"ALLOWED_USERS": "root deploy"})
        )
    )

    assert types(findings) == ["unexpected_user"]
    assert findings[0].severity == "critical"
    assert "mallory" in findings[0].reason


def test_allowed_user_does_not_fire():
    findings = list(
        detect.identity.detect(context([event(user="deploy")], cfg={"ALLOWED_USERS": "deploy"}))
    )

    assert findings == []


def test_sudo_is_called_out_by_loginuid():
    # Running as root, logged in as someone else: name the human.
    findings = list(
        detect.identity.detect(
            context([event(user="root", uid=0, loginuid="1507")], cfg={"ALLOWED_USERS": "deploy"})
        )
    )

    assert "su or sudo" in findings[0].reason
    assert findings[0].extra["loginuid"] == "1507"


def test_one_account_running_many_agents_is_one_finding():
    processes = [event(user="mallory", pid=pid) for pid in range(10)]

    findings = list(detect.identity.detect(context(processes, cfg={"ALLOWED_USERS": "root"})))

    # Ten alerts for one situation is how an operator learns to ignore alerts.
    assert len({finding.key for finding in findings}) == 1


# --------------------------------------------------------------------------
# runtime
# --------------------------------------------------------------------------


def test_long_running_process_fires_past_the_limit():
    findings = list(detect.runtime.detect(context([event(duration_sec=20_000)])))

    assert types(findings) == ["long_running_process"]
    assert "5.6h" in findings[0].reason


def test_process_within_the_limit_does_not_fire():
    assert list(detect.runtime.detect(context([event(duration_sec=3600)]))) == []


def test_persistent_session_is_exempt_however_long_it_runs():
    # A session someone is sitting in front of is not a hung process. Getting
    # this wrong makes the detector useless on the hosts it is meant for.
    findings = list(detect.runtime.detect(context([event(duration_sec=10**6, persistent=True)])))

    assert findings == []


# --------------------------------------------------------------------------
# frequency
# --------------------------------------------------------------------------


def test_user_high_frequency_fires_over_threshold():
    invocations = [{"ts": NOW, "user": "deploy", "ppid": 100 + i} for i in range(15)]

    findings = list(detect.frequency.detect(context(invocations=invocations)))

    assert "user_high_frequency" in types(findings)


def test_normal_usage_does_not_fire():
    invocations = [{"ts": NOW, "user": "deploy", "ppid": 100 + i} for i in range(3)]

    assert list(detect.frequency.detect(context(invocations=invocations))) == []


def test_spawn_storm_is_critical_and_names_the_parent():
    # Same parent every time: no human does this.
    invocations = [{"ts": NOW, "user": "root", "ppid": 500} for _ in range(20)]

    findings = list(detect.frequency.detect(context(invocations=invocations)))
    storm = next(f for f in findings if f.type == "parent_spawn_storm")

    assert storm.severity == "critical"
    assert storm.extra["ppid"] == 500
    assert "500" in storm.action


# --------------------------------------------------------------------------
# resource
# --------------------------------------------------------------------------


def test_high_cpu_fires_for_a_sustained_burn():
    findings = list(detect.resource.detect(context([event(pcpu=150.0, duration_sec=3600)])))

    assert "high_cpu" in types(findings)


def test_high_cpu_ignores_a_process_too_young_to_average():
    """The false positive that would otherwise fire on every single launch.

    %CPU is a lifetime average, so a two-second-old process that spent both
    seconds starting up reads as ~100%.
    """
    findings = list(detect.resource.detect(context([event(pcpu=180.0, duration_sec=2)])))

    assert findings == []


def test_high_mem_fires_on_absolute_size():
    findings = list(detect.resource.detect(context([event(rss_kb=4_000_000, pmem=8.0)])))

    assert "high_mem" in types(findings)


def test_high_mem_fires_on_share_of_host():
    findings = list(detect.resource.detect(context([event(rss_kb=500_000, pmem=70.0)])))

    assert "high_mem" in types(findings)


def test_ordinary_resource_use_does_not_fire():
    assert list(detect.resource.detect(context([event()]))) == []


# --------------------------------------------------------------------------
# load
# --------------------------------------------------------------------------


def test_high_load_with_several_agents_fires():
    processes = [event(pid=pid) for pid in range(4)]

    findings = list(detect.load.detect(context(processes, cores=2, load5=9.0)))

    assert types(findings) == ["agents_during_high_load"]
    assert findings[0].extra["concurrent_agents"] == 4


def test_high_load_without_agents_is_not_our_problem():
    # The host being busy is someone else's alert unless agents are involved.
    assert list(detect.load.detect(context([event()], cores=2, load5=9.0))) == []


def test_many_agents_on_an_idle_host_does_not_fire():
    processes = [event(pid=pid) for pid in range(6)]

    assert list(detect.load.detect(context(processes, cores=8, load5=0.4))) == []


def test_persistent_sessions_do_not_count_toward_load():
    # An idle attached terminal contributes nothing to load.
    processes = [event(pid=pid, persistent=True) for pid in range(6)]

    assert list(detect.load.detect(context(processes, cores=2, load5=9.0))) == []


def test_load_detector_is_silent_when_load_is_unavailable():
    assert list(detect.load.detect(context([event()], load5=None))) == []


# --------------------------------------------------------------------------
# the runner: cooldown and formatting
# --------------------------------------------------------------------------


def test_run_emits_then_suppresses_the_same_situation():
    ctx = context([event(duration_sec=20_000)])
    current = state.load("/nonexistent")

    first = detect.run(ctx, current, cooldown_sec=3600)
    second = detect.run(ctx, current, cooldown_sec=3600)

    assert len(first) == 1
    # A monitor that repeats itself every 60 seconds gets turned off.
    assert second == []


def test_run_re_emits_once_the_cooldown_expires():
    current = state.load("/nonexistent")
    detect.run(context([event(duration_sec=20_000)]), current, cooldown_sec=3600)

    later = detect.Context(
        now=NOW + 4000,
        cfg=config.load("/nonexistent"),
        processes=[event(duration_sec=24_000)],
        invocations=[],
        cores=4,
        load5=0.5,
    )

    assert len(detect.run(later, current, cooldown_sec=3600)) == 1


def test_a_restarted_process_is_a_new_situation():
    """Cooldown keys must not collapse distinct processes.

    Same pid, different start time is a different process; suppressing the
    second because of the first would hide a crash loop.
    """
    current = state.load("/nonexistent")
    detect.run(context([event(duration_sec=20_000, starttime_ticks=1)]), current, 3600)

    findings = detect.run(context([event(duration_sec=20_000, starttime_ticks=2)]), current, 3600)

    assert len(findings) == 1


def test_alerts_carry_what_an_operator_needs():
    alerts = detect.run(context([event(duration_sec=20_000)]), state.load("/nonexistent"), 3600)

    alert = alerts[0]
    assert alert["alert_type"] == "long_running_process"
    assert alert["severity"] == "warning"
    assert alert["ts"] == NOW
    assert alert["datetime"].startswith("20")
    assert alert["suggested_action"]
    assert alert["process_tree"]


def test_all_detectors_run_in_one_pass():
    # Three processes, because the load detector is about concurrency and will
    # not fire below HIGH_LOAD_AGENT_MIN however bad any one of them looks.
    ctx = context(
        [
            event(user="mallory", pid=pid, duration_sec=20_000, pcpu=200.0, rss_kb=4_000_000)
            for pid in (11, 12, 13)
        ],
        invocations=[{"ts": NOW, "user": "mallory", "ppid": 7} for _ in range(20)],
        cfg={"ALLOWED_USERS": "root"},
        cores=1,
        load5=8.0,
    )

    alerts = detect.run(ctx, state.load("/nonexistent"), 3600)
    fired = {alert["alert_type"] for alert in alerts}

    assert fired == {
        "unexpected_user",
        "user_high_frequency",
        "parent_spawn_storm",
        "long_running_process",
        "high_cpu",
        "high_mem",
        "agents_during_high_load",
    }


@pytest.mark.parametrize("detector", detect.DETECTORS)
def test_every_detector_survives_an_empty_scan(detector):
    assert list(detector(context()) or []) == []
