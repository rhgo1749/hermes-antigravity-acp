def test_gate_negative_probe_issue9_must_fail():
    """Throwaway sabotage for issue #9: the CI gate must refuse to pass."""
    assert False, "intentional negative probe (issue #9 gate fail-closed validation)"
