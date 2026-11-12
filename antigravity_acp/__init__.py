from .registry import VERSION, Distribution, resolve_distribution

__all__ = ["VERSION", "Distribution", "resolve_distribution"]

# Scenario probe (issue #9 CI validation): a provider-package comment change must
# classify as install-surface scope (OS lanes yes, ARM lanes no).
