import re

from antigravity_acp.registry import VERSION, resolve_distribution

# Publisher digests published by Google's first-party ACP update feed:
# https://dl.google.com/agy-extensions/releases/acp/feed/v1/next/1.5.0/acp_next.json
GOOGLE_FEED_PINS = {
    ("Linux", "x86_64"): "99dd8612450805011619d7b8447ce374c289e00549d8557f36790e1dd6256852",
    ("Linux", "aarch64"): "e729e05ef54ef0763e48900032466b47fa7c9939cde257f93ba49410ab577acb",
    ("Darwin", "arm64"): "123a16d5c40a8ac99e20f01a62b68dd860fd96b1c528dfb8eaa37ca8733d4845",
    ("Windows", "amd64"): "5cbadd4f4df698572473d8890fc26ec2dc1724501f06e3a963941daec2bd21d6",
    ("Windows", "arm64"): "8a4b2ea8df2ffefae33309348752e9119d21a6d36090c0eb48631c2e8f5781ab",
}


def test_linux_x86_64_uses_google_registry_shape() -> None:
    dist = resolve_distribution("Linux", "x86_64")
    assert VERSION in dist.url
    assert dist.url.startswith("https://dl.google.com/agy-extensions/releases/linux/")
    assert dist.executable == "agy_acp_server.par"
    assert dist.args == ("--uid=",)


def test_arm64_aliases_by_platform() -> None:
    assert resolve_distribution("Linux", "arm64").url.endswith("linux-arm64.zip")
    assert resolve_distribution("Darwin", "arm64").url.endswith("darwin-arm64.zip")
    assert resolve_distribution("Windows", "aarch64") == resolve_distribution("Windows", "arm64")
    assert resolve_distribution("Windows", "x86_64") == resolve_distribution("Windows", "amd64")
    assert resolve_distribution("Windows", "x64") == resolve_distribution("Windows", "amd64")


def test_every_distribution_carries_the_google_feed_digest() -> None:
    for (system, machine), expected in GOOGLE_FEED_PINS.items():
        dist = resolve_distribution(system, machine)
        assert dist.sha256 == expected
        assert re.fullmatch(r"[0-9a-f]{64}", dist.sha256)


def test_unsupported_platform_fails_closed() -> None:
    import pytest

    with pytest.raises(RuntimeError, match="Unsupported platform"):
        resolve_distribution("Plan 9", "x86_64")
