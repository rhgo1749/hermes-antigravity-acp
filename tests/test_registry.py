import re

from antigravity_acp.registry import VERSION, resolve_distribution

# Publisher digests published by Google's first-party ACP update feed:
# https://dl.google.com/agy-extensions/releases/acp/feed/v1/next/1.4.3/acp_next.json
GOOGLE_FEED_PINS = {
    ("Linux", "x86_64"): "baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a",
    ("Linux", "aarch64"): "b0273227c07cfa1ea5c1d9ff869b64c5b2b39b98862081fcd4c597ec316e0c57",
    ("Darwin", "arm64"): "a3cf324046396380fcd8c055a4a4c83ac4ea74a38ea883ccbfce5ca1e9927ae9",
    ("Windows", "amd64"): "4b68e5936a3d7a60b520aa1ee9479c8be58c43e015f026dc41e7ad17ec54d427",
    ("Windows", "arm64"): "655835b095e160d726ee894a10e56960a9a81b03503edbd348079336163b28de",
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
