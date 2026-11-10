from __future__ import annotations

import platform
from dataclasses import dataclass

VERSION = "1.4.4"

# The SHA-256 digests below are the publisher digests published by Google's
# first-party Antigravity ACP update feed channel that advertises this
# version:
#   https://dl.google.com/agy-extensions/releases/acp/feed/v1/next/1.4.3/acp_next.json
# (fetched and re-verified byte-identical on 2026-11-05). Google publishes no
# detached checksum file for the archive URLs themselves; the feed JSON is
# the only first-party digest source. Google offered no digest feed for the
# previously pinned 1.4.0, so this pin was raised to the first version with
# verifiable first-party digests rather than pinning unverified bytes.
# Rotation policy: fetch the feed for the intended version and change
# VERSION and every digest together in one reviewed commit; never hand-edit
# a digest and never promote a locally computed hash to publisher status.


@dataclass(frozen=True)
class Distribution:
    url: str
    executable: str
    sha256: str
    args: tuple[str, ...] = ()


_DISTRIBUTIONS: dict[tuple[str, str], Distribution] = {
    ("linux", "x86_64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/linux/"
            f"agy-acp-server-{VERSION}-linux-x86_64.zip"
        ),
        executable="agy_acp_server.par",
        sha256=("baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a"),
        args=("--uid=",),
    ),
    ("linux", "aarch64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/linux/"
            f"agy-acp-server-{VERSION}-linux-arm64.zip"
        ),
        executable="agy_acp_server.par",
        sha256=("b0273227c07cfa1ea5c1d9ff869b64c5b2b39b98862081fcd4c597ec316e0c57"),
        args=("--uid=",),
    ),
    ("darwin", "arm64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/macos/"
            f"agy-acp-server-{VERSION}-darwin-arm64.zip"
        ),
        executable="agy_acp_server.par",
        sha256=("a3cf324046396380fcd8c055a4a4c83ac4ea74a38ea883ccbfce5ca1e9927ae9"),
    ),
    ("windows", "amd64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/windows/"
            f"agy-acp-server-{VERSION}-windows-x86_64.zip"
        ),
        executable="agy_acp_server.exe",
        sha256=("4b68e5936a3d7a60b520aa1ee9479c8be58c43e015f026dc41e7ad17ec54d427"),
    ),
    ("windows", "arm64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/windows/"
            f"agy-acp-server-{VERSION}-windows-arm64.zip"
        ),
        executable="agy_acp_server.exe",
        sha256=("655835b095e160d726ee894a10e56960a9a81b03503edbd348079336163b28de"),
    ),
}


def resolve_distribution(system: str | None = None, machine: str | None = None) -> Distribution:
    system = (system or platform.system()).strip().lower()
    machine = (machine or platform.machine()).strip().lower()
    aliases = {
        "x86-64": "x86_64",
        "x64": "x86_64",
        "amd64": "amd64" if system == "windows" else "x86_64",
        "arm64": "arm64" if system in {"darwin", "windows"} else "aarch64",
    }
    machine = aliases.get(machine, machine)
    try:
        return _DISTRIBUTIONS[(system, machine)]
    except KeyError as exc:
        supported = ", ".join(f"{s}/{m}" for s, m in sorted(_DISTRIBUTIONS))
        raise RuntimeError(f"Unsupported platform {system}/{machine}. Supported: {supported}") from exc
