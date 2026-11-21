from __future__ import annotations

import platform
from dataclasses import dataclass

VERSION = "1.5.2"

# The SHA-256 digests below are the publisher digests published by Google's
# first-party Antigravity ACP update feed channel that advertises this
# version:
#   https://dl.google.com/agy-extensions/releases/acp/feed/v1/next/1.5.0/acp_next.json
# (fetched on 2026-11-18 and cross-checked digest-for-digest against the
# upstream ACP registry entry for antigravity-acp 1.5.2,
# agentclientprotocol/registry@e29b5bf3bfd8756db5d901690b43dc31e926ccd5;
# the feed's darwin-x86_64 target is intentionally not adopted here — this
# project's supported platform set is unchanged at five targets). Google
# publishes no detached checksum file for the archive URLs themselves; the
# feed JSON is the only first-party digest source. Google offered no digest
# feed for the formerly pinned 1.4.0, so pins only ever move to versions
# with verifiable first-party digests rather than pinning unverified bytes.
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
        sha256=("99dd8612450805011619d7b8447ce374c289e00549d8557f36790e1dd6256852"),
        args=("--uid=",),
    ),
    ("linux", "aarch64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/linux/"
            f"agy-acp-server-{VERSION}-linux-arm64.zip"
        ),
        executable="agy_acp_server.par",
        sha256=("e729e05ef54ef0763e48900032466b47fa7c9939cde257f93ba49410ab577acb"),
        args=("--uid=",),
    ),
    ("darwin", "arm64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/macos/"
            f"agy-acp-server-{VERSION}-darwin-arm64.zip"
        ),
        executable="agy_acp_server.par",
        sha256=("123a16d5c40a8ac99e20f01a62b68dd860fd96b1c528dfb8eaa37ca8733d4845"),
    ),
    ("windows", "amd64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/windows/"
            f"agy-acp-server-{VERSION}-windows-x86_64.zip"
        ),
        executable="agy_acp_server.exe",
        sha256=("5cbadd4f4df698572473d8890fc26ec2dc1724501f06e3a963941daec2bd21d6"),
    ),
    ("windows", "arm64"): Distribution(
        url=(
            "https://dl.google.com/agy-extensions/releases/windows/"
            f"agy-acp-server-{VERSION}-windows-arm64.zip"
        ),
        executable="agy_acp_server.exe",
        sha256=("8a4b2ea8df2ffefae33309348752e9119d21a6d36090c0eb48631c2e8f5781ab"),
    ),
}


def resolve_distribution(system: str | None = None, machine: str | None = None) -> Distribution:
    system = (system or platform.system()).strip().lower()
    machine = (machine or platform.machine()).strip().lower()
    aliases = {
        "x86-64": "amd64" if system == "windows" else "x86_64",
        "x64": "amd64" if system == "windows" else "x86_64",
        "x86_64": "amd64" if system == "windows" else "x86_64",
        "amd64": "amd64" if system == "windows" else "x86_64",
        "aarch64": "arm64" if system in {"darwin", "windows"} else "aarch64",
        "arm64": "arm64" if system in {"darwin", "windows"} else "aarch64",
    }
    machine = aliases.get(machine, machine)
    try:
        return _DISTRIBUTIONS[(system, machine)]
    except KeyError as exc:
        supported = ", ".join(f"{s}/{m}" for s, m in sorted(_DISTRIBUTIONS))
        raise RuntimeError(f"Unsupported platform {system}/{machine}. Supported: {supported}") from exc
