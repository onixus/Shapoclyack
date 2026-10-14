"""Portable scanner invocation. No admission, filesystem or API dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Mapping, Sequence

# Order is stable, but callers must compare meaning rather than argument order.
INPUT_FLAGS = {
    "ranges.txt": "--ranges",
    "domains.txt": "--domains",
    "ports.txt": "--ports-file",
    "ports_udp.txt": "--ports-udp-file",
    "scan_scope.json": "--scan-scope",
    "scan_policy.json": "--scan-policy",
    "config_overlay.json": "--config-overlay",
    "promoted_domains.txt": "--promoted-domains",
}


def input_arguments(paths: Mapping[str, str]) -> list[str]:
    unknown = set(paths) - INPUT_FLAGS.keys()
    if unknown:
        raise ValueError(f"unsupported scanner inputs: {sorted(unknown)}")
    if ("ranges.txt" in paths) != ("domains.txt" in paths):
        raise ValueError("ranges and domains paths must be supplied together")
    return [
        value
        for name, flag in INPUT_FLAGS.items()
        if name in paths
        for value in (flag, str(paths[name]))
    ]


def paths_from_arguments(arguments: Sequence[str]) -> dict[str, str]:
    """Strictly parse scanner input argv back into input paths (the inverse of :func:`input_arguments`)."""
    reverse = {flag: name for name, flag in INPUT_FLAGS.items()}
    if len(arguments) % 2:
        raise ValueError("scanner input arguments must be flag/path pairs")
    paths: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        flag, path = arguments[index : index + 2]
        if flag not in reverse or reverse[flag] in paths:
            raise ValueError(f"unsupported or repeated scanner input flag: {flag}")
        paths[reverse[flag]] = path
    input_arguments(paths)
    return paths


def required_input_names(command: Sequence[str]) -> set[str]:
    """Recover required logical files from an existing accepted command.

    Skip option values so a path literally matching a flag is not interpreted
    as a second input. Legacy commands without input flags require nothing.
    """
    reverse = {flag: name for name, flag in INPUT_FLAGS.items()}
    scalar = {*reverse, "--config", "--mode", "--run-id"}
    required = set()
    index = 0
    while index < len(command):
        token = command[index]
        if token in reverse:
            if index + 1 >= len(command):
                raise ValueError(f"missing accepted scanner input path: {token}")
            required.add(reverse[token])
        index += 2 if token in scalar else 1
    return required


@dataclass(frozen=True)
class ScanInvocation:
    config: str
    mode: str = "balanced"
    run_id: str | None = None
    delta: bool = False
    skip_nse: bool = False
    notify: bool = False
    export_defectdojo: bool = False
    inputs: Mapping[str, str] = field(default_factory=dict)

    def argv(self, executable: str) -> list[str]:
        if self.mode not in {"safe", "balanced", "fast"}:
            raise ValueError(f"unsupported scanner mode: {self.mode}")
        argv = [
            executable,
            "-m",
            "scanner.main",
            "--config",
            self.config,
            "--mode",
            self.mode,
        ]
        for name in ("delta", "skip_nse", "notify", "export_defectdojo"):
            if getattr(self, name):
                argv.append("--" + name.replace("_", "-"))
        if self.run_id:
            argv.extend(["--run-id", self.run_id])
        return argv + input_arguments(self.inputs)
