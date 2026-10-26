"""Process-matching primitives shared by the scan detectors and behavior attribution.

Extracted from engine.py so the scan pipeline and the behavior channel agree on
one definition of "this process looks like <agent rule>".
"""
from __future__ import annotations

import re

from agent_detector.core.models import ProcessInfo
from agent_detector.discovery.fingerprints.schema import ClientRule, ProcessSpec, SignatureRule


def process_text(proc: ProcessInfo) -> str:
    return " ".join((proc.name, *proc.cmdline))


def compile_excludes(spec: ProcessSpec | None) -> tuple[re.Pattern, ...]:
    if spec is None:
        return ()
    return tuple(re.compile(pattern) for pattern in spec.exclude_patterns)


def match_client_process(rule: ClientRule, proc: ProcessInfo,
                         excludes: tuple[re.Pattern, ...] | None = None) -> str | None:
    """Match one process against a client rule's ProcessSpec.

    Returns the match reason (``executable-name`` / ``executable-path`` /
    ``package-path``) or None; exclude patterns win first.
    """
    spec = rule.process
    if spec is None:
        return None
    patterns = excludes if excludes is not None else compile_excludes(spec)
    text = process_text(proc).replace("\\", "/").lower()
    if any(pattern.search(text) for pattern in patterns):
        return None
    exe_names = {name.lower() for name in spec.executable_names}
    if proc.name.lower() in exe_names:
        return "executable-name"
    if proc.cmdline:
        stem = proc.cmdline[0].replace("\\", "/").lower().rsplit("/", 1)[-1]
        if stem in exe_names:
            return "executable-path"
    tokens = [token.lower() for token in spec.cmdline_tokens]
    for arg in proc.cmdline:
        lowered = arg.replace("\\", "/").lower()
        if any(token in lowered for token in tokens):
            return "package-path"
    return None


def match_signature_process(rule: SignatureRule, proc: ProcessInfo) -> bool:
    return re.search(rule.pattern, process_text(proc), re.I) is not None