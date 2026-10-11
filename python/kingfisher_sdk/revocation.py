"""Explicit, potentially irreversible provider revocation."""
from __future__ import annotations
from dataclasses import dataclass, field
import math
import os
from time import monotonic
from types import MappingProxyType
from typing import Iterable, Mapping
from . import _native
from .rules import Rules
from .core import Finding
from .scanner import CancellationToken, Scanner
from .validation import InputDiagnostic, ValidationResult, Validator


@dataclass(frozen=True)
class RevocationResult:
    rule_id: str
    revoked: bool
    http_status: int | None


@dataclass(frozen=True)
class BatchRevocationResult:
    """One input's credential-free batch outcome, in original input order."""
    index: int
    rule_id: str
    outcome: str
    result: RevocationResult | None = None
    reason: str | None = None
    duplicate_of: int | None = None


@dataclass(frozen=True)
class RevocationCandidate:
    """Offline detection and actionable input issues; no live activity claim."""
    finding: Finding = field(repr=False)
    validation_supported: bool
    revocation_supported: bool
    input_diagnostics: tuple[InputDiagnostic, ...] = ()

    @property
    def rule_id(self) -> str:
        return self.finding.rule_id

    @property
    def missing_inputs(self) -> tuple[InputDiagnostic, ...]:
        return tuple(issue for issue in self.input_diagnostics
                     if issue.code in ("missing_dependency", "missing_variable"))

    @property
    def ready_for_validation(self) -> bool:
        """Known validation inputs are resolved; this does not prove validity."""
        return self.validation_supported and not any(
            issue.stage != "revocation" for issue in self.input_diagnostics)

    def to_dict(self, *, redact: bool = True) -> dict:
        return {"finding": self.finding.to_dict(redact=redact),
                "validation_supported": self.validation_supported,
                "revocation_supported": self.revocation_supported,
                "ready_for_validation": self.ready_for_validation,
                "input_diagnostics": [issue.to_dict() for issue in self.input_diagnostics]}


@dataclass(frozen=True)
class RevocationPlan:
    """Offline selection for one text/bytes input; secret fields omit repr.

    rule_ids contains the selected catalog IDs, including unsupported rules.
    candidates includes selected visible detections and their input diagnostics;
    candidate_rule_ids contains those defining revocation, even if inputs are missing.
    Empty candidates mean no revocable match, not proof that a secret is inactive.
    The plan retains findings and companion secrets; release it when finished.
    """
    rule_ids: tuple[str, ...]
    candidate_rule_ids: tuple[str, ...]
    _findings: tuple[Finding, ...] = field(repr=False)
    _candidate_indices: tuple[int, ...] = field(repr=False)
    candidates: tuple[RevocationCandidate, ...] = field(default=(), kw_only=True)
    source_path: str | None = field(default=None, repr=False, kw_only=True)
    _variables: Mapping[str, str] = field(default_factory=dict, repr=False, kw_only=True)

    def __post_init__(self):
        object.__setattr__(self, "_variables", MappingProxyType(dict(self._variables)))

    def to_dict(self, *, redact: bool = True) -> dict:
        """Report candidates and input diagnostics; secrets redact by default."""
        return {"rule_ids": list(self.rule_ids), "candidate_rule_ids": list(self.candidate_rule_ids),
                "source_path": self.source_path,
                "candidates": [candidate.to_dict(redact=redact) for candidate in self.candidates]}

    def validate(self, validator: Validator | None = None, *, timeout: float | None = None,
                 cancellation: CancellationToken | None = None) -> list[ValidationResult]:
        """Explicitly validate detected revocable candidates with supporting context.

        Returns candidates in scan order, including inactive/inconclusive states;
        it never chooses a winner or revokes. Supporting findings stay in the
        batch for native component association, without separate provider checks
        for helpers. Missing/ambiguous validation inputs skip provider work.
        A caller-supplied Validator can
        configure companion variables, enterprise endpoints and request controls.
        No candidates means no requests. The total deadline bounds this batch.
        """
        if not self._candidate_indices:
            return []
        validator = validator if validator is not None else Validator()
        if self._variables:
            # Explicit preparation variables overlay the supplied execution policy;
            # the shared binder still gives captures/components final precedence.
            validator = validator.with_variables(self._variables)
        states = validator._native.validate_prepared(
            [finding._native for finding in self._findings], list(self._candidate_indices),
            timeout=timeout, cancellation=cancellation)
        return [ValidationResult(self._findings[index], **state)
                for index, state in zip(self._candidate_indices, states, strict=True)]


def _deadline(timeout: float | None) -> float | None:
    if timeout is None:
        return None
    if (not math.isfinite(timeout) or timeout <= 0 or timeout >= 2**64
            or round(timeout * 1e9) == 0):
        raise ValueError("timeout must be finite and positive")
    return monotonic() + timeout


def _remaining(deadline: float | None, cancellation: CancellationToken | None) -> float | None:
    if cancellation is not None and cancellation.is_cancelled:
        raise RuntimeError("operation cancelled")
    remaining = None if deadline is None else deadline - monotonic()
    if remaining is not None and remaining <= 0:
        raise TimeoutError("operation timed out")
    return remaining


class Revoker:
    """Revoke a validated result or an exact rule ID with explicit confirmation.

    Supply Rules(["company.yml"], builtins=False) to prepare/revoke with custom
    YAML validation and revocation definitions; omit builtins=False to include
    the bundled catalog. Paths may also be directories. Result-based single and
    batch revocation retain the original custom action and resolved inputs,
    rather than looking up a replacement action in this Revoker's catalog.

    HTTP revocation is not retried; AWS uses its provider-specific retry policy.

    Uses the shared CLI HTTP/multi-step engine and AWS/GCP helpers. Only load
    trusted rules and endpoints: revocation sends credentials to rule URLs,
    including private addresses. Provider bodies are not returned to Python.
    """
    def __init__(self, rules: Rules | None = None, *, timeout: float = 10) -> None:
        self.rules = rules if rules is not None else Rules()
        self._native = _native.Revoker(self.rules._native, timeout)
        self._scanner: Scanner | None = None
        self._inspector: Validator | None = None

    def prepare(self, data: str | bytes, *, provider: str | None = None,
                variables: Mapping[str, str] | None = None,
                timeout: float | None = None,
                cancellation: CancellationToken | None = None) -> RevocationPlan:
        """Identify revocation candidates offline from a secret or its source text.

        provider accepts Rules.resolve() selectors: an exact rule ID, exact
        display name, or family (e.g. github). None selects the loaded catalog.
        Every selected detector is eligible, but only detected, visible rules
        with revocation become candidates. This scans the shared catalog then
        filters findings; it does not try each rule's provider API. Unlike normal
        scans, preparation retains missing-component candidates for diagnostics. Complete
        transitive dependencies are retained from this same input, even outside
        the selected family. Native scanning/binding handles captures/windows.

        Bare tokens may lack required context or companion values; supply the
        original text for compound credentials. No fuzzy selection, synthetic
        context, credential environment lookup or automatic revocation occurs.
        Overlapping matches remain separate candidates for explicit inspection.
        Explicit variables are retained for inspection/validation. Reuse this
        Revoker to reuse its compiled scanner. See prepare_from_text() for logical
        path/context support and prepare_from_file() for native file reading.
        """
        return self.prepare_from_text(data, provider=provider, variables=variables,
                                      timeout=timeout, cancellation=cancellation)

    def prepare_from_text(self, text: str | bytes, *, provider: str | None = None,
                          path: str | os.PathLike[str] | None = None,
                          variables: Mapping[str, str] | None = None,
                          timeout: float | None = None,
                          cancellation: CancellationToken | None = None) -> RevocationPlan:
        """Prepare one source text offline, keeping nearby compound credentials.

        path supplies a logical source path for path-aware detection; it is not
        read. Explicit variables configure supporting values/enterprise endpoints
        for both offline inspection and later validation. Required detected
        companions still require source context; variables don't fabricate them.
        Only preparation retains primaries missing dependencies, for diagnostics;
        normal Scanner behavior is unchanged. Timeout covers scan and inspection.
        """
        if isinstance(text, str):
            text = text.encode("utf-8")
        if not isinstance(text, bytes):
            raise TypeError("text must be str or bytes")
        return self._prepare(text, None, None if path is None else os.fspath(path),
                             provider, variables, _deadline(timeout), cancellation)

    def prepare_from_file(self, path: str | os.PathLike[str], *, provider: str | None = None,
                          variables: Mapping[str, str] | None = None,
                          timeout: float | None = None,
                          cancellation: CancellationToken | None = None) -> RevocationPlan:
        """Read one file offline with its real source path and complete context.

        Reuses native file reading/detection; no recursive enumeration, archive
        extraction or provider requests. File reads cannot be preempted. The file
        handle closes before return; the plan retains findings, not file bytes.
        Timeout covers reading, scanning and offline inspection.
        """
        source_path = os.fspath(path)
        return self._prepare(None, source_path, source_path, provider, variables,
                             _deadline(timeout), cancellation)

    def _prepare(self, data, file, source_path, provider, variables, deadline, cancellation):
        _remaining(deadline, cancellation)
        metadata = self.rules.metadata()
        by_id = {rule["id"]: rule for rule in metadata}
        selected = set(self.rules.resolve(provider) if provider is not None
                       else (rule["id"] for rule in metadata))
        revocable = {rule["id"] for rule in metadata
                     if rule["id"] in selected and rule["visible"] and rule["revocation"]}
        if self._scanner is None:
            self._scanner = Scanner(self.rules)
        findings = [Finding(finding) for finding in self._scanner._native.scan_preparation(
            data, file=file, path=source_path or "", timeout=_remaining(deadline, cancellation),
            cancellation=cancellation)]
        candidates = {finding.rule_id for finding in findings if finding.rule_id in revocable}
        matched = {finding.rule_id for finding in findings
                   if finding.visible and finding.rule_id in selected}
        # Keep only candidate rules and their dependencies. Unrelated provider
        # findings must never widen the subsequent explicit validation batch.
        required = set(matched)
        pending = list(matched)
        while pending:
            rule_id = pending.pop()
            for dependency in self.rules.detail(rule_id)["depends_on_rule"]:
                if dependency is not None and dependency["rule_id"] not in required:
                    required.add(dependency["rule_id"])
                    pending.append(dependency["rule_id"])
        retained = tuple(finding for finding in findings if finding.rule_id in required)
        variables = dict(variables or {})
        if self._inspector is None:
            self._inspector = Validator()
        diagnostics = self._inspector.with_variables(variables).inspect(
            retained, timeout=_remaining(deadline, cancellation), cancellation=cancellation)
        inspected = tuple(RevocationCandidate(finding, by_id[finding.rule_id]["validation"],
                                              by_id[finding.rule_id]["revocation"], issues)
                          for finding, issues in zip(retained, diagnostics, strict=True)
                          if finding.visible and finding.rule_id in selected)
        _remaining(deadline, cancellation)
        return RevocationPlan(tuple(sorted(selected)), tuple(sorted(candidates)), retained,
                              tuple(index for index, finding in enumerate(retained)
                                    if finding.rule_id in candidates), candidates=inspected,
                              source_path=source_path, _variables=variables)

    def revoke_many(self, results: Iterable[ValidationResult], *, confirm: bool = False,
                    timeout: float | None = None,
                    cancellation: CancellationToken | None = None) -> list[BatchRevocationResult]:
        """Explicitly revoke ready snapshots sequentially, returning one status per input.

        Eagerly materializes/type-checks the iterable before mutations. Skips
        unsupported/non-active/unresolved results. Deduplicates within this call
        by original rule/action definition and complete resolved inputs, keeping
        different compound pairs and endpoint/configuration snapshots distinct.
        Marking attempts before submission prevents retrying duplicates after an
        unknown outcome. Different rule IDs remain distinct: callers must resolve
        overlapping detector ambiguity before authorizing a batch.

        Outcomes: revoked, not_confirmed, skipped, duplicate, failed, unknown.
        Failures before mutation return failed; ambiguous submitted actions return
        unknown. Processing continues without retries. A total
        batch deadline/cancellation/Ctrl-C stops pending actions and propagates
        the normal exception, with .completed (safe statuses) and .pending_indices
        attached. An interrupted in-flight action is unknown, not rolled back.
        Constructor timeout still bounds each provider operation. Iteration of
        caller-owned generators cannot be preempted. No state persists between calls.
        """
        if confirm is not True:
            raise ValueError("revocation requires confirm=True")
        deadline = _deadline(timeout)
        results = list(results)
        if any(not isinstance(result, ValidationResult) for result in results):
            raise TypeError("revoke_many requires ValidationResult objects")
        completed = []
        attempted = {}

        def interrupted(error, pending):
            error.completed = tuple(completed)
            error.pending_indices = tuple(range(pending, len(results)))

        for index, validated in enumerate(results):
            submitted = False
            provider_result = None
            entry = None
            try:
                remaining = _remaining(deadline, cancellation)
                rule_id = validated.finding.rule_id
                if not validated.revocation_ready:
                    reason = validated.revocation_reason or (
                        "unsupported_revocation" if not validated.revocation_supported else validated.outcome)
                    entry = BatchRevocationResult(index, rule_id, "skipped", reason=reason)
                else:
                    inputs = validated.credential.revocation
                    key = (rule_id, inputs.secret, tuple(sorted(inputs.variables.items())))
                    # The native comparison includes the original action definition.
                    duplicate = next((previous for previous in attempted.get(key, ())
                                      if validated._native.same_revocation_as(results[previous]._native)), None)
                    if duplicate is not None:
                        entry = BatchRevocationResult(index, rule_id, "duplicate", duplicate_of=duplicate)
                    else:
                        attempted.setdefault(key, []).append(index)
                        submitted = True
                        try:
                            provider_result = self.revoke(validated, confirm=True, timeout=remaining,
                                                          cancellation=cancellation)
                        except ValueError:
                            entry = BatchRevocationResult(index, rule_id, "skipped", reason="invalid_inputs")
                        except RuntimeError as error:
                            if cancellation is not None and cancellation.is_cancelled:
                                raise
                            outcome = "unknown" if getattr(error, "outcome_unknown", True) else "failed"
                            entry = BatchRevocationResult(index, rule_id, outcome, reason="request_failed")
                        else:
                            outcome = "revoked" if provider_result.revoked else "not_confirmed"
                            entry = BatchRevocationResult(index, rule_id, outcome, result=provider_result)
                completed.append(entry)
            except (RuntimeError, TimeoutError, KeyboardInterrupt) as error:
                # Cover bookkeeping as well as provider I/O. A completed response
                # remains evidence even if cancellation arrives before its append.
                if completed and completed[-1].index == index:
                    pending = index + 1
                elif entry is not None:
                    completed.append(entry)
                    pending = index + 1
                elif provider_result is not None:
                    outcome = "revoked" if provider_result.revoked else "not_confirmed"
                    completed.append(BatchRevocationResult(index, validated.finding.rule_id, outcome,
                                                          result=provider_result))
                    pending = index + 1
                elif submitted:
                    reason = ("timeout" if isinstance(error, TimeoutError) else
                              "interrupted" if isinstance(error, KeyboardInterrupt) else "cancelled")
                    completed.append(BatchRevocationResult(index, validated.finding.rule_id, "unknown", reason=reason))
                    pending = index + 1
                else:
                    pending = index
                interrupted(error, pending)
                raise
        return completed

    def revoke(self, rule_id: str | ValidationResult, secret: str | None = None, *, confirm: bool = False,
               variables: Mapping[str, str] | None = None,
               timeout: float | None = None,
               cancellation: CancellationToken | None = None) -> RevocationResult:
        """Revoke a verified active ValidationResult using its retained inputs,
        or pass an exact rule ID, secret and supporting values explicitly.
        Exact-ID calls require secret and raise TypeError when it is omitted.
        Result-based calls use the original rule and cannot override inputs.
        Perform revocation only with confirm=True. Pass supporting values
        (e.g. AKID, KEY_ID and enterprise endpoint variables) explicitly.
        A timeout/error can mean the provider applied the operation without a
        response. Cancellation and Ctrl-C have the same ambiguity; inspect provider state before manually retrying.
        """
        if not isinstance(rule_id, ValidationResult) and secret is None:
            raise TypeError("secret is required with an exact rule ID")
        if confirm is not True:
            raise ValueError("revocation requires confirm=True")
        if isinstance(rule_id, ValidationResult):
            if secret is not None or variables is not None:
                raise ValueError("result-based revocation does not accept secret or variable overrides")
            if rule_id._native is None:
                raise ValueError("a result returned by Validator.validate() is required")
            return RevocationResult(**self._native.revoke_validated(
                rule_id._native, timeout=timeout, cancellation=cancellation))
        if secret is None:
            raise TypeError("secret is required with an exact rule ID")
        return RevocationResult(**self._native.revoke(
            rule_id, secret, dict(variables or {}),
            timeout=timeout, cancellation=cancellation))
