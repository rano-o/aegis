#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import os
import shlex
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from slither.slither import Slither


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    contract: str
    function: str
    file: str
    lines: list[int]
    message: str
    evidence: str


@dataclass
class MemberAccess:
    base_name: str
    base_type: str
    member_name: str
    node_id: int


@dataclass
class CallFact:
    callee_name: str
    callee_contract: str
    call_kind: str
    node_id: int
    argument_names: tuple[str, ...]
    receiver_name: str
    result_name: str
    callee: Any | None = None


@dataclass
class VarReadFact:
    var_name: str
    node_id: int


@dataclass
class AssignmentFact:
    lvalue_name: str
    node_id: int
    op_text: str
    read_names: tuple[str, ...]


@dataclass
class ReturnFact:
    node_id: int
    returned_values: list[str]
    is_constant_zero: bool


@dataclass
class BranchFact:
    node_id: int
    condition_vars: list[str]


@dataclass
class SignatureFacts:
    parameter_types: list[str]
    parameter_names: list[str]
    return_types: list[str]


@dataclass
class CFGFacts:
    branches: list[BranchFact]
    returns: list[ReturnFact]
    node_count: int


@dataclass
class DFGFacts:
    member_accesses: list[MemberAccess]
    var_reads: list[VarReadFact]
    assignments: list[AssignmentFact]
    param_indices_used: set[int]


@dataclass
class CallGraphFacts:
    calls: list[CallFact]
    all_callee_names: list[str]


@dataclass
class FunctionIR:
    contract: Any
    function: Any
    sig: SignatureFacts
    cfg: CFGFacts
    dfg: DFGFacts
    cg: CallGraphFacts


@dataclass(frozen=True)
class ObservationEvidence:
    kind: str
    node_id: int
    detail: str


@dataclass(frozen=True)
class Observation:
    observed: bool
    evidence: tuple[ObservationEvidence, ...] = ()


@dataclass(frozen=True)
class SemanticRoleFact:
    role: str
    node_id: int
    detail: str


@dataclass(frozen=True)
class SemanticEvent:
    kind: str
    node_id: int
    detail: str
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReturnSite:
    node_id: int
    value: str
    kind: str
    success_like: bool
    event_kinds: tuple[str, ...]
    evidence: tuple[ObservationEvidence, ...]
    obligations: tuple[str, ...] = ()


@dataclass(frozen=True)
class HelperSummary:
    caller_guard: bool
    auth_like: bool
    hash_binding_like: bool
    recomputed_hash_like: bool
    nonce_ref_like: bool
    nonce_progress_like: bool
    evidence: tuple[ObservationEvidence, ...]


@dataclass(frozen=True)
class VOIR:
    contract_name: str
    function_name: str
    source_file: str
    lines: tuple[int, ...]
    source_snippet: str
    roles: tuple[SemanticRoleFact, ...]
    events: tuple[SemanticEvent, ...]
    return_sites: tuple[ReturnSite, ...]
    helper_summaries: tuple[HelperSummary, ...]
    provided_hash_vars: tuple[str, ...]
    recomputed_hash_vars: tuple[str, ...]
    auth: Observation
    hash_binding: Observation
    recomputed_hash: Observation
    nonce_ref: Observation
    nonce_progress: Observation
    caller_binding: Observation
    const_zero_return: Observation
    success_without_auth: Observation
    delegated_execution: Observation
    success_returns: Observation
    raw_success_returns: Observation
    template_delegation: Observation
    nonce_keyed_dispatch: Observation

    @property
    def is_delegated(self) -> bool:
        return any(hs.auth_like or hs.nonce_ref_like for hs in self.helper_summaries)


def _first_n(text: str | None, n: int = 240) -> str:
    if not text:
        return ""
    flat = " ".join(text.split())
    return flat[:n]


def _make_finding(
    rule_id: str,
    category: str,
    severity: str,
    contract: Any,
    function: Any,
    message: str,
) -> Finding:
    source_file = ""
    if function.source_mapping and function.source_mapping.filename:
        source_file = str(function.source_mapping.filename.absolute)
    lines = (
        list(function.source_mapping.lines)
        if function.source_mapping and function.source_mapping.lines
        else []
    )
    evidence = _first_n(
        function.source_mapping.content if function.source_mapping else "",
    )
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        contract=contract.name,
        function=function.name,
        file=source_file,
        lines=lines,
        message=message,
        evidence=evidence,
    )


def _make_voir_finding(
    voir: VOIR,
    rule_id: str,
    severity: str,
    message: str,
    *observations: Observation,
) -> Finding:
    evidence_parts: list[str] = []
    for obs in observations:
        for ev in obs.evidence:
            loc = f"node {ev.node_id}" if ev.node_id >= 0 else "global"
            evidence_parts.append(f"{ev.kind}@{loc}: {ev.detail}")
    evidence = " | ".join(evidence_parts[:6])
    if voir.source_snippet:
        evidence = (
            f"{evidence} || {voir.source_snippet}" if evidence else voir.source_snippet
        )
    return Finding(
        rule_id=rule_id,
        category="validateUserOp",
        severity=severity,
        contract=voir.contract_name,
        function=voir.function_name,
        file=voir.source_file,
        lines=list(voir.lines),
        message=message,
        evidence=evidence,
    )


def _is_synthetic_function(function: Any) -> bool:
    return function.name.startswith("slitherConstructor")


def _has_implementation_body(function: Any) -> bool:
    return len(getattr(function, "nodes", [])) > 0


def _is_actionable_function(contract: Any, function: Any) -> bool:
    if _is_synthetic_function(function):
        return False
    if getattr(contract, "is_interface", False):
        return False
    if not _has_implementation_body(function):
        return False
    return True


def _is_validate_userop_like(function: Any) -> bool:
    if len(function.parameters) < 3 or len(function.returns) < 1:
        return False
    p0 = str(function.parameters[0].type).lower()
    p1 = str(function.parameters[1].type).lower()
    p2 = str(function.parameters[2].type).lower()
    r0 = str(function.returns[0].type).lower()
    return (
        ("useroperation" in p0 or "packeduseroperation" in p0)
        and p1 == "bytes32"
        and p2 == "uint256"
        and r0 == "uint256"
    )


def _is_account_entry_implementation(contract: Any, function: Any) -> bool:
    name = contract.name.lower()
    if "validator" in name and "account" not in name:
        return False
    if "module" in name and "account" not in name:
        return False

    for f in contract.functions_declared:
        if f.name == function.name:
            continue
        if f.name in ("execute", "executeBatch", "executeUserOp"):
            return True
    return True


def _normalize(name: str) -> str:
    return name.lstrip("_").lower()


def _build_function_ir(contract: Any, function: Any) -> FunctionIR:
    from slither.slithir.operations import (
        HighLevelCall,
        InternalCall,
        LibraryCall,
        LowLevelCall,
        Member,
        Return,
    )

    param_types = [str(p.type).lower() for p in function.parameters]
    param_names = [p.name for p in function.parameters]
    return_types = [str(r.type).lower() for r in function.returns]
    sig = SignatureFacts(
        parameter_types=param_types,
        parameter_names=param_names,
        return_types=return_types,
    )

    branches: list[BranchFact] = []
    returns: list[ReturnFact] = []
    member_accesses: list[MemberAccess] = []
    var_reads: list[VarReadFact] = []
    assignments: list[AssignmentFact] = []
    calls: list[CallFact] = []
    param_indices_used: set[int] = set()
    node_count = 0

    param_name_set = set(param_names)

    for node in function.nodes:
        nid = node.node_id
        node_count += 1

        node_type_str = str(node.type)
        if "IF" in node_type_str:
            cond_vars = [getattr(v, "name", str(v)) for v in node.variables_read]
            branches.append(BranchFact(node_id=nid, condition_vars=cond_vars))

        for v in node.variables_read:
            vname = getattr(v, "name", str(v))
            var_reads.append(VarReadFact(var_name=vname, node_id=nid))
            if vname in param_name_set:
                try:
                    param_indices_used.add(param_names.index(vname))
                except ValueError:
                    pass

        for ir_op in node.irs:
            lvalue_obj = getattr(ir_op, "lvalue", None)
            lvalue_name = getattr(lvalue_obj, "name", str(lvalue_obj or ""))
            result_name = lvalue_name
            if lvalue_name:
                read_names = tuple(
                    getattr(v, "name", str(v)) for v in getattr(ir_op, "read", [])
                )
                assignments.append(
                    AssignmentFact(
                        lvalue_name=lvalue_name,
                        node_id=nid,
                        op_text=str(ir_op),
                        read_names=read_names,
                    )
                )

            if isinstance(ir_op, Member):
                base_var = ir_op.variable_left
                member_var = ir_op.variable_right
                base_name = getattr(base_var, "name", str(base_var))
                base_type = str(getattr(base_var, "type", ""))
                member_name = getattr(member_var, "name", str(member_var))
                member_accesses.append(
                    MemberAccess(
                        base_name=base_name,
                        base_type=base_type,
                        member_name=member_name,
                        node_id=nid,
                    )
                )

            if isinstance(ir_op, InternalCall):
                fname = getattr(ir_op.function, "name", str(ir_op.function))
                cname = ""
                if hasattr(ir_op.function, "contract_declarer"):
                    cname = str(ir_op.function.contract_declarer.name)
                arg_names = tuple(
                    getattr(arg, "name", str(arg))
                    for arg in getattr(ir_op, "arguments", [])
                )
                calls.append(
                    CallFact(
                        callee_name=_normalize(fname),
                        callee_contract=cname.lower(),
                        call_kind="internal",
                        node_id=nid,
                        argument_names=arg_names,
                        receiver_name="",
                        result_name=result_name,
                        callee=getattr(ir_op, "function", None),
                    )
                )
            elif isinstance(ir_op, LibraryCall):
                fname = getattr(ir_op.function, "name", str(ir_op.function))
                cname = ""
                receiver_name = getattr(
                    getattr(ir_op, "destination", None),
                    "name",
                    str(getattr(ir_op, "destination", "")),
                )
                if hasattr(ir_op, "destination") and hasattr(ir_op.destination, "type"):
                    cname = str(ir_op.destination.type)
                arg_names = tuple(
                    getattr(arg, "name", str(arg))
                    for arg in getattr(ir_op, "arguments", [])
                )
                calls.append(
                    CallFact(
                        callee_name=_normalize(fname),
                        callee_contract=cname.lower(),
                        call_kind="library",
                        node_id=nid,
                        argument_names=arg_names,
                        receiver_name=receiver_name,
                        result_name=result_name,
                        callee=getattr(ir_op, "function", None),
                    )
                )
            elif isinstance(ir_op, HighLevelCall):
                fname = getattr(ir_op.function, "name", str(ir_op.function))
                cname = ""
                receiver_name = getattr(
                    getattr(ir_op, "destination", None),
                    "name",
                    str(getattr(ir_op, "destination", "")),
                )
                if hasattr(ir_op, "destination") and hasattr(ir_op.destination, "type"):
                    cname = str(ir_op.destination.type)
                arg_names = tuple(
                    getattr(arg, "name", str(arg))
                    for arg in getattr(ir_op, "arguments", [])
                )
                calls.append(
                    CallFact(
                        callee_name=_normalize(fname),
                        callee_contract=cname.lower(),
                        call_kind="high_level",
                        node_id=nid,
                        argument_names=arg_names,
                        receiver_name=receiver_name,
                        result_name=result_name,
                        callee=getattr(ir_op, "function", None),
                    )
                )
            elif isinstance(ir_op, LowLevelCall):
                fname = str(getattr(ir_op, "function_name", ""))
                arg_names = tuple(
                    getattr(arg, "name", str(arg))
                    for arg in getattr(ir_op, "arguments", [])
                )
                calls.append(
                    CallFact(
                        callee_name=_normalize(fname),
                        callee_contract="",
                        call_kind="low_level",
                        node_id=nid,
                        argument_names=arg_names,
                        receiver_name="",
                        result_name=result_name,
                        callee=None,
                    )
                )

            if isinstance(ir_op, Return):
                ret_vals = []
                is_zero = False
                for rv in ir_op.values:
                    rstr = str(rv)
                    ret_vals.append(rstr)
                    if rstr.strip() == "0":
                        is_zero = True
                returns.append(
                    ReturnFact(
                        node_id=nid,
                        returned_values=ret_vals,
                        is_constant_zero=is_zero,
                    )
                )

    # Fallback: Slither's node.internal_calls catches modifier-injected calls
    # that SlithIR operations may miss.
    for node in function.nodes:
        for c in node.internal_calls:
            cname_raw = getattr(c, "name", str(c))
            ccontract = ""
            if hasattr(c, "contract_declarer") and c.contract_declarer:
                ccontract = str(c.contract_declarer.name).lower()
            normalized = _normalize(cname_raw)
            already = any(
                cf.callee_name == normalized and cf.node_id == node.node_id
                for cf in calls
            )
            if not already:
                calls.append(
                    CallFact(
                        callee_name=normalized,
                        callee_contract=ccontract,
                        call_kind="internal",
                        node_id=node.node_id,
                        argument_names=(),
                        receiver_name="",
                        result_name="",
                        callee=c,
                    )
                )

    seen_names: set[str] = set()
    all_callee_names: list[str] = []
    for cf in calls:
        if cf.callee_name not in seen_names:
            seen_names.add(cf.callee_name)
            all_callee_names.append(cf.callee_name)

    cfg = CFGFacts(branches=branches, returns=returns, node_count=node_count)
    dfg = DFGFacts(
        member_accesses=member_accesses,
        var_reads=var_reads,
        assignments=assignments,
        param_indices_used=param_indices_used,
    )
    cg = CallGraphFacts(calls=calls, all_callee_names=all_callee_names)

    return FunctionIR(
        contract=contract,
        function=function,
        sig=sig,
        cfg=cfg,
        dfg=dfg,
        cg=cg,
    )


def _collect_function_irs(sl: Slither) -> list[FunctionIR]:
    out: list[FunctionIR] = []
    for contract in sl.contracts:
        for function in contract.functions_declared:
            if not _is_validate_userop_like(function):
                continue
            if not _is_actionable_function(contract, function):
                continue
            if not _is_account_entry_implementation(contract, function):
                continue
            out.append(_build_function_ir(contract, function))
    return out


def _param_read(ir: FunctionIR, param_index: int) -> bool:
    return param_index in ir.dfg.param_indices_used


def _observe_constant_zero_returns(ir: FunctionIR) -> list[ObservationEvidence]:
    out: list[ObservationEvidence] = []
    for ret in ir.cfg.returns:
        if ret.is_constant_zero:
            out.append(ObservationEvidence("return", ret.node_id, "return 0"))
    return out


def _hash_provenance(ir: FunctionIR) -> tuple[set[str], set[str]]:
    provided_hash_vars: set[str] = set()
    recomputed_hash_vars: set[str] = set()
    result_to_callee: dict[str, str] = {
        cf.result_name: cf.callee_name
        for cf in ir.cg.calls
        if cf.result_name and cf.callee_name
    }
    if len(ir.sig.parameter_names) > 1:
        provided_hash_vars.add(ir.sig.parameter_names[1])

    changed = True
    while changed:
        changed = False
        for assign in ir.dfg.assignments:
            lhs = assign.lvalue_name
            if not lhs:
                continue
            reads = set(assign.read_names)
            callee_name = result_to_callee.get(lhs, "")
            wraps_provided_hash = bool(
                reads.intersection(provided_hash_vars)
            ) and callee_name in {
                "toethsignedmessagehash",
                "toethsignedmessagehashbytes32",
            }
            if wraps_provided_hash:
                if lhs not in provided_hash_vars:
                    provided_hash_vars.add(lhs)
                    changed = True
                continue
            if lhs not in recomputed_hash_vars and reads.intersection(
                recomputed_hash_vars
            ):
                recomputed_hash_vars.add(lhs)
                changed = True
            if (
                lhs not in provided_hash_vars
                and reads.intersection(provided_hash_vars)
                and lhs not in recomputed_hash_vars
            ):
                provided_hash_vars.add(lhs)
                changed = True

    return provided_hash_vars, recomputed_hash_vars


def _make_helper_summary(
    ir: FunctionIR,
    call: CallFact,
    provided_hash_vars: set[str],
    recomputed_hash_vars: set[str],
) -> HelperSummary:
    callee_name = call.callee_name
    evidence = [ObservationEvidence("call", call.node_id, callee_name)]
    receiver_name = call.receiver_name
    hash_related_names = set(call.argument_names)
    if receiver_name:
        hash_related_names.add(receiver_name)
    caller_guard = False
    auth_like = bool(hash_related_names.intersection(provided_hash_vars))
    hash_binding_like = auth_like and (
        any(
            arg == ir.sig.parameter_names[1]
            for arg in hash_related_names
            if len(ir.sig.parameter_names) > 1
        )
        or bool(hash_related_names.intersection(provided_hash_vars))
    )
    recomputed_hash_like = (
        auth_like
        and not hash_binding_like
        and (bool(hash_related_names.intersection(recomputed_hash_vars)))
    )
    nonce_ref_like = False
    nonce_progress_like = False
    return HelperSummary(
        caller_guard=caller_guard,
        auth_like=auth_like,
        hash_binding_like=hash_binding_like,
        recomputed_hash_like=recomputed_hash_like,
        nonce_ref_like=nonce_ref_like,
        nonce_progress_like=nonce_progress_like,
        evidence=tuple(evidence),
    )


def _internal_callee_sender_guard(call: CallFact) -> bool:
    callee = call.callee
    if callee is None:
        return False
    nodes = getattr(callee, "nodes", [])
    for node in nodes:
        node_type = str(getattr(node, "type", ""))
        if "IF" not in node_type:
            continue
        reads = [
            getattr(v, "name", str(v)).lower()
            for v in getattr(node, "variables_read", [])
        ]
        if any("msg.sender" in r for r in reads):
            return True
    return False


def _has_direct_sender_entrypoint_guard(ir: FunctionIR) -> bool:
    entrypoint_tmp_vars: set[str] = set()
    guard_tmp_vars: set[str] = set()
    for assign in ir.dfg.assignments:
        reads = {r.lower() for r in assign.read_names}
        if assign.lvalue_name and any("entrypoint" in r for r in reads):
            entrypoint_tmp_vars.add(assign.lvalue_name.lower())
        if any("msg.sender" in r for r in reads) and any(
            "entrypoint" in r for r in reads
        ):
            if assign.lvalue_name:
                guard_tmp_vars.add(assign.lvalue_name.lower())
        if any("msg.sender" in r for r in reads) and entrypoint_tmp_vars.intersection(
            reads
        ):
            if assign.lvalue_name:
                guard_tmp_vars.add(assign.lvalue_name.lower())
        if bool(guard_tmp_vars.intersection(reads)):
            return True
    return False


def _build_voir(ir: FunctionIR) -> VOIR:
    provided_hash_vars, recomputed_hash_vars = _hash_provenance(ir)
    roles: list[SemanticRoleFact] = []
    events: list[SemanticEvent] = []
    helper_summaries: list[HelperSummary] = []
    auth_evidence: list[ObservationEvidence] = []
    hash_binding_evidence: list[ObservationEvidence] = []
    recomputed_hash_evidence: list[ObservationEvidence] = []
    nonce_progress_evidence: list[ObservationEvidence] = []
    caller_binding_evidence: list[ObservationEvidence] = []

    if len(ir.sig.parameter_names) > 0:
        roles.append(SemanticRoleFact("user_op", -1, ir.sig.parameter_names[0]))
    if len(ir.sig.parameter_names) > 1:
        roles.append(SemanticRoleFact("user_op_hash", -1, ir.sig.parameter_names[1]))
    if len(ir.sig.parameter_names) > 2:
        roles.append(SemanticRoleFact("missing_funds", -1, ir.sig.parameter_names[2]))

    signature_members = [
        ObservationEvidence(
            "member_access", ma.node_id, f"{ma.base_name}.{ma.member_name}"
        )
        for ma in ir.dfg.member_accesses
        if len(ir.sig.parameter_names) > 0
        and ma.base_name == ir.sig.parameter_names[0]
        and ma.member_name.lower() == "signature"
    ]
    nonce_members = [
        ObservationEvidence(
            "member_access", ma.node_id, f"{ma.base_name}.{ma.member_name}"
        )
        for ma in ir.dfg.member_accesses
        if len(ir.sig.parameter_names) > 0
        and ma.base_name == ir.sig.parameter_names[0]
        and ma.member_name.lower() == "nonce"
    ]
    hash_reads = []
    if _param_read(ir, 1):
        hash_reads.append(ObservationEvidence("param_read", -1, "param[1]"))
    delegated_execution_evidence: list[ObservationEvidence] = []
    template_delegation_evidence: list[ObservationEvidence] = []
    nonce_keyed_dispatch_evidence: list[ObservationEvidence] = []

    for assign in ir.dfg.assignments:
        reads_lower = {r.lower() for r in assign.read_names}
        if any("delegatecall" in r for r in reads_lower):
            delegated_execution_evidence.append(
                ObservationEvidence("ir", assign.node_id, "delegatecall operation")
            )

    is_abstract_contract = bool(getattr(ir.contract, "is_abstract", False))
    has_internal_validation_hooks = any(
        cf.call_kind == "internal" and len(cf.argument_names) == 0 for cf in ir.cg.calls
    )
    if is_abstract_contract and has_internal_validation_hooks:
        template_delegation_evidence.append(
            ObservationEvidence(
                "semantic",
                -1,
                "abstract template delegates entrypoint/nonce/funding checks to hooks",
            )
        )

    has_module_registry_fetch = any(
        cf.call_kind == "internal"
        and len(cf.argument_names) == 1
        and any(
            "module" in rn.lower() or "validator" in rn.lower()
            for rn in cf.argument_names
        )
        for cf in ir.cg.calls
    )
    has_nonce_key_guard = any(
        any("nonce" in v.lower() for v in br.condition_vars)
        and any(
            ("validator" in v.lower()) or ("module" in v.lower())
            for v in br.condition_vars
        )
        for br in ir.cfg.branches
    )
    has_validate_selector_dispatch = any(
        any("validateuserop.selector" in rn.lower() for rn in a.read_names)
        or (
            any("userophash" in rn.lower() for rn in a.read_names)
            and any("userop" in rn.lower() for rn in a.read_names)
            and any("selector" in rn.lower() for rn in a.read_names)
        )
        for a in ir.dfg.assignments
    )
    has_low_level_validation_call = any(
        cf.call_kind == "low_level" and cf.callee_name == "call" for cf in ir.cg.calls
    )
    has_internal_sender_guard = any(
        cf.call_kind == "internal" and _internal_callee_sender_guard(cf)
        for cf in ir.cg.calls
    )
    has_direct_sender_guard = _has_direct_sender_entrypoint_guard(ir)
    if (
        has_module_registry_fetch
        and has_nonce_key_guard
        and has_validate_selector_dispatch
        and has_low_level_validation_call
    ):
        nonce_keyed_dispatch_evidence.append(
            ObservationEvidence(
                "semantic",
                -1,
                "nonce-keyed validator registry dispatch for validation",
            )
        )
    if has_internal_sender_guard or has_direct_sender_guard:
        caller_binding_evidence.append(
            ObservationEvidence(
                "semantic",
                -1,
                "sender guard exists in validateUserOp frame",
            )
        )
        events.append(
            SemanticEvent(
                "caller_guard",
                -1,
                "sender guard exists in validateUserOp frame",
                ("caller",),
            )
        )

    for ev in signature_members:
        roles.append(SemanticRoleFact("signature", ev.node_id, ev.detail))
        events.append(
            SemanticEvent(
                "signature_ref", ev.node_id, ev.detail, ("user_op", "signature")
            )
        )
    for ev in nonce_members:
        roles.append(SemanticRoleFact("nonce", ev.node_id, ev.detail))
        events.append(
            SemanticEvent("nonce_ref", ev.node_id, ev.detail, ("user_op", "nonce"))
        )
    for ev in hash_reads:
        roles.append(SemanticRoleFact("hash", ev.node_id, ev.detail))
        events.append(
            SemanticEvent("hash_ref", ev.node_id, ev.detail, ("user_op_hash",))
        )

    for call in ir.cg.calls:
        helper = _make_helper_summary(
            ir, call, provided_hash_vars, recomputed_hash_vars
        )
        helper_summaries.append(helper)
        if helper.auth_like:
            ev = ObservationEvidence("call", call.node_id, call.callee_name)
            auth_evidence.append(ev)
            events.append(
                SemanticEvent(
                    "auth_call", call.node_id, call.callee_name, ("signature", "hash")
                )
            )
        if helper.hash_binding_like:
            ev = ObservationEvidence(
                "call",
                call.node_id,
                f"{call.callee_name}({', '.join(call.argument_names)})",
            )
            hash_binding_evidence.append(ev)
            events.append(
                SemanticEvent(
                    "hash_bind", call.node_id, ev.detail, ("user_op_hash", "signature")
                )
            )
        if helper.recomputed_hash_like:
            ev = ObservationEvidence(
                "call",
                call.node_id,
                f"{call.callee_name}({', '.join(call.argument_names)})",
            )
            recomputed_hash_evidence.append(ev)
            events.append(
                SemanticEvent(
                    "recomputed_hash_auth",
                    call.node_id,
                    ev.detail,
                    ("hash", "signature"),
                )
            )
        if helper.nonce_ref_like:
            events.append(
                SemanticEvent("nonce_ref", call.node_id, call.callee_name, ("nonce",))
            )
        if helper.nonce_progress_like:
            ev = ObservationEvidence("call", call.node_id, call.callee_name)
            nonce_progress_evidence.append(ev)
            events.append(
                SemanticEvent(
                    "nonce_progress", call.node_id, call.callee_name, ("nonce",)
                )
            )
        if helper.caller_guard:
            ev = ObservationEvidence("call", call.node_id, call.callee_name)
            caller_binding_evidence.append(ev)
            events.append(
                SemanticEvent(
                    "caller_guard", call.node_id, call.callee_name, ("caller",)
                )
            )

    if not auth_evidence:
        for call in ir.cg.calls:
            if call.call_kind in {"library", "high_level"} and any(
                x in call.argument_names for x in provided_hash_vars
            ):
                ev = ObservationEvidence(
                    "call",
                    call.node_id,
                    "verification call with digest derived from provided hash",
                )
                auth_evidence.append(ev)
                events.append(
                    SemanticEvent(
                        "auth_call", call.node_id, ev.detail, ("signature", "hash")
                    )
                )
                hash_binding_evidence.append(
                    ObservationEvidence(
                        "call",
                        call.node_id,
                        "verification argument intersects provided hash lineage",
                    )
                )
                events.append(
                    SemanticEvent(
                        "hash_bind",
                        call.node_id,
                        "verification argument intersects provided hash lineage",
                        ("user_op_hash", "signature"),
                    )
                )

    if (
        not auth_evidence
        and has_module_registry_fetch
        and has_validate_selector_dispatch
    ):
        auth_evidence.append(
            ObservationEvidence(
                "semantic",
                -1,
                "validation delegated through module registry with fixed selector dispatch",
            )
        )
        events.append(
            SemanticEvent(
                "auth_call",
                -1,
                "validation delegated through module registry with fixed selector dispatch",
                ("signature", "hash"),
            )
        )

    if has_validate_selector_dispatch and has_nonce_key_guard and nonce_members:
        nonce_progress_evidence.append(
            ObservationEvidence(
                "semantic",
                -1,
                "nonce participates in selector-dispatched validation routing",
            )
        )
        events.append(
            SemanticEvent(
                "nonce_progress",
                -1,
                "nonce participates in selector-dispatched validation routing",
                ("nonce",),
            )
        )

    return_sites: list[ReturnSite] = []
    zero_return_evidence = _observe_constant_zero_returns(ir)
    success_without_auth_evidence: list[ObservationEvidence] = []
    success_returns_evidence: list[ObservationEvidence] = []
    raw_success_returns_evidence: list[ObservationEvidence] = []
    for ret in ir.cfg.returns:
        value = ret.returned_values[0] if ret.returned_values else ""
        success_like = ret.is_constant_zero
        kind = "constant_zero" if ret.is_constant_zero else "return"
        prior_event_kinds = tuple(
            sorted(
                {
                    ev.kind
                    for ev in events
                    if ev.node_id <= ret.node_id or ev.node_id < 0
                }
            )
        )
        obligations: list[str] = []
        if "auth_call" in prior_event_kinds or "auth_gate" in prior_event_kinds:
            obligations.append("auth")
        if "hash_bind" in prior_event_kinds:
            obligations.append("hash_bind")
        if "nonce_ref" in prior_event_kinds:
            obligations.append("nonce_ref")
        if "nonce_progress" in prior_event_kinds:
            obligations.append("nonce_progress")
        if "caller_guard" in prior_event_kinds:
            obligations.append("caller_guard")
        if "validation_window" in prior_event_kinds:
            obligations.append("validation_window")
        return_sites.append(
            ReturnSite(
                node_id=ret.node_id,
                value=value,
                kind=kind,
                success_like=success_like,
                event_kinds=prior_event_kinds,
                evidence=tuple([ObservationEvidence("return", ret.node_id, value)]),
                obligations=tuple(obligations),
            )
        )
        if success_like:
            success_returns_evidence.append(
                ObservationEvidence("return", ret.node_id, value)
            )
        if ret.is_constant_zero:
            raw_success_returns_evidence.append(
                ObservationEvidence("return", ret.node_id, value)
            )
        if (
            success_like
            and "auth_call" not in prior_event_kinds
            and "auth_gate" not in prior_event_kinds
        ):
            success_without_auth_evidence.append(
                ObservationEvidence("return", ret.node_id, value)
            )

    fn = ir.function
    source_file = ""
    lines: tuple[int, ...] = ()
    snippet = ""
    if fn.source_mapping:
        if fn.source_mapping.filename:
            source_file = str(fn.source_mapping.filename.absolute)
        if fn.source_mapping.lines:
            lines = tuple(fn.source_mapping.lines)
        snippet = _first_n(fn.source_mapping.content)

    auth_obs = Observation(bool(auth_evidence), tuple(auth_evidence))
    hash_obs = Observation(bool(hash_binding_evidence), tuple(hash_binding_evidence))
    recomputed_hash_obs = Observation(
        bool(recomputed_hash_evidence), tuple(recomputed_hash_evidence)
    )
    nonce_ref_obs = Observation(
        bool(nonce_members) or any(h.nonce_ref_like for h in helper_summaries),
        tuple(
            list(nonce_members)
            + [ev for hs in helper_summaries for ev in hs.evidence if hs.nonce_ref_like]
        ),
    )
    nonce_progress_obs = Observation(
        bool(nonce_progress_evidence), tuple(nonce_progress_evidence)
    )
    caller_obs = Observation(
        bool(caller_binding_evidence), tuple(caller_binding_evidence)
    )
    zero_return_obs = Observation(
        bool(zero_return_evidence), tuple(zero_return_evidence)
    )
    success_without_auth_obs = Observation(
        bool(success_without_auth_evidence), tuple(success_without_auth_evidence)
    )
    delegated_execution_obs = Observation(
        bool(delegated_execution_evidence), tuple(delegated_execution_evidence)
    )
    success_returns_obs = Observation(
        bool(success_returns_evidence), tuple(success_returns_evidence)
    )
    raw_success_returns_obs = Observation(
        bool(raw_success_returns_evidence), tuple(raw_success_returns_evidence)
    )
    template_delegation_obs = Observation(
        bool(template_delegation_evidence), tuple(template_delegation_evidence)
    )
    nonce_keyed_dispatch_obs = Observation(
        bool(nonce_keyed_dispatch_evidence), tuple(nonce_keyed_dispatch_evidence)
    )

    _ablation_mode = os.getenv("AEGIS_ABLATION", "")
    if _ablation_mode == "no_auth_lifting":
        auth_obs = Observation(False, ())
    elif _ablation_mode == "no_nonce_lifting":
        nonce_ref_obs = Observation(False, ())
        nonce_progress_obs = Observation(False, ())
    elif _ablation_mode == "no_hash_binding_lifting":
        hash_obs = Observation(False, ())
        recomputed_hash_obs = Observation(False, ())
    elif _ablation_mode == "no_caller_binding_lifting":
        caller_obs = Observation(False, ())
    elif _ablation_mode == "no_return_path_semantics":
        zero_return_obs = Observation(False, ())
        success_without_auth_obs = Observation(False, ())
        success_returns_obs = Observation(False, ())
        raw_success_returns_obs = Observation(False, ())
        return_sites = []
    elif _ablation_mode == "no_profile_binding":
        caller_obs = Observation(False, ())
        template_delegation_obs = Observation(False, ())
        nonce_keyed_dispatch_obs = Observation(False, ())
        delegated_execution_obs = Observation(False, ())
        return_sites = [
            ReturnSite(
                node_id=rs.node_id,
                value=rs.value,
                kind=rs.kind,
                success_like=rs.success_like,
                event_kinds=rs.event_kinds,
                evidence=rs.evidence,
                obligations=(),
            )
            for rs in return_sites
        ]
    elif _ablation_mode == "structural_only":
        auth_obs = Observation(False, ())
        hash_obs = Observation(False, ())
        recomputed_hash_obs = Observation(False, ())
        nonce_ref_obs = Observation(False, ())
        nonce_progress_obs = Observation(False, ())
        caller_obs = Observation(False, ())
        zero_return_obs = Observation(False, ())
        success_without_auth_obs = Observation(False, ())
        delegated_execution_obs = Observation(False, ())
        success_returns_obs = Observation(False, ())
        raw_success_returns_obs = Observation(False, ())
        template_delegation_obs = Observation(False, ())
        nonce_keyed_dispatch_obs = Observation(False, ())
        return_sites = []

    return VOIR(
        contract_name=ir.contract.name,
        function_name=fn.name,
        source_file=source_file,
        lines=lines,
        source_snippet=snippet,
        roles=tuple(roles),
        events=tuple(events),
        return_sites=tuple(return_sites),
        helper_summaries=tuple(helper_summaries),
        provided_hash_vars=tuple(sorted(provided_hash_vars)),
        recomputed_hash_vars=tuple(sorted(recomputed_hash_vars)),
        auth=auth_obs,
        hash_binding=hash_obs,
        recomputed_hash=recomputed_hash_obs,
        nonce_ref=nonce_ref_obs,
        nonce_progress=nonce_progress_obs,
        caller_binding=caller_obs,
        const_zero_return=zero_return_obs,
        success_without_auth=success_without_auth_obs,
        delegated_execution=delegated_execution_obs,
        success_returns=success_returns_obs,
        raw_success_returns=raw_success_returns_obs,
        template_delegation=template_delegation_obs,
        nonce_keyed_dispatch=nonce_keyed_dispatch_obs,
    )


def check_vu001(voir: VOIR) -> list[Finding]:
    if voir.template_delegation.observed:
        return []
    if voir.nonce_keyed_dispatch.observed:
        return []
    if voir.delegated_execution.observed:
        return []
    if voir.auth.observed:
        return []
    return [
        _make_voir_finding(
            voir,
            "VU001",
            "high",
            "validateUserOp appears to miss robust signature/authorization checks.",
            voir.auth,
        )
    ]


def check_vu002(voir: VOIR) -> list[Finding]:
    if voir.delegated_execution.observed:
        return []
    if voir.nonce_ref.observed or voir.is_delegated:
        return []
    return [
        _make_voir_finding(
            voir,
            "VU002",
            "high",
            "validateUserOp does not reference nonce; replay protection may be incomplete.",
            voir.nonce_ref,
            voir.auth,
            voir.caller_binding,
        )
    ]


def check_vu003(voir: VOIR) -> list[Finding]:
    if voir.delegated_execution.observed:
        return []
    if not voir.raw_success_returns.observed:
        return []
    if not voir.success_without_auth.observed:
        return []
    return [
        _make_voir_finding(
            voir,
            "VU003",
            "medium",
            "validateUserOp contains a constant-success return path without "
            "authentication/hash-binding semantics.",
            voir.raw_success_returns,
            voir.success_without_auth,
        )
    ]


def check_vu004(voir: VOIR) -> list[Finding]:
    if voir.delegated_execution.observed:
        return []
    if not voir.auth.observed:
        return []
    if voir.hash_binding.observed:
        return []
    if not voir.recomputed_hash.observed:
        return []
    return [
        _make_voir_finding(
            voir,
            "VU004",
            "medium",
            "validateUserOp likely fails to bind verification to a hash-like argument.",
            voir.auth,
            voir.hash_binding,
            voir.recomputed_hash,
        )
    ]


def check_vu005(voir: VOIR) -> list[Finding]:
    if voir.delegated_execution.observed:
        return []
    if not voir.nonce_ref.observed:
        return []
    if voir.is_delegated:
        return []
    if voir.template_delegation.observed:
        return []
    if voir.nonce_keyed_dispatch.observed:
        return []
    if voir.nonce_progress.observed:
        return []
    return [
        _make_voir_finding(
            voir,
            "VU005",
            "medium",
            "validateUserOp references nonce but no clear consume/update signal is visible.",
            voir.nonce_ref,
            voir.nonce_progress,
            voir.auth,
            voir.caller_binding,
        )
    ]


def check_vu007(voir: VOIR) -> list[Finding]:
    if voir.delegated_execution.observed:
        return []
    if voir.template_delegation.observed:
        return []
    if voir.caller_binding.observed:
        return []
    return [
        _make_voir_finding(
            voir,
            "VU007",
            "medium",
            "validateUserOp may miss strict caller binding to trusted EntryPoint flow.",
            voir.caller_binding,
        )
    ]


_VU_CHECKERS = [
    check_vu001,
    check_vu002,
    check_vu003,
    check_vu004,
    check_vu005,
    check_vu007,
]


def detect_validate_user_op(sl: Slither) -> list[Finding]:
    findings: list[Finding] = []
    for ir in _collect_function_irs(sl):
        voir = _build_voir(ir)
        for checker in _VU_CHECKERS:
            findings.extend(checker(voir))
    return findings


def run(
    target: str,
    solc: str = "",
    solc_args: str = "",
    solc_remaps: list[str] | None = None,
) -> list[Finding]:
    kwargs: dict[str, Any] = {}
    target_path = Path(target)
    if solc:
        kwargs["solc"] = solc
    if solc_args:
        kwargs["solc_args"] = solc_args
    if solc_remaps:
        kwargs["solc_remaps"] = solc_remaps
    if target_path.is_file():
        kwargs["compile_force_framework"] = "solc"
        kwargs["foundry_ignore_compile"] = True
        kwargs["hardhat_ignore_compile"] = True
    sl = Slither(target, **kwargs)
    return detect_validate_user_op(sl)


def _group_summary(findings: Iterable[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.rule_id] = out.get(f.rule_id, 0) + 1
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase-1 ERC-4337 static detector (IR + lightweight VU checkers)",
    )
    parser.add_argument("target", help="Solidity file, directory, or project root")
    parser.add_argument(
        "--json-out", default="", help="Write machine-readable findings JSON to path"
    )
    parser.add_argument("--solc", default="", help="Path to solc binary (optional)")
    parser.add_argument(
        "--solc-args", default="", help="Extra solc args, e.g. remappings/include paths"
    )
    parser.add_argument("--solc-remaps", default="", help="Comma-separated remappings")
    args = parser.parse_args()
    remaps: list[str] = []
    for tok in shlex.split(args.solc_remaps):
        remaps.extend([r for r in tok.split(",") if r])
    findings = run(
        args.target, solc=args.solc, solc_args=args.solc_args, solc_remaps=remaps
    )
    print(f"[aa4337] analyzed target: {args.target}")
    print(f"[aa4337] findings: {len(findings)}")
    for rule, count in sorted(_group_summary(findings).items()):
        print(f"  - {rule}: {count}")
    if findings:
        print("\n[aa4337] detailed findings")
        for f in findings:
            loc = f"{f.file}:{f.lines[0] if f.lines else '?'}"
            print(f"- [{f.severity}] {f.rule_id} {f.contract}.{f.function} @ {loc}")
            print(f"  {f.message}")
    if args.json_out:
        payload = {
            "target": args.target,
            "total_findings": len(findings),
            "summary": _group_summary(findings),
            "findings": [asdict(f) for f in findings],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[aa4337] JSON written: {args.json_out}")


if __name__ == "__main__":
    main()
