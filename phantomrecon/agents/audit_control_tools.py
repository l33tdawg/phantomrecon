#!/usr/bin/env python3
"""
Audit control tools used by ADK workflow agents:
- aggregate_findings: normalize and summarize results across specialist agents
- should_continue_audit: decide if the audit loop should continue
"""
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


def _get_state(context) -> Dict[str, Any]:
    if context and hasattr(context, 'session'):
        return context.session.state
    return {}


def aggregate_findings(context=None, **kwargs) -> Dict[str, Any]:
    state = _get_state(context)
    targets: List[str] = []
    findings: List[Dict[str, Any]] = []

    # Known result keys from specialist agents
    result_keys = [
        'web_security_results', 'api_security_results', 'sqli_results', 'ssh_network_results',
        'auth_results', 'cloud_security_results', 'cryptography_results',
        'cms_security_results', 'container_security_results', 'mobile_security_results'
    ]

    for key in result_keys:
        data = state.get(key)
        if not data:
            continue
        if isinstance(data, dict):
            if 'target' in data:
                targets.append(str(data.get('target')))
            # Extract vulnerabilities if present
            vulns = data.get('vulnerabilities') or data.get('issues') or []
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict):
                        v_copy = dict(v)
                        v_copy['source'] = key
                        findings.append(v_copy)

    # Compute simple coverage metrics
    coverage = {
        'agents_covered': [k for k in result_keys if state.get(k) is not None],
        'num_agents_with_results': len([k for k in result_keys if state.get(k) is not None]),
        'total_findings': len(findings),
        'unique_targets': len(set(targets)),
    }

    summary = {
        'critical': sum(1 for f in findings if str(f.get('severity', '')).upper() == 'CRITICAL'),
        'high': sum(1 for f in findings if str(f.get('severity', '')).upper() == 'HIGH'),
        'medium': sum(1 for f in findings if str(f.get('severity', '')).upper() == 'MEDIUM'),
        'low': sum(1 for f in findings if str(f.get('severity', '')).upper() == 'LOW'),
    }

    result = {
        'tool': 'aggregate_findings',
        'coverage': coverage,
        'summary': summary,
        'findings': findings,
    }

    # Persist for loop controller
    state['audit_findings'] = result
    state['last_findings_count'] = len(findings)

    # Track iteration counter
    iter_count = int(state.get('audit_iteration') or 0)
    state['audit_iteration'] = iter_count + 1

    return result


def should_continue_audit(context=None, **kwargs) -> Dict[str, Any]:
    """
    Decide if we should continue another loop iteration.
    Criteria:
      - Stop if iterations exceed max_iterations (default 5)
      - Stop if no_new_findings_threshold consecutive iterations with zero delta findings (default 2)
      - Stop if agent coverage threshold met and no critical/high findings remain
    """
    state = _get_state(context)
    max_iterations = int(kwargs.get('max_iterations') or 5)
    no_new_findings_threshold = int(kwargs.get('no_new_findings_threshold') or 2)
    required_coverage = int(kwargs.get('required_coverage') or 6)  # number of specialist agents with results

    iteration = int(state.get('audit_iteration') or 0)
    audit = state.get('audit_findings') or {}
    coverage = (audit.get('coverage') or {}).get('num_agents_with_results') or 0
    summary = audit.get('summary') or {}
    last = int(state.get('last_findings_count') or 0)
    prev = int(state.get('prev_findings_count') or 0)
    delta = last - prev

    # Update consecutive no-new count
    consecutive = int(state.get('no_new_consecutive') or 0)
    if delta <= 0:
        consecutive += 1
    else:
        consecutive = 0
    state['no_new_consecutive'] = consecutive
    state['prev_findings_count'] = last

    # Decision logic
    reasons: List[str] = []
    continue_flag = True

    if iteration >= max_iterations:
        continue_flag = False
        reasons.append(f"max_iterations_reached={iteration}")

    if coverage >= required_coverage and (summary.get('critical', 0) + summary.get('high', 0) == 0):
        continue_flag = False
        reasons.append("coverage_met_and_no_critical_high")

    if consecutive >= no_new_findings_threshold:
        continue_flag = False
        reasons.append(f"no_new_findings_consecutive={consecutive}")

    decision = {
        'tool': 'should_continue_audit',
        'continue': continue_flag,
        'iteration': iteration,
        'coverage': coverage,
        'summary': summary,
        'reasons': reasons or ["continue_searching"]
    }

    state['audit_continue_decision'] = decision
    return decision


