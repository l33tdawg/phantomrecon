#!/usr/bin/env python3
"""
Container and Kubernetes Security Tools
Checks for exposed Docker/Kubernetes APIs and basic misconfigurations
"""
from typing import Dict, Any
import requests
import logging
import json

logger = logging.getLogger(__name__)

async def test_docker_api_exposure(context=None, **kwargs) -> Dict[str, Any]:
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    results = {"test": "docker_api_exposure", "target": target, "vulnerabilities": []}
    # Common Docker API ports
    ports = [2375, 2376]
    for port in ports:
        try:
            url = f"http://{target}:{port}/version"
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and 'ApiVersion' in r.text:
                results["vulnerabilities"].append({
                    "type": "Exposed Docker API",
                    "severity": "CRITICAL",
                    "endpoint": url,
                    "remediation": "Bind Docker API to localhost and require TLS/authentication"
                })
        except Exception:
            continue
    return results

async def test_kubernetes_api_exposure(context=None, **kwargs) -> Dict[str, Any]:
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    results = {"test": "kubernetes_api_exposure", "target": target, "vulnerabilities": []}
    # Default Kubernetes API port
    try:
        url = f"https://{target}:6443/version"
        r = requests.get(url, timeout=3, verify=False)
        if r.status_code == 200 and 'gitVersion' in r.text:
            results["vulnerabilities"].append({
                "type": "Exposed Kubernetes API",
                "severity": "HIGH",
                "endpoint": url,
                "remediation": "Restrict access to Kubernetes API server with authentication and network policies"
            })
    except Exception:
        pass
    return results

logger.info("Container security tools module loaded")

