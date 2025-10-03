#!/usr/bin/env python3
"""
CMS Security Testing Tools
WordPress, Joomla, Drupal quick checks using HTTP requests and CLI tools if available
"""
import requests
from typing import Dict, Any
import subprocess
import json
import logging

logger = logging.getLogger(__name__)

def _run(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return "", str(e), 1
    return p.stdout, p.stderr, p.returncode

async def detect_cms(context=None, **kwargs) -> Dict[str, Any]:
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    base_url = f"https://{target}" if not target.startswith('http') else target
    results = {"test": "detect_cms", "target": target, "cms": None, "indicators": []}
    try:
        r = requests.get(base_url, timeout=10, verify=False)
        server = r.headers.get('Server', '')
        if 'wordpress' in r.text.lower() or 'wp-content' in r.text:
            results["cms"] = "WordPress"; results["indicators"].append('wp-content')
        if 'Joomla' in r.text or 'joomla' in server.lower():
            results["cms"] = results.get("cms") or "Joomla"; results["indicators"].append('Joomla')
        if 'Drupal.settings' in r.text or 'drupal' in server.lower():
            results["cms"] = results.get("cms") or "Drupal"; results["indicators"].append('Drupal.settings')
    except Exception as e:
        results["error"] = str(e)
    return results

async def wordpress_quick_audit(context=None, **kwargs) -> Dict[str, Any]:
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    base_url = f"https://{target}" if not target.startswith('http') else target
    results = {"test": "wordpress_quick_audit", "target": target, "vulnerabilities": [], "info": {}}
    try:
        # Check readme and sensitive files
        for path in ['/readme.html', '/wp-config.php.bak', '/wp-admin/install.php']:
            try:
                r = requests.get(base_url + path, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 0:
                    results["vulnerabilities"].append({"type": "Exposed WordPress File", "path": path, "severity": "MEDIUM"})
            except:
                pass
        # Try wpscan if present
        out, err, rc = _run(['wpscan', '--url', base_url, '--no-update', '--disable-tls-checks', '--format', 'json'], timeout=120)
        if rc == 0 and out:
            try:
                wp = json.loads(out)
                results["info"]["version"] = wp.get('version', {})
                vulns = []
                for plugin, meta in (wp.get('plugins', {}) or {}).items():
                    if meta and meta.get('vulnerabilities'):
                        for v in meta['vulnerabilities']:
                            vulns.append({"plugin": plugin, "title": v.get('title'), "fixed_in": v.get('fixed_in')})
                if vulns:
                    results["vulnerabilities"].append({"type": "Vulnerable Plugins", "details": vulns, "severity": "HIGH"})
            except Exception as e:
                results["info"]["wpscan_parse_error"] = str(e)
        else:
            results["info"]["wpscan"] = "not available or failed"
    except Exception as e:
        results["error"] = str(e)
    return results

async def drupal_quick_audit(context=None, **kwargs) -> Dict[str, Any]:
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    base_url = f"https://{target}" if not target.startswith('http') else target
    results = {"test": "drupal_quick_audit", "target": target, "vulnerabilities": []}
    try:
        for path in ['/CHANGELOG.txt', '/core/CHANGELOG.txt']:
            try:
                r = requests.get(base_url + path, timeout=5, verify=False)
                if r.status_code == 200 and 'Drupal' in r.text:
                    results["vulnerabilities"].append({"type": "Exposed Drupal Changelog", "path": path, "severity": "LOW"})
            except:
                pass
    except Exception as e:
        results["error"] = str(e)
    return results

async def joomla_quick_audit(context=None, **kwargs) -> Dict[str, Any]:
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    base_url = f"https://{target}" if not target.startswith('http') else target
    results = {"test": "joomla_quick_audit", "target": target, "vulnerabilities": []}
    try:
        for path in ['/README.txt', '/configuration.php-dist']:
            try:
                r = requests.get(base_url + path, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 0:
                    results["vulnerabilities"].append({"type": "Exposed Joomla File", "path": path, "severity": "LOW"})
            except:
                pass
    except Exception as e:
        results["error"] = str(e)
    return results

logger.info("CMS security tools module loaded")

