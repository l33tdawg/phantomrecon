#!/usr/bin/env python3
"""
Comprehensive Web Security Testing Tools
State-of-the-art web application security assessment capabilities
"""
import requests
import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote
import logging
from bs4 import BeautifulSoup
import asyncio
from phantomrecon.executor_fix import run_command_detailed
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

logger = logging.getLogger(__name__)

# ==============================================================================
# XSS TESTING TOOLS
# ==============================================================================

XSS_PAYLOADS = [
    # Basic XSS
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    # Event handlers
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    # Encoded payloads
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    # DOM XSS
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>",
    # Filter bypass
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    # Advanced bypasses
    "<iframe src=javascript:alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
]

async def test_xss_comprehensive(context=None, **kwargs) -> Dict[str, Any]:
    """
    Comprehensive XSS testing across multiple vectors and encoding types.
    Tests: Reflected XSS, Stored XSS, DOM-based XSS
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "comprehensive_xss",
        "target": target,
        "vulnerabilities": [],
        "tested_vectors": 0,
        "findings_count": 0
    }
    
    # Build URLs to test
    base_url = f"https://{target}" if not target.startswith('http') else target
    test_urls = [
        base_url,
        f"{base_url}/search",
        f"{base_url}/index.php",
        f"{base_url}/login",
    ]
    
    for url in test_urls:
        for payload in XSS_PAYLOADS:
            try:
                # Test in URL parameters
                test_url = f"{url}?q={quote(payload)}&search={quote(payload)}"
                response = requests.get(test_url, timeout=5, verify=False, allow_redirects=True)
                
                if payload in response.text:
                    results["vulnerabilities"].append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "url": url,
                        "payload": payload,
                        "location": "URL parameter",
                        "evidence": f"Payload reflected in response",
                        "remediation": "Implement output encoding and Content Security Policy"
                    })
                    results["findings_count"] += 1
                
                results["tested_vectors"] += 1
                
            except Exception as e:
                logger.debug(f"XSS test error for {url}: {e}")
                continue
            
            await asyncio.sleep(0.1)  # Rate limiting
    
    return results

async def test_dom_xss(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for DOM-based XSS vulnerabilities by analyzing JavaScript code.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "dom_xss",
        "target": target,
        "vulnerabilities": [],
        "dangerous_patterns": []
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    try:
        response = requests.get(base_url, timeout=10, verify=False)
        
        # Dangerous JavaScript patterns
        dangerous_patterns = [
            r'document\.write\(',
            r'document\.writeln\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'eval\(',
            r'setTimeout\(',
            r'setInterval\(',
            r'Function\(',
            r'location\.href\s*=',
            r'document\.location',
        ]
        
        for pattern in dangerous_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                results["dangerous_patterns"].append({
                    "pattern": pattern,
                    "count": len(matches),
                    "risk": "Potential DOM XSS sink",
                })
        
        if results["dangerous_patterns"]:
            results["vulnerabilities"].append({
                "type": "Potential DOM XSS",
                "severity": "MEDIUM",
                "url": base_url,
                "details": f"Found {len(results['dangerous_patterns'])} dangerous JavaScript patterns",
                "remediation": "Review JavaScript code for unsafe DOM manipulation"
            })
    
    except Exception as e:
        logger.error(f"DOM XSS test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# CSRF TESTING TOOLS
# ==============================================================================

async def test_csrf_protection(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for CSRF protection mechanisms (tokens, SameSite cookies, etc.)
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "csrf_protection",
        "target": target,
        "vulnerabilities": [],
        "protections_found": []
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    try:
        session = requests.Session()
        response = session.get(base_url, timeout=10, verify=False)
        
        # Check for CSRF tokens
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').upper()
            
            if form_method == 'POST':
                # Look for CSRF token fields
                token_found = False
                token_patterns = ['csrf', 'token', '_token', 'authenticity_token', '__RequestVerificationToken']
                
                inputs = form.find_all('input', type=['hidden', 'text'])
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if any(pattern in name for pattern in token_patterns):
                        token_found = True
                        results["protections_found"].append({
                            "type": "CSRF Token",
                            "form": form_action,
                            "field": inp.get('name')
                        })
                        break
                
                if not token_found:
                    results["vulnerabilities"].append({
                        "type": "Missing CSRF Protection",
                        "severity": "MEDIUM",
                        "form": form_action,
                        "method": form_method,
                        "remediation": "Implement CSRF tokens and SameSite cookie attribute"
                    })
        
        # Check cookie security
        for cookie in response.cookies:
            cookie_secure = cookie.secure
            cookie_httponly = cookie.has_nonstandard_attr('HttpOnly')
            cookie_samesite = cookie.get_nonstandard_attr('SameSite')
            
            if not cookie_samesite:
                results["vulnerabilities"].append({
                    "type": "Missing SameSite Cookie Attribute",
                    "severity": "LOW",
                    "cookie": cookie.name,
                    "remediation": "Set SameSite=Strict or SameSite=Lax on cookies"
                })
    
    except Exception as e:
        logger.error(f"CSRF test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# SSRF TESTING TOOLS
# ==============================================================================

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "file:///etc/passwd",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "dict://localhost:11211/stats",
    "gopher://localhost:9000/_GET",
]

async def test_ssrf_vulnerabilities(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for Server-Side Request Forgery vulnerabilities.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "ssrf_vulnerabilities",
        "target": target,
        "vulnerabilities": [],
        "tested_payloads": 0
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Common SSRF-prone parameters
    test_params = ['url', 'uri', 'path', 'dest', 'redirect', 'return', 'next', 'file', 'document', 'folder', 'root', 'pg', 'style']
    
    for param in test_params:
        for payload in SSRF_PAYLOADS:
            try:
                test_url = f"{base_url}?{param}={quote(payload)}"
                response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # Check for signs of SSRF
                ssrf_indicators = [
                    "root:x:",  # /etc/passwd content
                    "localhost",
                    "127.0.0.1",
                    "169.254.169.254",
                    "metadata",
                    "ami-id",
                    "instance-id",
                ]
                
                for indicator in ssrf_indicators:
                    if indicator in response.text.lower():
                        results["vulnerabilities"].append({
                            "type": "SSRF Vulnerability",
                            "severity": "CRITICAL",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Response contains '{indicator}'",
                            "remediation": "Implement URL whitelist and disable unnecessary protocols"
                        })
                        break
                
                results["tested_payloads"] += 1
                
            except Exception as e:
                logger.debug(f"SSRF test error: {e}")
                continue
            
            await asyncio.sleep(0.1)
    
    return results

# ==============================================================================
# PATH TRAVERSAL TESTING TOOLS
# ==============================================================================

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",  # Double encoding
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
]

async def test_path_traversal(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for path/directory traversal vulnerabilities.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "path_traversal",
        "target": target,
        "vulnerabilities": [],
        "tested_payloads": 0
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Common file-related parameters
    test_params = ['file', 'path', 'document', 'folder', 'root', 'pg', 'style', 'pdf', 'template', 'php', 'cat', 'dir', 'action', 'board', 'date', 'detail', 'download', 'prefix', 'include', 'inc', 'locate', 'show', 'doc', 'site', 'type', 'view', 'content', 'layout', 'mod', 'conf']
    
    for param in test_params:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            try:
                test_url = f"{base_url}?{param}={payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                # Check for file content indicators
                traversal_indicators = [
                    "root:x:0:0",  # /etc/passwd
                    "daemon:x:",
                    "[boot loader]",  # Windows hosts file
                    "# localhost",
                    "127.0.0.1",
                ]
                
                for indicator in traversal_indicators:
                    if indicator in response.text:
                        results["vulnerabilities"].append({
                            "type": "Path Traversal",
                            "severity": "HIGH",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Response contains '{indicator}'",
                            "remediation": "Implement input validation and use absolute paths"
                        })
                        break
                
                results["tested_payloads"] += 1
                
            except Exception as e:
                logger.debug(f"Path traversal test error: {e}")
                continue
            
            await asyncio.sleep(0.1)
    
    return results

# ==============================================================================
# OPEN REDIRECT TESTING TOOLS
# ==============================================================================

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "//google.com",
    "@evil.com",
]

async def test_open_redirect(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for open redirect vulnerabilities.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "open_redirect",
        "target": target,
        "vulnerabilities": [],
        "tested_payloads": 0
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Common redirect parameters
    redirect_params = ['url', 'redirect', 'return', 'next', 'redir', 'ret', 'r', 'page', 'goto', 'destination', 'dest', 'uri', 'continue', 'window', 'to']
    
    for param in redirect_params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            try:
                test_url = f"{base_url}?{param}={quote(payload)}"
                response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # Check for redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location or 'google.com' in location:
                        results["vulnerabilities"].append({
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "redirect_location": location,
                            "remediation": "Implement redirect URL whitelist"
                        })
                
                results["tested_payloads"] += 1
                
            except Exception as e:
                logger.debug(f"Open redirect test error: {e}")
                continue
            
            await asyncio.sleep(0.1)
    
    return results

# ==============================================================================
# SECURITY HEADERS TESTING
# ==============================================================================

async def test_security_headers(context=None, **kwargs) -> Dict[str, Any]:
    """
    Analyzes HTTP security headers.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "security_headers",
        "target": target,
        "headers_present": [],
        "headers_missing": [],
        "vulnerabilities": []
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    try:
        response = requests.get(base_url, timeout=10, verify=False)
        headers = response.headers
        
        # Required security headers
        security_headers = {
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000',
            'Content-Security-Policy': 'Restrictive CSP',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'no-referrer or strict-origin',
            'Permissions-Policy': 'Restrictive permissions'
        }
        
        for header, recommended in security_headers.items():
            if header in headers:
                results["headers_present"].append({
                    "header": header,
                    "value": headers[header],
                    "status": "PRESENT"
                })
            else:
                results["headers_missing"].append({
                    "header": header,
                    "recommended": recommended
                })
                results["vulnerabilities"].append({
                    "type": f"Missing Security Header: {header}",
                    "severity": "LOW" if header in ['X-XSS-Protection', 'Referrer-Policy'] else "MEDIUM",
                    "remediation": f"Add {header}: {recommended}"
                })
    
    except Exception as e:
        logger.error(f"Security headers test error: {e}")
        results["error"] = str(e)
    
    return results

logger.info("Web security tools module loaded")

# ==============================================================================
# HEADLESS BROWSER CRAWLING AND DIRECTORY LISTING DETECTION
# ==============================================================================

def _init_headless_chrome() -> Optional[webdriver.Chrome]:
    if not SELENIUM_AVAILABLE:
        return None
    options = ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    try:
        driver = webdriver.Chrome(options=options)
        return driver
    except Exception:
        return None

async def headless_crawl_site(context=None, **kwargs) -> Dict[str, Any]:
    """
    Crawl the target website using a headless browser to discover links, forms, and structure.
    Args:
      start_path: optional path to start from
      max_pages: int (default 200)
      same_origin_only: bool (default True)
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    if not SELENIUM_AVAILABLE:
        return {"error": "Selenium not available. Please install selenium and a compatible driver."}

    base_url = f"https://{target}" if not target.startswith('http') else target
    start_path = kwargs.get('start_path') or '/'
    max_pages: int = int(kwargs.get('max_pages') or 200)
    same_origin_only: bool = bool(kwargs.get('same_origin_only') if kwargs.get('same_origin_only') is not None else True)

    driver = _init_headless_chrome()
    if driver is None:
        return {"error": "Failed to initialize headless Chrome driver"}

    origin = urlparse(base_url).netloc
    start_url = urljoin(base_url, start_path)

    discovered: Set[str] = set()
    to_visit: List[str] = [start_url]
    pages: List[Dict[str, Any]] = []

    try:
        while to_visit and len(discovered) < max_pages:
            url = to_visit.pop(0)
            if url in discovered:
                continue
            try:
                driver.get(url)
            except Exception:
                discovered.add(url)
                continue

            discovered.add(url)
            page_source = driver.page_source or ""
            status = 200  # Selenium does not expose status easily; assume success if loaded

            links = set()
            try:
                for a in driver.find_elements(By.TAG_NAME, 'a'):
                    href = a.get_attribute('href')
                    if not href:
                        continue
                    parsed = urlparse(href)
                    if same_origin_only and parsed.netloc and parsed.netloc != origin:
                        continue
                    if parsed.scheme in ['http', 'https']:
                        links.add(href)
            except Exception:
                pass

            forms = []
            try:
                for form in driver.find_elements(By.TAG_NAME, 'form'):
                    forms.append({
                        "action": form.get_attribute('action'),
                        "method": (form.get_attribute('method') or 'GET').upper(),
                    })
            except Exception:
                pass

            pages.append({
                "url": url,
                "status": status,
                "num_links": len(links),
                "num_forms": len(forms),
                "forms": forms,
            })

            for link in links:
                if link not in discovered and len(discovered) + len(to_visit) < max_pages:
                    to_visit.append(link)

        site_map = {
            "test": "headless_crawl_site",
            "target": target,
            "pages_crawled": len(pages),
            "pages": pages,
        }
        if context and hasattr(context, 'session'):
            context.session.state['web_crawl'] = site_map
        return site_map
    finally:
        try:
            driver.quit()
        except Exception:
            pass

async def detect_directory_listing(context=None, **kwargs) -> Dict[str, Any]:
    """
    Use headless browser to identify directory listing pages (Apache/Nginx style 'Index of /').
    If a crawl was performed, use those pages; otherwise check root and common directories.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    if not SELENIUM_AVAILABLE:
        return {"error": "Selenium not available. Please install selenium and a compatible driver."}

    base_url = f"https://{target}" if not target.startswith('http') else target
    common_dirs = kwargs.get('paths') or [
        '/', '/static/', '/assets/', '/images/', '/uploads/', '/backup/', '/files/', '/logs/', '/.git/', '/.svn/'
    ]

    driver = _init_headless_chrome()
    if driver is None:
        return {"error": "Failed to initialize headless Chrome driver"}

    findings: List[Dict[str, Any]] = []
    checked: Set[str] = set()

    # Use crawl data if present
    crawl = None
    if context and hasattr(context, 'session'):
        crawl = context.session.state.get('web_crawl')
    urls_to_check: List[str] = []
    if crawl and crawl.get('pages'):
        for p in crawl['pages']:
            u = p.get('url')
            if u and u.endswith('/'):
                urls_to_check.append(u)
    if not urls_to_check:
        urls_to_check = [urljoin(base_url, p) for p in common_dirs]

    try:
        for url in urls_to_check:
            if url in checked:
                continue
            checked.add(url)
            try:
                driver.get(url)
                html = driver.page_source or ""
            except Exception:
                continue

            lower = html.lower()
            if ('index of /' in lower) or ('parent directory' in lower):
                severity = 'HIGH' if any(s in url for s in ['/uploads/', '/backup/', '/logs/', '/files/']) else 'MEDIUM'
                findings.append({
                    "type": "Directory Listing Enabled",
                    "severity": severity,
                    "url": url,
                    "evidence": "Page contains 'Index of /' or 'Parent Directory'",
                    "remediation": "Disable autoindex/listing and add index files or restrict access",
                })

        result = {"test": "detect_directory_listing", "target": target, "vulnerabilities": findings}
        return result
    finally:
        try:
            driver.quit()
        except Exception:
            pass

