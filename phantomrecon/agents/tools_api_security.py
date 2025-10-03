#!/usr/bin/env python3
"""
Comprehensive API Security Testing Tools
REST API, GraphQL, WebSocket, and API Authentication testing
"""
import requests
import json
try:
    import jwt  # PyJWT
    JWT_AVAILABLE = True
except Exception:
    jwt = None
    JWT_AVAILABLE = False
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import logging
import base64
import hashlib
import hmac
import asyncio

logger = logging.getLogger(__name__)

# ==============================================================================
# REST API SECURITY TESTING
# ==============================================================================

async def test_api_authentication(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests REST API authentication mechanisms for weaknesses.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "api_authentication",
        "target": target,
        "vulnerabilities": [],
        "findings": []
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Common API endpoints
    api_endpoints = [
        '/api/v1/',
        '/api/v2/',
        '/api/',
        '/rest/',
        '/graphql',
        '/api/users',
        '/api/admin',
        '/api/config',
    ]
    
    for endpoint in api_endpoints:
        try:
            url = urljoin(base_url, endpoint)
            
            # Test 1: No authentication
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                results["vulnerabilities"].append({
                    "type": "Unauthenticated API Access",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "remediation": "Implement proper authentication for API endpoints"
                })
            
            # Test 2: Weak API keys
            weak_keys = ['test', 'demo', 'api_key', '12345', 'admin', 'key']
            for key in weak_keys:
                headers = {'X-API-Key': key, 'Authorization': f'Bearer {key}'}
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                if response.status_code == 200:
                    results["vulnerabilities"].append({
                        "type": "Weak API Key Accepted",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "weak_key": key,
                        "remediation": "Implement strong API key generation and validation"
                    })
            
            # Test 3: HTTP Methods testing
            for method in ['PUT', 'DELETE', 'PATCH']:
                response = requests.request(method, url, timeout=5, verify=False)
                if response.status_code not in [401, 403, 405]:
                    results["vulnerabilities"].append({
                        "type": "Unrestricted HTTP Method",
                        "severity": "MEDIUM",
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": response.status_code,
                        "remediation": "Restrict HTTP methods and implement proper authorization"
                    })
            
        except Exception as e:
            logger.debug(f"API auth test error for {endpoint}: {e}")
            continue
        
        await asyncio.sleep(0.1)
    
    return results

async def test_api_authorization(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for broken object level authorization (BOLA/IDOR) in APIs.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "api_authorization",
        "target": target,
        "vulnerabilities": [],
        "idor_tests": 0
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Common IDOR-prone endpoints
    test_patterns = [
        '/api/users/{id}',
        '/api/profile/{id}',
        '/api/documents/{id}',
        '/api/orders/{id}',
        '/api/accounts/{id}',
        '/api/messages/{id}',
    ]
    
    # Test with different IDs
    test_ids = ['1', '2', '100', 'admin', 'test']
    
    for pattern in test_patterns:
        for test_id in test_ids:
            try:
                endpoint = pattern.replace('{id}', test_id)
                url = urljoin(base_url, endpoint)
                
                response = requests.get(url, timeout=5, verify=False)
                
                # If we get data without authentication, it's IDOR
                if response.status_code == 200 and len(response.content) > 0:
                    results["vulnerabilities"].append({
                        "type": "Broken Object Level Authorization (IDOR)",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "tested_id": test_id,
                        "evidence": "Accessed object without proper authorization",
                        "remediation": "Implement object-level authorization checks"
                    })
                
                results["idor_tests"] += 1
                
            except Exception as e:
                logger.debug(f"IDOR test error: {e}")
                continue
            
            await asyncio.sleep(0.1)
    
    return results

# ==============================================================================
# JWT SECURITY TESTING
# ==============================================================================

async def test_jwt_vulnerabilities(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests JWT tokens for common vulnerabilities.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    jwt_token = kwargs.get('jwt_token')
    
    results = {
        "test": "jwt_vulnerabilities",
        "target": target,
        "vulnerabilities": [],
        "jwt_analysis": {}
    }
    
    if not JWT_AVAILABLE:
        return {"error": "PyJWT not available. Install 'pyjwt' to run JWT tests."}
    
    if not jwt_token:
        return {"error": "No JWT token provided for testing"}
    
    try:
        # Decode without verification to analyze
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        header = jwt.get_unverified_header(jwt_token)
        
        results["jwt_analysis"] = {
            "header": header,
            "payload": decoded,
            "algorithm": header.get('alg')
        }
        
        # Test 1: Algorithm confusion (alg: none)
        try:
            none_token = jwt.encode(decoded, key="", algorithm="none")
            results["vulnerabilities"].append({
                "type": "Algorithm Confusion (none)",
                "severity": "CRITICAL",
                "test_token": none_token,
                "remediation": "Reject tokens with alg=none"
            })
        except:
            pass
        
        # Test 2: Weak signature
        weak_secrets = ['secret', 'password', '123456', 'jwt', 'key']
        for secret in weak_secrets:
            try:
                jwt.decode(jwt_token, secret, algorithms=["HS256"])
                results["vulnerabilities"].append({
                    "type": "Weak JWT Secret",
                    "severity": "CRITICAL",
                    "weak_secret": secret,
                    "remediation": "Use strong, random secrets (256+ bits)"
                })
                break
            except:
                continue
        
        # Test 3: No expiration
        if 'exp' not in decoded:
            results["vulnerabilities"].append({
                "type": "Missing JWT Expiration",
                "severity": "MEDIUM",
                "remediation": "Always set exp claim in JWT tokens"
            })
        
        # Test 4: Sensitive data in payload
        sensitive_keys = ['password', 'secret', 'ssn', 'credit_card', 'api_key']
        for key in sensitive_keys:
            if key in str(decoded).lower():
                results["vulnerabilities"].append({
                    "type": "Sensitive Data in JWT",
                    "severity": "HIGH",
                    "sensitive_field": key,
                    "remediation": "Never store sensitive data in JWT payload"
                })
    
    except Exception as e:
        logger.error(f"JWT test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# GRAPHQL SECURITY TESTING
# ==============================================================================

GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
"""

async def test_graphql_security(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests GraphQL endpoints for security issues.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "graphql_security",
        "target": target,
        "vulnerabilities": [],
        "schema_info": {}
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    graphql_url = urljoin(base_url, '/graphql')
    
    try:
        # Test 1: Introspection enabled
        response = requests.post(
            graphql_url,
            json={'query': GRAPHQL_INTROSPECTION_QUERY},
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            if '__schema' in str(data):
                results["vulnerabilities"].append({
                    "type": "GraphQL Introspection Enabled",
                    "severity": "MEDIUM",
                    "endpoint": graphql_url,
                    "remediation": "Disable introspection in production"
                })
                results["schema_info"] = data
        
        # Test 2: Query depth limit
        deep_query = """
        {
          user { 
            posts { 
              comments { 
                author { 
                  posts { 
                    comments { 
                      author { 
                        posts { id }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        response = requests.post(
            graphql_url,
            json={'query': deep_query},
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            results["vulnerabilities"].append({
                "type": "No Query Depth Limit",
                "severity": "HIGH",
                "endpoint": graphql_url,
                "remediation": "Implement query depth limiting to prevent DoS"
            })
        
        # Test 3: Batch query attacks
        batch_query = [
            {'query': '{ users { id } }'},
            {'query': '{ users { id } }'},
            {'query': '{ users { id } }'},
        ] * 100  # 300 queries
        
        response = requests.post(
            graphql_url,
            json=batch_query,
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            results["vulnerabilities"].append({
                "type": "Unrestricted Batch Queries",
                "severity": "HIGH",
                "endpoint": graphql_url,
                "remediation": "Limit batch query size to prevent DoS"
            })
    
    except Exception as e:
        logger.error(f"GraphQL test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# API RATE LIMITING TESTING
# ==============================================================================

async def test_api_rate_limiting(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for API rate limiting and DoS protection.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "api_rate_limiting",
        "target": target,
        "vulnerabilities": [],
        "requests_sent": 0,
        "rate_limit_detected": False
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    test_url = urljoin(base_url, '/api/')
    
    try:
        # Send rapid requests
        for i in range(100):
            response = requests.get(test_url, timeout=2, verify=False)
            results["requests_sent"] += 1
            
            # Check for rate limit response
            if response.status_code == 429:  # Too Many Requests
                results["rate_limit_detected"] = True
                results["rate_limit_at_request"] = i + 1
                break
            
            # Check rate limit headers
            if 'X-RateLimit-Limit' in response.headers or 'RateLimit-Limit' in response.headers:
                results["rate_limit_detected"] = True
                results["rate_limit_headers"] = dict(response.headers)
                break
        
        if not results["rate_limit_detected"]:
            results["vulnerabilities"].append({
                "type": "No Rate Limiting",
                "severity": "MEDIUM",
                "endpoint": test_url,
                "requests_completed": results["requests_sent"],
                "remediation": "Implement rate limiting to prevent DoS attacks"
            })
    
    except Exception as e:
        logger.error(f"Rate limit test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# API VERSIONING TESTING
# ==============================================================================

async def test_api_versioning(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for insecure API versioning practices.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "api_versioning",
        "target": target,
        "versions_found": [],
        "vulnerabilities": []
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Common API version patterns
    version_patterns = [
        '/api/v1/',
        '/api/v2/',
        '/api/v3/',
        '/v1/api/',
        '/v2/api/',
        '/api/1.0/',
        '/api/2.0/',
    ]
    
    for version in version_patterns:
        try:
            url = urljoin(base_url, version)
            response = requests.get(url, timeout=5, verify=False)
            
            if response.status_code not in [404, 403]:
                results["versions_found"].append({
                    "version": version,
                    "status_code": response.status_code,
                    "accessible": True
                })
                
                # Check if old version has vulnerabilities
                if 'v1' in version or '1.0' in version:
                    results["vulnerabilities"].append({
                        "type": "Old API Version Still Accessible",
                        "severity": "MEDIUM",
                        "version": version,
                        "remediation": "Deprecate and remove old API versions"
                    })
        
        except Exception as e:
            logger.debug(f"Version test error: {e}")
            continue
        
        await asyncio.sleep(0.1)
    
    return results

logger.info("API security tools module loaded")

