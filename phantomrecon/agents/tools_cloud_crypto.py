#!/usr/bin/env python3
"""
Cloud Security and Cryptography Testing Tools
AWS, Azure, GCP misconfigurations and TLS/SSL testing
"""
import requests
import ssl
import socket
from typing import Dict, List, Any, Optional
import logging
import asyncio
from urllib.parse import urlparse
import subprocess
import json

logger = logging.getLogger(__name__)

# ==============================================================================
# CLOUD MISCONFIGURATION TESTING (AWS, Azure, GCP)
# ==============================================================================

AWS_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
]

AZURE_METADATA_URLS = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
]

GCP_METADATA_URLS = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
]

async def test_cloud_metadata_exposure(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for exposed cloud metadata endpoints (SSRF to metadata services).
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "cloud_metadata_exposure",
        "target": target,
        "vulnerabilities": [],
        "metadata_accessible": False
    }
    
    base_url = f"https://{target}" if not target.startswith('http') else target
    
    # Test if application can be tricked into accessing metadata
    test_params = ['url', 'uri', 'redirect', 'path', 'dest']
    
    all_metadata_urls = AWS_METADATA_URLS + AZURE_METADATA_URLS + GCP_METADATA_URLS
    
    for param in test_params:
        for metadata_url in all_metadata_urls:
            try:
                test_url = f"{base_url}?{param}={metadata_url}"
                response = requests.get(test_url, timeout=3, verify=False)
                
                # Check for metadata indicators
                metadata_indicators = [
                    'ami-id',
                    'instance-id',
                    'InstanceId',
                    'projectId',
                    'accessToken',
                    'privateIpAddress',
                ]
                
                for indicator in metadata_indicators:
                    if indicator in response.text:
                        cloud_provider = "AWS" if "169.254.169.254" in metadata_url else \
                                       "Azure" if "metadata/instance" in metadata_url else "GCP"
                        
                        results["vulnerabilities"].append({
                            "type": "Cloud Metadata Exposure",
                            "severity": "CRITICAL",
                            "cloud_provider": cloud_provider,
                            "endpoint": test_url,
                            "metadata_url": metadata_url,
                            "evidence": f"Found indicator: {indicator}",
                            "remediation": "Block access to metadata endpoints and implement SSRF protection"
                        })
                        results["metadata_accessible"] = True
                        break
            
            except Exception as e:
                logger.debug(f"Metadata test error: {e}")
                continue
            
            await asyncio.sleep(0.1)
    
    return results

async def test_s3_bucket_permissions(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for misconfigured S3 buckets (public read/write).
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    bucket_name = kwargs.get('bucket_name', target)
    
    results = {
        "test": "s3_bucket_permissions",
        "bucket": bucket_name,
        "vulnerabilities": [],
        "permissions": {}
    }
    
    if not bucket_name:
        return {"error": "No S3 bucket specified"}
    
    try:
        # Test public read
        s3_url = f"https://{bucket_name}.s3.amazonaws.com/"
        response = requests.get(s3_url, timeout=10)
        
        if response.status_code == 200:
            results["permissions"]["public_read"] = True
            results["vulnerabilities"].append({
                "type": "Publicly Readable S3 Bucket",
                "severity": "HIGH",
                "bucket": bucket_name,
                "url": s3_url,
                "remediation": "Restrict S3 bucket access and enable encryption"
            })
        
        # Test public write
        test_file = "test-permission-check.txt"
        try:
            upload_response = requests.put(
                f"{s3_url}{test_file}",
                data="test",
                timeout=10
            )
            if upload_response.status_code in [200, 201]:
                results["permissions"]["public_write"] = True
                results["vulnerabilities"].append({
                    "type": "Publicly Writable S3 Bucket",
                    "severity": "CRITICAL",
                    "bucket": bucket_name,
                    "url": s3_url,
                    "remediation": "Immediately restrict write access and audit bucket"
                })
        except:
            pass
    
    except Exception as e:
        logger.error(f"S3 bucket test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# TLS/SSL SECURITY TESTING
# ==============================================================================

async def test_tls_configuration(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests TLS/SSL configuration for weak ciphers, protocols, and certificate issues.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "tls_configuration",
        "target": target,
        "vulnerabilities": [],
        "certificate_info": {},
        "supported_protocols": [],
        "cipher_suites": []
    }
    
    # Parse hostname and port
    if ':' in target:
        hostname, port = target.split(':')
        port = int(port)
    else:
        hostname = target
        port = 443
    
    try:
        # Test SSL/TLS protocols
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Should fail for modern Python
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
        }
        
        for protocol_name, protocol in protocols.items():
            if protocol is None:
                continue
            
            try:
                context_ssl = ssl.SSLContext(protocol)
                context_ssl.check_hostname = False
                context_ssl.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results["supported_protocols"].append(protocol_name)
                        
                        # Flag weak protocols
                        if protocol_name in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                            results["vulnerabilities"].append({
                                "type": f"Weak Protocol Supported: {protocol_name}",
                                "severity": "HIGH",
                                "protocol": protocol_name,
                                "remediation": "Disable weak protocols, use TLS 1.2+ only"
                            })
            except:
                continue
        
        # Get certificate information
        try:
            context_ssl = ssl.create_default_context()
            context_ssl.check_hostname = False
            context_ssl.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    results["certificate_info"] = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter'),
                    }
                    
                    results["cipher_suites"].append({
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    })
                    
                    # Check for weak ciphers
                    weak_cipher_indicators = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                    if any(indicator in cipher[0] for indicator in weak_cipher_indicators):
                        results["vulnerabilities"].append({
                            "type": "Weak Cipher Suite",
                            "severity": "HIGH",
                            "cipher": cipher[0],
                            "remediation": "Disable weak cipher suites"
                        })
        except Exception as e:
            logger.debug(f"Certificate test error: {e}")
    
    except Exception as e:
        logger.error(f"TLS test error: {e}")
        results["error"] = str(e)
    
    # Try using testssl.sh if available
    try:
        testssl_result = subprocess.run(
            ['testssl.sh', '--quiet', '--json', hostname],
            capture_output=True,
            timeout=30,
            text=True
        )
        if testssl_result.returncode == 0:
            results["testssl_output"] = json.loads(testssl_result.stdout)
    except:
        pass  # testssl.sh not available
    
    return results

# ==============================================================================
# CRYPTOGRAPHIC IMPLEMENTATION TESTING
# ==============================================================================

async def test_password_hashing(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for weak password hashing (if password hashes are leaked/accessible).
    """
    password_hashes = kwargs.get('password_hashes', [])
    
    results = {
        "test": "password_hashing",
        "vulnerabilities": [],
        "hash_analysis": []
    }
    
    if not password_hashes:
        return {"info": "No password hashes provided for analysis"}
    
    for hash_value in password_hashes:
        hash_info = {"hash": hash_value, "detected_algorithm": "unknown"}
        
        # Detect hash type by length and format
        if len(hash_value) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
            hash_info["detected_algorithm"] = "MD5"
            results["vulnerabilities"].append({
                "type": "Weak Hash Algorithm: MD5",
                "severity": "CRITICAL",
                "hash": hash_value[:16] + "...",
                "remediation": "Use bcrypt, scrypt, or Argon2 for password hashing"
            })
        
        elif len(hash_value) == 40:
            hash_info["detected_algorithm"] = "SHA1"
            results["vulnerabilities"].append({
                "type": "Weak Hash Algorithm: SHA1",
                "severity": "HIGH",
                "hash": hash_value[:16] + "...",
                "remediation": "Use bcrypt, scrypt, or Argon2 for password hashing"
            })
        
        elif hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
            hash_info["detected_algorithm"] = "bcrypt"
            hash_info["secure"] = True
        
        elif hash_value.startswith('$argon2'):
            hash_info["detected_algorithm"] = "Argon2"
            hash_info["secure"] = True
        
        results["hash_analysis"].append(hash_info)
    
    return results

async def test_encryption_at_rest(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests for data encryption at rest (database encryption, etc.).
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    
    results = {
        "test": "encryption_at_rest",
        "target": target,
        "findings": [],
        "vulnerabilities": []
    }
    
    # This would require access to database/storage layer
    # For now, check for common indicators in responses
    
    base_url = f"https://{target}" if target and not target.startswith('http') else target
    
    try:
        if base_url:
            response = requests.get(base_url, timeout=10, verify=False)
            
            # Check for plaintext sensitive data in responses
            sensitive_patterns = [
                r'\b\d{16}\b',  # Credit card
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+',  # Passwords in config
            ]
            
            import re
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    results["vulnerabilities"].append({
                        "type": "Potential Unencrypted Sensitive Data",
                        "severity": "MEDIUM",
                        "pattern": pattern,
                        "matches_found": len(matches),
                        "remediation": "Encrypt sensitive data at rest and in transit"
                    })
    
    except Exception as e:
        logger.error(f"Encryption test error: {e}")
        results["error"] = str(e)
    
    return results

# ==============================================================================
# CERTIFICATE VALIDATION TESTING
# ==============================================================================

async def test_certificate_validation(context=None, **kwargs) -> Dict[str, Any]:
    """
    Tests SSL certificate validation and common issues.
    """
    target = kwargs.get('target') or (context.session.state.get('initial_target') if context else None)
    if not target:
        return {"error": "No target specified"}
    
    results = {
        "test": "certificate_validation",
        "target": target,
        "vulnerabilities": [],
        "certificate_chain": []
    }
    
    hostname = target.split(':')[0] if ':' in target else target
    port = int(target.split(':')[1]) if ':' in target else 443
    
    try:
        # Test with verification
        context_ssl = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results["certificate_valid"] = True
        except ssl.SSLError as e:
            results["vulnerabilities"].append({
                "type": "Certificate Validation Failed",
                "severity": "HIGH",
                "error": str(e),
                "remediation": "Fix certificate issues (expired, self-signed, wrong domain)"
            })
        
        # Test for self-signed certificate
        context_ssl_nocheck = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context_ssl_nocheck.check_hostname = False
        context_ssl_nocheck.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context_ssl_nocheck.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check if issuer == subject (self-signed)
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                if subject == issuer:
                    results["vulnerabilities"].append({
                        "type": "Self-Signed Certificate",
                        "severity": "MEDIUM",
                        "subject": subject,
                        "remediation": "Use a certificate from a trusted CA"
                    })
    
    except Exception as e:
        logger.error(f"Certificate validation error: {e}")
        results["error"] = str(e)
    
    return results

logger.info("Cloud security and cryptography tools module loaded")

