#!/usr/bin/env python3
import nmap
import json
from typing import Dict, List, Optional, Any, Tuple
import os
import logging
import subprocess
import shlex
from google.adk.tools import ToolContext # Import ToolContext
from bs4 import BeautifulSoup, Comment # Import BeautifulSoup and Comment
import re # For finding comments
from urllib.parse import urlparse # Import urlparse
# Import requests safely
try:
    import requests
except ImportError:
    requests = None # Handle case where requests is not installed
import time
import ipaddress # For IP validation
# Import our command executor instead of trying to use ShellCommandExecutor directly
from phantomrecon.executor_fix import run_command, run_command_detailed
# Import ADK's UnsafeLocalCodeExecutor for executing shell commands
from google.adk.code_executors import UnsafeLocalCodeExecutor
import aiohttp
import asyncio
from google.adk.tools import google_search_tool # Import ADK Google Search 
# Import global cache access
try:
    from google.adk.sessions.in_memory_session_service import _get_from_global_cache, _set_in_global_cache
except ImportError:
    # Define fallbacks if imports fail
    def _get_from_global_cache(key, default=None):
        print(f"[WARNING] Could not access global cache for key: {key}")
        return default

    def _set_in_global_cache(key, value):
        print(f"[WARNING] Could not store in global cache for key: {key}")
        return

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def _load_dummy_data() -> Dict:
    """Load dummy scan data for testing or when no target is specified."""
    dummy_file = os.path.join(os.path.dirname(__file__), 
                            '../data/dummy_scan_output.json')
    try:
        with open(dummy_file, 'r') as f:
            logger.info("Loading dummy scan data.")
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Dummy data file not found at {dummy_file}. Cannot provide dummy data.")
        # Return structure indicating error or empty scan
        return {"scan": {}, "error": f"Dummy data file not found at {dummy_file}"}
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding dummy data file {dummy_file}: {e}")
        return {"error": "Failed to load or decode dummy data."}
    except Exception as e:
        logger.error(f"Unexpected error loading dummy data: {e}")
        return {"error": f"Unexpected error loading dummy data: {e}"}

async def perform_nmap_scan(**kwargs) -> Dict[str, Any]:
    """
    Performs an Nmap scan on the target and returns structured results.
    Uses data from the session state 'initial_target' for scan target.
    
    Returns:
        Dict[str, Any]: Scan results.
    """
    # Extract context from kwargs
    context = kwargs.get('context')
    
    # Debug state
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        print(f"[DEBUG-NMAP] State Keys: {list(context.session.state.keys())}")
        print(f"[DEBUG-NMAP] initial_target: {context.session.state.get('initial_target')}")
        print(f"[DEBUG-NMAP] State Type: {type(context.session.state)}")
        
    # Check for direct target override from parallel function
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
        print(f"[NMAP] Using direct target override: {direct_target}")
        target = direct_target
    else:
        # Extract target from context
        target = None
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            target = context.session.state.get('initial_target')
    
    # If no target is found, return an error
    if not target:
        error_msg = "No target specified for Nmap scan. Please provide a target domain or IP address."
        logger.error(error_msg)
        results = {
            "error": error_msg,
            "scan": {}
        }
        return results
    
    logger.info(f"Starting Nmap scan for target: {target}")
    print(f"[NMAP] Starting scan on {target}...")
    
    # Try to detect if target is an IP or domain name
    is_ip = False
    try:
        # Just check if parseable as IP
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        # Assume it's a domain name
        pass
        
    # Construct basic scan command  
    scan_args = ['-sV', '-Pn', '--top-ports', '1000']
    
    command = ['nmap'] + scan_args + [target]
    command_str = ' '.join(command)
    print(f"[NMAP] Running command: {command_str}")
    
    stdout, stderr, returncode = await _run_command_async(command, timeout=90)
    
    if returncode != 0:
        logger.error(f"Nmap scan failed for {target}: {stderr}")
        print(f"[NMAP] Scan failed with error: {stderr}")
        results = {
            "error": f"Nmap scan failed with return code {returncode}",
            "stderr": stderr,
            "scan": {}
        }
    else:
        logger.info(f"Nmap scan completed for {target}")
        print(f"[NMAP] Scan completed, processing results...")
        # Process the output into structured format
        scan_results = _parse_nmap_output(stdout)
        results = {
            "scan": scan_results,
            "command": command_str
        }
        
    # Remove state-saving logic and just return results
    print(f"[NMAP] Scan completed, returning results")
    return results

# Note: analyze_vulnerabilities logic is removed from here.
# It's better placed within the planner agent/tool which interprets the scan results. 

# --- DNS and WHOIS Recon ---

async def perform_dns_recon(**kwargs) -> Dict[str, Any]:
    """
    Performs DNS reconnaissance on target from state using ADK's command execution.
    
    Returns:
        Dict[str, Any]: DNS recon results.
    """
    # Extract context from kwargs
    context = kwargs.get('context')
    
    # Debug state
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        print(f"[DEBUG-DNS] State Keys: {list(context.session.state.keys())}")
        print(f"[DEBUG-DNS] initial_target: {context.session.state.get('initial_target')}")
        print(f"[DEBUG-DNS] State Type: {type(context.session.state)}")
    
    # Check for direct target override from parallel function
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
        print(f"[DNS] Using direct target override: {direct_target}")
        target = direct_target
    else:
        # Extract target from context
        target = None
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            target = context.session.state.get('initial_target')
    
    # If no target is found, return an error
    if not target:
        error_msg = "No target specified for DNS reconnaissance. Please provide a target domain or IP address."
        logger.error(error_msg)
        results = {
            "error": error_msg,
            "dns_records": {},
            "subdomains": [],
            "ip_addresses": []
        }
        return results
    
    logger.info(f"Starting DNS recon for target: {target}")
    print(f"[DNS] Starting reconnaissance on {target}...")
    
    # Check if target is likely an IP or domain
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
        print(f"[DNS] Target is an IP address")
    except ValueError:
        # Must be a domain name
        print(f"[DNS] Target is a domain name")
        pass
    
    # Initialize results dictionary
    results = {
        "target": target,
        "dns_records": {},
        "subdomains": [],
        "ip_addresses": []
    }
    
    # Use dig commands for more reliable DNS lookups
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    
    # If target is an IP, try a reverse lookup first
    if is_ip:
        logger.info(f"Target is an IP address ({target}). Attempting reverse lookup.")
        print(f"[DNS] Attempting reverse lookup for IP {target}...")
        # Run reverse DNS lookup using dig
        command = ["dig", "-x", target, "+short"]
        stdout, stderr, returncode = await _run_command_async(command, timeout=10)
        
        if returncode == 0 and stdout:
            # Clean up the output (strip periods at end, etc.)
            reverse_domains = [line.strip().rstrip('.') for line in stdout.splitlines() if line.strip()]
            results["reverse_lookups"] = reverse_domains
            
            # If we got a domain, we can continue to look up other records
            if reverse_domains:
                logger.info(f"Found domains via reverse lookup: {reverse_domains}")
                print(f"[DNS] Found domains via reverse lookup: {reverse_domains}")
                # Use the first domain for additional lookups
                target = reverse_domains[0]
                is_ip = False
            else:
                logger.info(f"No reverse DNS records found for IP {target}")
                print(f"[DNS] No reverse DNS records found for IP {target}")
                results["dns_records"] = {"error": "No reverse DNS records found"}
                
        else:
            logger.warning(f"Reverse lookup failed for IP {target}: {stderr}")
            print(f"[DNS] Reverse lookup failed: {stderr}")
            results["dns_records"] = {"error": f"Reverse lookup failed: {stderr}"}
    
    # Only proceed with DNS lookups if we have a domain
    if not is_ip:
        print(f"[DNS] Looking up DNS records for {target}...")
        # Collect DNS records for each type
        for record_type in record_types:
            command = ["dig", target, record_type, "+short"]
            stdout, stderr, returncode = await _run_command_async(command, timeout=10)
            
            if returncode == 0:
                # Process the output based on record type
                records = [line.strip() for line in stdout.splitlines() if line.strip()]
                
                if records:
                    results["dns_records"][record_type] = records
                    print(f"[DNS] Found {len(records)} {record_type} records")
                    
                    # Extract IP addresses from A/AAAA records
                    if record_type in ["A", "AAAA"]:
                        results["ip_addresses"].extend(records)
            else:
                logger.warning(f"Failed to get {record_type} records for {target}: {stderr}")
                print(f"[DNS] Failed to get {record_type} records: {stderr}")
    
    # Look for common subdomains if target is a domain
    if not is_ip:
        print(f"[DNS] Searching for common subdomains...")
        await _find_subdomains(target, results)
        print(f"[DNS] Found {len(results.get('subdomains', []))} subdomains")
    
    # Remove state-saving logic and just return results
    print(f"[DNS] Reconnaissance completed, returning results")
    return results

async def _find_subdomains(target: str, results: Dict[str, Any], max_subdomains: int = 10) -> None:
    """
    Helper function to find subdomains using common prefixes.
    Updates the results dictionary in-place.
    """
    common_subdomains = ["www", "mail", "smtp", "pop", "imap", "blog", "shop", 
                         "dev", "api", "stage", "test", "admin", "secure"]
    
    found_subdomains = []
    
    for prefix in common_subdomains[:max_subdomains]:
        subdomain = f"{prefix}.{target}"
        command = ["dig", subdomain, "A", "+short"]
        stdout, stderr, returncode = await _run_command_async(command, timeout=5)
        
        if returncode == 0 and stdout.strip():
            # Found a valid subdomain with A record
            ips = [line.strip() for line in stdout.splitlines() if line.strip()]
            found_subdomains.append({"name": subdomain, "ip_addresses": ips})
            logger.debug(f"Found subdomain: {subdomain} -> {ips}")
    
    results["subdomains"] = found_subdomains

# --- Command Execution Helpers ---
async def _run_command_async(command: List[str], timeout: int = 60) -> Tuple[str, str, int]:
    """
    Helper function to run a shell command using our custom CommandExecutor.
    Returns stdout, stderr, returncode.
    """
    try:
        # Use the run_command function from executor_fix.py
        from phantomrecon.executor_fix import run_command
        return await run_command(command, timeout)
    except Exception as e:
        # Log the error and return empty output with error code
        logger.error(f"Error executing command {command}: {e}")
        return "", f"Error executing command: {e}", -1

async def _run_command_detailed_async(command: str, timeout: int = 15) -> Tuple[str, str, int]:
    """
    More detailed command runner with proper escaping & better error messages.
    Takes a command string instead of list.
    """
    try:
        # Use the run_command_detailed function from executor_fix.py
        from phantomrecon.executor_fix import run_command_detailed
        return await run_command_detailed(command, timeout)
    except Exception as e:
        # Log the error and return empty output with error code
        logger.error(f"Error executing command {command}: {e}")
        return "", f"Error executing command: {e}", -1

# --- Web Search and Analysis --- 

# Import ADK Google Search
async def perform_web_search(**kwargs) -> Dict[str, Any]:
    """
    Performs a search for the target using patterns since Google Search Tool is not reliable.
    
    Returns:
        Dict[str, Any]: Search results.
    """
    # Extract context from kwargs
    context = kwargs.get('context')
    
    # Debug state
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        print(f"[DEBUG-WEB] State Keys: {list(context.session.state.keys())}")
        print(f"[DEBUG-WEB] initial_target: {context.session.state.get('initial_target')}")
        print(f"[DEBUG-WEB] State Type: {type(context.session.state)}")
    
    # Check for direct target override from parallel function
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
        print(f"[WEB] Using direct target override: {direct_target}")
        target = direct_target
    else:
        # Extract target from session state
        target = None
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            target = context.session.state.get('initial_target')
    
    # If no target is found, return an error
    if not target:
        error_msg = "No target specified for web search. Please provide a target domain or IP address."
        logger.error(error_msg)
        results = {
            "error": error_msg,
            "search_query": "",
            "results": [],
            "status": "error"
        }
        return results
    
    logger.info(f"Starting web search for target: {target}")
    print(f"[WEB] Starting search for {target}...")
    
    # Create search query (for reference, we won't use it)
    search_query = f"site:{target}"
    logger.info(f"Using search query: {search_query}")
    print(f"[WEB] Using search query: {search_query}")
    
    # Don't even try GoogleSearchTool - go straight to pattern-based URLs
    print(f"[WEB] Using pattern-based URL generation for target: {target}")
    
    # Generate pattern-based URLs for reliability
    base_domain = target.split('.')[0] if '.' in target else target
    
    # Create more comprehensive list of potential URLs
    search_results = [
        f"https://{target}",
        f"https://www.{target}",
        f"https://{target}/about",
        f"https://{target}/contact",
        f"https://{target}/index.html",
        f"https://{target}/services",
        f"https://{target}/products",
        f"https://{target}/blog",
        f"https://{target}/news",
        f"https://en.wikipedia.org/wiki/{base_domain}"
    ]
    print(f"[WEB] Generated {len(search_results)} URLs using patterns")
    
    results = {
        "target": target,
        "search_query": search_query,
        "results": search_results,
        "status": "completed"
    }

    # Remove state-saving logic and just return results
    print(f"[WEB] Search completed, returning results")
    logger.info(f"Generated {len(search_results)} URLs for analysis")
    return results

# Removed ToolContext type hint for LlmAgent compatibility
async def analyze_web_content(**kwargs) -> Dict[str, Any]:
    """
    Analyzes web content from URLs found in web search results.
    
    Returns:
        Dict[str, Any]: Analysis results.
    """
    # Extract context from kwargs
    context = kwargs.get('context')
    
    # Check for direct target override (just for logging)
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
        print(f"[ANALYSIS] Working with target override: {direct_target}")
    
    # Debug state
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        print(f"[DEBUG-ANALYSIS] State Keys: {list(context.session.state.keys())}")
        print(f"[DEBUG-ANALYSIS] initial_target: {context.session.state.get('initial_target')}")
        print(f"[DEBUG-ANALYSIS] web_search_results: {context.session.state.get('web_search_results') is not None}")
        print(f"[DEBUG-ANALYSIS] State Type: {type(context.session.state)}")
    
    # Get search results from session state, if available
    search_results = None
    # First check if we were provided web_result directly in kwargs (from parallel recon)
    if 'web_result' in kwargs and isinstance(kwargs['web_result'], dict):
        print(f"[ANALYSIS] Using web search results provided directly in kwargs")
        search_results = kwargs['web_result']
    # Otherwise try to get it from session state
    elif context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        search_results = context.session.state.get('web_search_results', {})
    
    print(f"[ANALYSIS] Starting web content analysis...")
    
    # Initialize with empty result structure
    analysis_results = {
        "status": "error",
        "urls_analyzed": 0,
        "failed_urls": 0,
        "results": []
    }
    
    # Check if we have search results to work with
    if not search_results or not isinstance(search_results, dict):
        logger.warning("No valid web search results found in state for analysis")
        print(f"[ANALYSIS] Error: No valid web search results found")
        analysis_results["error"] = "No valid web search results found in state"
        
        return analysis_results
    
    # Extract URLs from search results
    urls = search_results.get('results', [])
    if not urls:
        logger.warning("No URLs found in web search results for analysis")
        print(f"[ANALYSIS] Error: No URLs found in web search results")
        analysis_results["error"] = "No URLs found in web search results"
        
        return analysis_results
    
    # Set up the HTTP session with appropriate headers
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    # Limit the number of URLs to check to prevent excessive requests
    max_urls = 5
    urls_to_check = urls[:max_urls]
    
    logger.info(f"Analyzing content from {len(urls_to_check)} URLs")
    print(f"[ANALYSIS] Analyzing content from {len(urls_to_check)} URLs")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # Create an analysis task for each URL
        tasks = []
        for url in urls_to_check:
            print(f"[ANALYSIS] Queuing analysis for: {url}")
            tasks.append(_analyze_single_url(session, url))
        
        # Run all tasks concurrently
        print(f"[ANALYSIS] Executing analysis tasks concurrently...")
        url_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process the results
        for result in url_results:
            if isinstance(result, Exception):
                # Handle any exceptions during analysis
                logger.error(f"Error analyzing URL: {result}")
                print(f"[ANALYSIS] Error analyzing URL: {result}")
                analysis_results["failed_urls"] += 1
            else:
                # Add successful result to our list
                if result:  # Only add if we got a valid result
                    analysis_results["results"].append(result)
                    analysis_results["urls_analyzed"] += 1
                    print(f"[ANALYSIS] Successfully analyzed: {result.get('url')}")
    
    # Update status if we successfully analyzed anything
    if analysis_results["urls_analyzed"] > 0:
        analysis_results["status"] = "completed"
    
    # Remove state-saving logic and just return results
    print(f"[ANALYSIS] Analysis completed, returning results")
    return analysis_results

async def _analyze_single_url(session, url):
    """
    Helper function to analyze a single URL asynchronously.
    
    Args:
        session: aiohttp ClientSession to use for requests
        url: URL to analyze
    
    Returns:
        Dict with analysis results or None if analysis failed
    """
    if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
        logger.warning(f"Skipping invalid URL format: {url}")
        return None
    
    logger.info(f"Analyzing content for: {url}")
    
    # Initialize result structure
    result = {
        "url": url,
        "status": "error",
        "title": None,
        "description": None,
        "headers": {},
        "technologies": [],
        "forms_found": 0,
        "external_links": 0,
        "internal_links": 0,
        "has_login_form": False,
        "content_summary": None
    }
    
    try:
        # Fetch the URL with a timeout
        async with session.get(url, timeout=10) as response:
            result["status_code"] = response.status
            
            # Store relevant headers
            for header_name, header_value in response.headers.items():
                result["headers"][header_name] = header_value
                
                # Simple technology detection from headers
                if header_name.lower() == 'server':
                    result["technologies"].append(f"Server: {header_value}")
                elif header_name.lower() == 'x-powered-by':
                    result["technologies"].append(f"Powered by: {header_value}")
            
            # Skip further processing for non-successful responses
            if response.status >= 400:
                result["error"] = f"HTTP error {response.status}"
                return result
                
            # Check content type
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
                result["error"] = f"Not HTML content: {content_type}"
                result["status"] = "skipped_non_html"
                return result
                
            # Read the content
            html = await response.text()
            
            # Parse with BeautifulSoup
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract basic page info
            if soup.title:
                result["title"] = soup.title.string.strip() if soup.title.string else None
                
            # Look for meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc and meta_desc.get('content'):
                result["description"] = meta_desc.get('content')
                
            # Count forms and check for login forms
            forms = soup.find_all('form')
            result["forms_found"] = len(forms)
            
            for form in forms:
                # Look for common login form indicators
                password_input = form.find('input', attrs={'type': 'password'})
                login_text = any(text in str(form).lower() for text in ['login', 'sign in', 'signin', 'log in'])
                
                if password_input or login_text:
                    result["has_login_form"] = True
                    break
            
            # Count links
            base_url = '/'.join(url.split('/')[:3])  # http(s)://domain.com
            for link in soup.find_all('a', href=True):
                href = link.get('href', '')
                if href.startswith('#') or not href:
                    continue
                
                if href.startswith('/'):
                    # Internal link with relative path
                    result["internal_links"] += 1
                elif href.startswith(base_url):
                    # Internal link with absolute path
                    result["internal_links"] += 1
                elif href.startswith(('http://', 'https://')):
                    # External link
                    result["external_links"] += 1
            
            # Basic technology detection
            if soup.find('script', src=lambda x: x and 'jquery' in x.lower()):
                result["technologies"].append("jQuery")
            if soup.find('script', src=lambda x: x and 'bootstrap' in x.lower()):
                result["technologies"].append("Bootstrap")
            if soup.find(lambda tag: tag.name == 'script' and 'React' in (tag.string or '')):
                result["technologies"].append("React")
            if soup.find(id='___gatsby') or soup.find(id='gatsby-focus-wrapper'):
                result["technologies"].append("Gatsby.js")
            if soup.find(attrs={"data-reactroot": True}):
                result["technologies"].append("React")
            if soup.find('meta', attrs={'name': 'generator', 'content': lambda x: x and 'WordPress' in x}):
                result["technologies"].append("WordPress")
            
            # Get a brief content summary (first paragraph or similar)
            first_p = soup.find('p')
            if first_p and first_p.text:
                content = first_p.text.strip()
                result["content_summary"] = content[:200] + "..." if len(content) > 200 else content
            
            # Update status to completed
            result["status"] = "completed"
            
    except asyncio.TimeoutError:
        result["error"] = "Request timed out"
        logger.warning(f"Request timed out for {url}")
    except Exception as e:
        result["error"] = f"Analysis error: {str(e)}"
        logger.error(f"Error analyzing {url}: {e}")
    
    return result

# --- Aggregation Function ---

# Removed ToolContext type hint for LlmAgent compatibility
def aggregate_recon_data(context, parallel_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combines results from parallel reconnaissance tasks (Nmap, DNS, Web Search, Web Analysis).
    Retrieves 'initial_target' from state for context.

    Args:
        context (ToolContext): ADK ToolContext.
        parallel_results (Dict[str, Any]): Dictionary containing results from parallel tasks.
            Expected keys: 'nmap_scan_results', 'dns_recon_results', 'web_search_results', 'web_analysis_results'

    Returns:
        Dict[str, Any]: Aggregated reconnaissance data (also stored in state['recon']).
    """
    logger.info("Aggregating reconnaissance data from parallel tasks.")

    # --- State Validation ---
    target = context.session.state.get('initial_target')
    if not target:
        logger.error("State validation failed: 'initial_target' missing in session state during aggregation.")
        aggregated_data = {"error": "Initial target missing in state.", **parallel_results}
        context.session.state['recon'] = aggregated_data # Store partial/error state
        return aggregated_data
    # --- End State Validation ---

    aggregated_data = {
        "target": target,
        # Use .get() with default empty dict/list to handle cases where a task might have failed
        "nmap_scan": parallel_results.get('nmap_scan_results', {'scan': {}, 'error': 'Nmap results missing'}),
        "dns_recon": parallel_results.get('dns_recon_results', {'error': 'DNS recon results missing'}),
        "web_search": parallel_results.get('web_search_results', {'urls': [], 'error': 'Web search results missing'}),
        "web_analysis": parallel_results.get('web_analysis_results', [{'error': 'Web analysis results missing'}])
    }

    # Basic validation/logging of results received
    for key, value in parallel_results.items():
        if isinstance(value, dict) and value.get('error'):
            logger.warning(f"Aggregation detected error in '{key}': {value['error']}")
        elif isinstance(value, list) and value and isinstance(value[0], dict) and value[0].get('error'):
             logger.warning(f"Aggregation detected error in first item of '{key}': {value[0]['error']}")
        elif not value:
             logger.warning(f"Aggregation received empty results for '{key}'.")
        else:
             logger.info(f"Successfully aggregated results for '{key}'.")

    # Store the final aggregated data in session state under the key 'recon'
    context.session.state['recon'] = aggregated_data
    logger.debug("Stored aggregated reconnaissance data in session state['recon'].")

    return aggregated_data

# --- Shared Helper for Web Analysis --- 
def _safe_request(url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
    """Make a safe HTTP request with error handling and user agent."""
    if requests is None:
        logger.error("The 'requests' library is required for web analysis but not installed.")
        return None
        
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'PhantomRecon-Analyzer/1.0' 
    })
    kwargs.setdefault('allow_redirects', True) # Follow redirects for analysis
    kwargs.setdefault('timeout', 15) 
    kwargs.setdefault('verify', False) # Insecure: Accept self-signed certs for testing
    if not kwargs.get('verify', True):
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except (ImportError, AttributeError):
            pass 

    try:
        logger.debug(f"Making {method} request to {url} for analysis")
        response = session.request(method, url, **kwargs)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.Timeout:
        logger.warning(f"Analysis request timed out for {url}")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"Analysis connection error for {url}: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        logger.warning(f"Analysis HTTP error for {url}: {e.response.status_code} {e.response.reason}")
        # Return the response object even on HTTP error, maybe analysis can still work?
        return e.response 
    except requests.exceptions.RequestException as e:
        logger.warning(f"Analysis request failed for {url}: {e}")
        return None

def _parse_nmap_output(nmap_output: str) -> Dict[str, Any]:
    """
    Parse raw nmap output text into a structured dictionary.
    
    Args:
        nmap_output (str): Raw nmap command output
        
    Returns:
        Dict[str, Any]: Structured scan results
    """
    results = {}
    current_host = None
    host_data = {}
    
    lines = nmap_output.split('\n')
    
    # First pass - get host info
    for line in lines:
        line = line.strip()
        
        # Identify host
        if line.startswith('Nmap scan report for '):
            if current_host and host_data:
                results[current_host] = host_data
            
            current_host = line.replace('Nmap scan report for ', '').strip()
            host_data = {
                'addresses': {},
                'hostnames': [],
                'tcp': {},
                'status': 'unknown'
            }
            
        # Host status
        elif line.startswith('Host is '):
            host_data['status'] = line.split('Host is ')[1].split()[0].lower()
            
        # IP/hostname correlation
        elif ' (' in line and ')' in line and 'scan report' in line:
            try:
                # Format like "Nmap scan report for example.com (93.184.216.34)"
                parts = line.split(' (')
                hostname = parts[0].replace('Nmap scan report for ', '').strip()
                ip = parts[1].replace(')', '').strip()
                host_data['hostnames'].append({'name': hostname, 'type': 'user'})
                host_data['addresses']['ipv4'] = ip
                # Update current_host to IP
                current_host = ip
            except:
                pass
                
        # Port information
        elif '/tcp' in line or '/udp' in line:
            try:
                if '/tcp' in line:
                    protocol = 'tcp'
                    port_parts = line.split('/tcp')
                else:
                    protocol = 'udp'
                    port_parts = line.split('/udp')
                    
                port_num = int(port_parts[0].strip())
                port_info = port_parts[1].strip().split(' ', 1)
                
                state = port_info[0].strip()
                service_info = {}
                
                if len(port_info) > 1:
                    service_desc = port_info[1].strip()
                    
                    # Extract service details
                    service_parts = service_desc.split(' ', 1)
                    service_name = service_parts[0].strip()
                    service_info['name'] = service_name
                    
                    if len(service_parts) > 1 and service_parts[1]:
                        extra_info = service_parts[1].strip()
                        if '(' in extra_info and ')' in extra_info:
                            # Extract version info
                            version_part = extra_info.split('(')[1].split(')')[0]
                            service_info['product'] = version_part.split()[0]
                            if len(version_part.split()) > 1:
                                service_info['version'] = ' '.join(version_part.split()[1:])
                        service_info['extrainfo'] = extra_info
                
                # Create port entry
                port_entry = {
                    'state': state,
                    'reason': 'syn-ack',  # Default, since raw output often doesn't show reason
                    'port': port_num,
                    **service_info
                }
                
                host_data[protocol][str(port_num)] = port_entry
            except Exception as e:
                logger.warning(f"Error parsing port line: {line} - {e}")
    
    # Add the last host
    if current_host and host_data:
        results[current_host] = host_data
        
    return results

def _ensure_serializable(data):
    """
    Ensures that all data is serializable (JSON-compatible) by converting
    complex objects to simple Python types.
    
    Args:
        data: Any Python object
        
    Returns:
        A JSON-serializable version of the data
    """
    if data is None:
        return None
    elif isinstance(data, (str, int, float, bool)):
        return data
    elif isinstance(data, dict):
        return {k: _ensure_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_ensure_serializable(item) for item in data]
    elif isinstance(data, tuple):
        return [_ensure_serializable(item) for item in data]
    elif isinstance(data, set):
        return [_ensure_serializable(item) for item in data]
    elif hasattr(data, '__dict__'):
        # Handle custom objects by converting to dict
        return _ensure_serializable(data.__dict__)
    else:
        # Convert anything else to string representation
        try:
            return str(data)
        except Exception as e:
            logger.warning(f"Could not convert {type(data)} to string: {e}")
            return f"<Non-serializable object of type {type(data).__name__}>"

def get_global_state(context=None) -> Dict[str, Any]:
    """
    Get state either from context.session.state or from global cache as fallback.
    
    This function handles the case where context is None by using the global cache.
    
    Args:
        context: The ToolContext object, which may be None
        
    Returns:
        Dict containing state values
    """
    state = {}
    
    # First try to get state from context if available
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        state = context.session.state
        print(f"[STATE] Using state from context with {len(state)} keys")
        return state
    
    # If context is not available, try to get state from emergency cache
    print(f"[STATE] Context not available, using global cache fallback")
    
    # Get important keys from global cache
    try:
        target = _get_from_global_cache('initial_target')
        if target:
            state['initial_target'] = target
            print(f"[STATE] Retrieved initial_target from global cache: {target}")
    except Exception as e:
        print(f"[WARNING] Error accessing global cache: {e}")
    
    # If state is still empty, try emergency file cache as last resort
    if not state:
        try:
            import pickle
            cache_file = 'recon_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    recon_data = pickle.load(f)
                    # Extract target from recon data if available
                    if 'target' in recon_data:
                        state['initial_target'] = recon_data['target']
                        print(f"[STATE] Retrieved initial_target from cache file: {state['initial_target']}")
                    # Store full recon data
                    state['recon'] = recon_data
                    print(f"[STATE] Loaded {len(recon_data)} keys from cache file")
        except Exception as e:
            print(f"[WARNING] Could not load from emergency cache file: {e}")
    
    return state

async def perform_parallel_recon(**kwargs) -> Dict[str, Any]:
    """
    Performs all reconnaissance methods (nmap, dns, web search) in parallel.
    This function is optimized for speed and fault tolerance - if one method fails,
    the others will still complete.
    
    Returns:
        Dict[str, Any]: Combined results from all recon methods
    """
    # Extract context from kwargs first, regardless of whether we have a direct target
    context = kwargs.get('context')
    
    # Enhanced state debugging - print all keys and their types
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        print(f"[DEBUG-PARALLEL] Full State Keys: {list(context.session.state.keys())}")
        print(f"[DEBUG-PARALLEL] Context type: {type(context)}")
        print(f"[DEBUG-PARALLEL] Session type: {type(context.session)}")
        print(f"[DEBUG-PARALLEL] State type: {type(context.session.state)}")
        
        # Print details about the initial_target key specifically
        if 'initial_target' in context.session.state:
            target_value = context.session.state.get('initial_target')
            print(f"[DEBUG-PARALLEL] initial_target exists with value: '{target_value}' (type: {type(target_value)})")
        else:
            print(f"[DEBUG-PARALLEL] initial_target key does not exist in state")
    
    # Get state using our helper function, which handles cases where context is None
    state = get_global_state(context)
    
    # THEN check for direct target override
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
        print(f"[PARALLEL] Using direct target override: {direct_target}")
        target = direct_target
    else:
        # Extract target from state, prioritizing initial_target
        target = state.get('initial_target')
        if target:
            logger.info(f"Found target in state[initial_target]: {target}")
            print(f"[STATE] Retrieved target from state: {target}")
        else:
            # Fall back to checking other potential state keys
            for potential_key in ['validation_result', 'user_input', 'target']:
                potential_target = state.get(potential_key)
                if potential_target and isinstance(potential_target, str):
                    target = potential_target
                    print(f"[STATE] Found target in {potential_key}: {target}")
                    # Store it in initial_target for consistency
                    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
                        context.session.state['initial_target'] = target
                    # Also store in global cache
                    try:
                        _set_in_global_cache('initial_target', target)
                        print(f"[STATE] Stored initial_target in global cache: {target}")
                    except Exception as e:
                        print(f"[WARNING] Error storing in global cache: {e}")
                    break
            
            if not target:
                logger.warning("Could not find target in any state key")
                print("[STATE] Could not find target in any state key")
    
    # If no target is found, return an error
    if not target:
        error_msg = "No target specified. Please provide a target domain or IP address."
        logger.error(error_msg)
        print(f"[ERROR] {error_msg}")
        
        # Return an error result instead of using a default target
        results = {
            "status": "error",
            "error": error_msg,
            "timestamp": time.time()
        }
        
        # Store this error in session state
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            try:
                # Apply serialization fix to error result
                serializable_results = _ensure_serializable(results)
                context.session.state['recon'] = serializable_results
                print(f"[STATE] Stored error in recon state")
            except Exception as e:
                logger.warning(f"Failed to store error in state: {e}")
        
        # Also store in global cache regardless of context
        try:
            serializable_results = _ensure_serializable(results)
            _set_in_global_cache('recon', serializable_results)
            print(f"[STATE] Stored error in global cache")
        except Exception as e:
            logger.warning(f"Failed to store error in global cache: {e}")
        
        return results
    
    # Ensure the target is passed to individual recon functions
    print(f"\n[INFO] Starting parallel reconnaissance for {target}...")
    
    # Create modified kwargs with explicit target
    modified_kwargs = kwargs.copy()
    modified_kwargs['direct_target_override'] = target
    
    # Create tasks for all recon methods with the enriched kwargs
    print("[INFO] Launching NMAP scan, DNS reconnaissance, and web search in parallel...")
    tasks = [
        asyncio.create_task(perform_nmap_scan(**modified_kwargs)),
        asyncio.create_task(perform_dns_recon(**modified_kwargs)),
        asyncio.create_task(perform_web_search(**modified_kwargs))
    ]
    
    # Run all tasks concurrently and handle exceptions
    results = {
        "target": target,
        "timestamp": time.time(),
        "status": "partial"  # Default to partial in case some methods fail
    }
    
    # Use gather with return_exceptions=True to prevent one failure from stopping everything
    print("[INFO] Waiting for all reconnaissance tasks to complete...")
    nmap_result, dns_result, web_result = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process nmap results
    if isinstance(nmap_result, Exception):
        logger.error(f"Nmap scan failed: {nmap_result}")
        print(f"[ERROR] Nmap scan failed: {nmap_result}")
        results["nmap_scan"] = {"error": f"Scan failed: {str(nmap_result)}"}
    else:
        print(f"[SUCCESS] Nmap scan completed successfully")
        results["nmap_scan"] = nmap_result
    
    # Process DNS results
    if isinstance(dns_result, Exception):
        logger.error(f"DNS recon failed: {dns_result}")
        print(f"[ERROR] DNS reconnaissance failed: {dns_result}")
        results["dns_recon"] = {"error": f"DNS recon failed: {str(dns_result)}"}
    else:
        print(f"[SUCCESS] DNS reconnaissance completed successfully")
        results["dns_recon"] = dns_result
    
    # Process web search results
    if isinstance(web_result, Exception):
        logger.error(f"Web search failed: {web_result}")
        print(f"[ERROR] Web search failed: {web_result}")
        results["web_search"] = {"error": f"Web search failed: {str(web_result)}"}
    else:
        print(f"[SUCCESS] Web search completed successfully")
        results["web_search"] = web_result
        
        # If web search succeeded, also trigger web content analysis
        # Pass context to analyze_web_content
        try:
            print("[INFO] Starting web content analysis...")
            # Create a new kwargs with the web_result directly included
            web_analysis_kwargs = modified_kwargs.copy()
            web_analysis_kwargs['web_result'] = web_result
            web_analysis = await analyze_web_content(**web_analysis_kwargs)
            print("[SUCCESS] Web content analysis completed successfully")
            results["web_analysis"] = web_analysis
        except Exception as e:
            logger.error(f"Web content analysis failed: {e}")
            print(f"[ERROR] Web content analysis failed: {e}")
            results["web_analysis"] = {"error": f"Analysis failed: {str(e)}"}
    
    # Update overall status
    success_count = sum(1 for r in [nmap_result, dns_result, web_result] 
                         if not isinstance(r, Exception))
    
    if success_count == 3:
        results["status"] = "completed"
        print(f"[INFO] All reconnaissance tasks completed successfully")
    elif success_count == 0:
        results["status"] = "failed"
        print(f"[WARNING] All reconnaissance tasks failed")
    else:
        print(f"[INFO] {success_count}/3 reconnaissance tasks completed successfully")
    
    # Store results in session state if possible
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        try:
            # Convert all results to serializable format before storing
            print(f"[STATE] Ensuring all recon data is serializable before storing in state")
            
            # Store all individual results in session state
            if not isinstance(nmap_result, Exception):
                serializable_nmap = _ensure_serializable(nmap_result)
                context.session.state['nmap_scan_results'] = serializable_nmap
                print(f"[STATE] Stored nmap_scan_results in session state")
            
            if not isinstance(dns_result, Exception):
                serializable_dns = _ensure_serializable(dns_result)
                context.session.state['dns_recon_results'] = serializable_dns
                print(f"[STATE] Stored dns_recon_results in session state")
            
            if not isinstance(web_result, Exception):
                serializable_web = _ensure_serializable(web_result)
                context.session.state['web_search_results'] = serializable_web
                print(f"[STATE] Stored web_search_results in session state")
            
            # Store web analysis results if available
            if "web_analysis" in results and (not isinstance(results["web_analysis"], dict) or not results["web_analysis"].get("error")):
                serializable_web_analysis = _ensure_serializable(results["web_analysis"])
                context.session.state['web_content_analysis'] = serializable_web_analysis
                print(f"[STATE] Stored web_content_analysis in session state")
            
            # Store the combined results in 'recon'
            serializable_results = _ensure_serializable(results)
            context.session.state['recon'] = serializable_results
            logger.debug("Stored combined recon results in session state.")
            print("[INFO] Combined reconnaissance results stored in session state")
            
            # List all keys in session state for debugging
            print(f"[STATE] Final state keys: {list(context.session.state.keys())}")
            print(f"[STATE] State type: {type(context.session.state)}")
            
            # Add extra validation to ensure data was actually stored
            if 'recon' in context.session.state:
                print(f"[VERIFY] Successfully verified 'recon' is in state")
            else:
                print(f"[VERIFY] 'recon' is NOT in state after attempted save!")
                
        except Exception as e:
            # Add detailed logging for the exception
            logger.exception(f"Detailed error storing state:") 
            print(f"[WARNING] Error storing in session state: {e}")
            # Try global cache as fallback
            try:
                serializable_results = _ensure_serializable(results)
                _set_in_global_cache('recon', serializable_results)
                print(f"[STATE] Stored recon in global cache")
                
                # Also store individual components
                if not isinstance(nmap_result, Exception):
                    _set_in_global_cache('nmap_scan_results', _ensure_serializable(nmap_result))
                if not isinstance(dns_result, Exception):
                    _set_in_global_cache('dns_recon_results', _ensure_serializable(dns_result))
                if not isinstance(web_result, Exception):
                    _set_in_global_cache('web_search_results', _ensure_serializable(web_result))
                    
                print(f"[STATE] Stored individual components in global cache")
            except Exception as e2:
                print(f"[WARNING] Could not store in global cache: {e2}")
                # Emergency file-based fallback
                try:
                    import pickle
                    import os
                    cache_file = 'recon_cache.pkl'
                    with open(cache_file, 'wb') as f:
                        pickle.dump(results, f)
                    print(f"[INFO] Saved recon results to emergency cache file: {cache_file}")
                except Exception as e3:
                    print(f"[WARNING] Could not save to emergency cache file: {e3}")
    else:
        logger.warning("Could not access session state to store combined recon results.")
        print("[WARNING] Could not store reconnaissance results in session state")
        
        # Always store in global cache as the primary fallback
        try:
            serializable_results = _ensure_serializable(results)
            _set_in_global_cache('recon', serializable_results)
            print(f"[STATE] Stored recon in global cache")
            
            # Also store individual components
            if not isinstance(nmap_result, Exception):
                _set_in_global_cache('nmap_scan_results', _ensure_serializable(nmap_result))
            if not isinstance(dns_result, Exception):
                _set_in_global_cache('dns_recon_results', _ensure_serializable(dns_result))
            if not isinstance(web_result, Exception):
                _set_in_global_cache('web_search_results', _ensure_serializable(web_result))
                
            print(f"[STATE] Stored individual components in global cache")
        except Exception as e:
            print(f"[WARNING] Could not store in global cache: {e}")
            # Emergency file-based fallback as last resort
            try:
                import pickle
                import os
                cache_file = 'recon_cache.pkl'
                with open(cache_file, 'wb') as f:
                    pickle.dump(results, f)
                print(f"[INFO] Saved recon results to emergency cache file: {cache_file}")
            except Exception as e2:
                print(f"[WARNING] Could not save to emergency cache file: {e2}")
    
    return results
