#!/usr/bin/env python3
import nmap
import json
from typing import Dict, List, Optional, Any, Tuple
import os
import logging
import subprocess
import shlex
try:
    from google.adk.tools import ToolContext  # Import ToolContext when available
except Exception:
    class ToolContext:  # Fallback placeholder for local smoke tests
        pass
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
# ADK now provides GoogleSearchTool internally to Gemini; no direct import/usage here
# Remove custom global cache fallbacks; rely on context.session.state throughout
# Import rich for better parallel execution visualization
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.spinner import Spinner
from rich.text import Text
from rich import box

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

console = Console()

class ParallelTaskTracker:
    """Tracks and visualizes parallel task execution in real-time."""
    
    def __init__(self, target: str):
        self.target = target
        self.tasks = {
            'nmap': {'status': 'pending', 'start_time': None, 'end_time': None, 'result': None},
            'dns': {'status': 'pending', 'start_time': None, 'end_time': None, 'result': None},
        }
        
    def start_task(self, task_name: str):
        """Mark a task as started."""
        if task_name in self.tasks:
            self.tasks[task_name]['status'] = 'running'
            self.tasks[task_name]['start_time'] = time.time()
    
    def complete_task(self, task_name: str, success: bool = True, result: Any = None):
        """Mark a task as completed."""
        if task_name in self.tasks:
            self.tasks[task_name]['status'] = 'complete' if success else 'failed'
            self.tasks[task_name]['end_time'] = time.time()
            self.tasks[task_name]['result'] = result
    
    def get_elapsed(self, task_name: str) -> str:
        """Get elapsed time for a task."""
        task = self.tasks.get(task_name)
        if not task or not task['start_time']:
            return "0.0s"
        
        end = task['end_time'] if task['end_time'] else time.time()
        elapsed = end - task['start_time']
        return f"{elapsed:.1f}s"
    
    def generate_table(self) -> Table:
        """Generate a rich Table showing current task status."""
        table = Table(title=f"[bold cyan]Parallel Reconnaissance: {self.target}[/bold cyan]", 
                     box=box.ROUNDED, 
                     show_header=True,
                     header_style="bold magenta")
        
        table.add_column("Agent", style="cyan", width=15)
        table.add_column("Status", width=15)
        table.add_column("Elapsed", justify="right", width=10)
        table.add_column("Details", width=40)
        
        for task_name, task_info in self.tasks.items():
            # Status with color and icon
            status = task_info['status']
            if status == 'pending':
                status_text = Text("⏳ Pending", style="dim")
            elif status == 'running':
                status_text = Text("⚡ Running", style="bold yellow")
            elif status == 'complete':
                status_text = Text("✓ Complete", style="bold green")
            else:  # failed
                status_text = Text("✗ Failed", style="bold red")
            
            # Get details based on result
            details = ""
            if task_info['result'] and isinstance(task_info['result'], dict):
                if task_name == 'nmap':
                    scan_data = task_info['result'].get('scan', {})
                    host_count = len(scan_data)
                    if host_count > 0:
                        details = f"{host_count} host(s) scanned"
                elif task_name == 'dns':
                    dns_records = task_info['result'].get('dns_records', {})
                    subdomain_count = len(task_info['result'].get('subdomains', []))
                    record_types = len(dns_records)
                    details = f"{record_types} record types, {subdomain_count} subdomain(s)"
            
            if task_info['status'] == 'failed':
                error = task_info['result'].get('error', 'Unknown error') if isinstance(task_info['result'], dict) else 'Task failed'
                details = f"Error: {error[:35]}..."
            
            # Display task name
            display_name = {
                'nmap': 'NMAP Scan',
                'dns': 'DNS Recon',
            }.get(task_name, task_name.upper())
            
            table.add_row(
                display_name,
                status_text,
                self.get_elapsed(task_name),
                details
            )
        
        return table

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
        
    # Check for direct target override from parallel function
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
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
    
    # Try to detect if target is an IP or domain name
    is_ip = False
    try:
        # Just check if parseable as IP
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        # Assume it's a domain name
        pass
        
    # Construct scan command from environment
    env_top_ports = os.getenv('NMAP_TOP_PORTS', '1000').strip()
    env_extra_args = os.getenv('NMAP_ARGS', '').strip()
    env_timeout = int(os.getenv('NMAP_TIMEOUT', '90'))
    env_disable = os.getenv('NMAP_DISABLE', '0').strip() in ('1', 'true', 'True')

    if env_disable:
        logger.warning("Nmap disabled via NMAP_DISABLE env var")
        return {"scan": {}, "warning": "Nmap disabled via env", "command": None}

    # Base args
    scan_args = ['-sV', '-Pn', '--top-ports', env_top_ports]
    # Extra args
    if env_extra_args:
        try:
            scan_args.extend(shlex.split(env_extra_args))
        except Exception:
            scan_args.extend(env_extra_args.split())
    
    command = ['nmap'] + scan_args + [target]
    command_str = ' '.join(command)
    
    stdout, stderr, returncode = await _run_command_async(command, timeout=env_timeout)
    
    if returncode != 0:
        logger.error(f"Nmap scan failed for {target}: {stderr}")
        results = {
            "error": f"Nmap scan failed with return code {returncode}",
            "stderr": stderr,
            "scan": {}
        }
    else:
        logger.info(f"Nmap scan completed for {target}")
        # Process the output into structured format
        scan_results = _parse_nmap_output(stdout)
        results = {
            "scan": scan_results,
            "command": command_str
        }
        
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
    
    # Check for direct target override from parallel function
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
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
    
    # Check if target is likely an IP or domain
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        # Must be a domain name
        pass
    
    # Initialize results dictionary (flat keys) and also build a compatibility 'dns' view later
    results = {
        "target": target,
        "dns_records": {},
        "subdomains": [],
        "ip_addresses": [],
        "errors": []
    }
    
    # Use dig commands for more reliable DNS lookups
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    
    # If target is an IP, try a reverse lookup first
    if is_ip:
        logger.info(f"Target is an IP address ({target}). Attempting reverse lookup.")
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
                # Use the first domain for additional lookups
                target = reverse_domains[0]
                is_ip = False
            else:
                logger.info(f"No reverse DNS records found for IP {target}")
                results["errors"].append("No reverse DNS records found")
        else:
            logger.warning(f"Reverse lookup failed for IP {target}: {stderr}")
            results["errors"].append(f"Reverse lookup failed: {stderr}")
    
    # Only proceed with DNS lookups if we have a domain
    if not is_ip:
        # Collect DNS records for each type
        for record_type in record_types:
            command = ["dig", target, record_type, "+short"]
            stdout, stderr, returncode = await _run_command_async(command, timeout=10)
            
            if returncode == 0:
                # Process the output based on record type
                records = [line.strip() for line in stdout.splitlines() if line.strip()]
                
                if records:
                    results["dns_records"][record_type] = records
                    
                    # Extract IP addresses from A/AAAA records
                    if record_type in ["A", "AAAA"]:
                        results["ip_addresses"].extend(records)
            else:
                logger.warning(f"Failed to get {record_type} records for {target}: {stderr}")
                if stderr:
                    results["errors"].append(f"dig {record_type} failed: {stderr.strip()}")
    
    # Look for common subdomains if target is a domain
    if not is_ip:
        await _find_subdomains(target, results)
    
    # Attempt WHOIS lookup (best effort)
    whois_output = None
    try:
        # Prefer 'whois' command if available
        whois_cmd = ["whois", target]
        stdout, stderr, returncode = await _run_command_async(whois_cmd, timeout=10)
        if returncode == 0 and stdout:
            # Don't store full text in results to avoid massive reports; keep as string for status
            whois_output = stdout.strip()
        elif returncode != 0 and stderr:
            whois_output = f"Failed whois: {stderr.strip()}"
    except Exception as e:
        whois_output = f"Failed whois: {str(e)}"

    if whois_output:
        results["whois"] = whois_output

    # Build compatibility view under 'dns.dig' expected by report builder
    results["dns"] = {
        "dig": results.get("dns_records", {}),
    }

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

# Define our own search function that doesn't depend on the ADK's GoogleSearchTool
# Remove legacy fallback search; search is either handled by ADK or omitted

# Import ADK Google Search
# Remove web search function; ADK search is internal and not directly used by tools

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
    
    # Get search results or seed URLs if missing
    search_results = None
    seeded_urls: List[str] = []
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        state = context.session.state
        search_results = state.get('web_search_results', {})
        # Seed URLs when no search results
        if not search_results:
            target = state.get('initial_target')
            if isinstance(target, str) and target:
                bases = [
                    f"http://{target}",
                    f"https://{target}",
                    f"http://www.{target}",
                    f"https://www.{target}"
                ]
                # Include discovered subdomains
                dns = state.get('dns_recon_results') or {}
                for sub in (dns.get('subdomains') or []):
                    name = sub.get('name') if isinstance(sub, dict) else None
                    if isinstance(name, str):
                        bases.extend([f"http://{name}", f"https://{name}"])
                common_paths = [
                    '/', '/login', '/admin', '/robots.txt', '/.git/HEAD', '/.env', '/wp-login.php'
                ]
                for base in bases:
                    for p in common_paths:
                        seeded_urls.append(base.rstrip('/') + p)
            if seeded_urls:
                print(f"[ANALYSIS] Seeded {len(seeded_urls)} URLs for analysis (no search results)")
    
    print(f"[ANALYSIS] Starting web content analysis...")
    
    # Initialize with empty result structure
    analysis_results = {
        "status": "error",
        "urls_analyzed": 0,
        "failed_urls": 0,
        "results": []
    }
    
    # Build URL list from search results or seeds
    urls: List[str] = []
    if isinstance(search_results, dict):
        urls = search_results.get('results', []) or []
    if not urls and seeded_urls:
        urls = seeded_urls
    if not urls:
        logger.warning("No URLs available for analysis (no search results and no seeds)")
        print(f"[ANALYSIS] Error: No URLs available for analysis")
        analysis_results["error"] = "No URLs available for analysis"
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
    
    # No fallback: ADK sessions provide state; if absent, return empty
    return state

# Removed perform_web_search wrapper; not needed with updated ADK

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
    
    # Get state using our helper function, which handles cases where context is None
    state = get_global_state(context)
    
    # THEN check for direct target override
    direct_target = kwargs.get('direct_target_override')
    if direct_target:
        target = direct_target
    else:
        # Extract target from state, prioritizing initial_target
        target = state.get('initial_target')
        if target:
            logger.info(f"Found target in state[initial_target]: {target}")
        else:
            # Fall back to checking other potential state keys
            for potential_key in ['validation_result', 'user_input', 'target']:
                potential_target = state.get(potential_key)
                if potential_target and isinstance(potential_target, str):
                    target = potential_target
                    # Store it in initial_target for consistency
                    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
                        context.session.state['initial_target'] = target
                    # Also store in global cache
                    try:
                        _set_in_global_cache('initial_target', target)
                    except Exception as e:
                        pass
                    break
    
    # If no target is found, return an error
    if not target:
        error_msg = "No target specified. Please provide a target domain or IP address."
        logger.error(error_msg)
        
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
            except Exception as e:
                logger.warning(f"Failed to store error in state: {e}")
        
        # Also store in global cache regardless of context
        try:
            serializable_results = _ensure_serializable(results)
            _set_in_global_cache('recon', serializable_results)
        except Exception as e:
            logger.warning(f"Failed to store error in global cache: {e}")
        
        return results
    
    # Create modified kwargs with explicit target
    modified_kwargs = kwargs.copy()
    modified_kwargs['direct_target_override'] = target
    
    # Initialize the task tracker
    tracker = ParallelTaskTracker(target)
    
    # Create wrapper tasks that update the tracker
    async def nmap_task():
        tracker.start_task('nmap')
        result = await perform_nmap_scan(**modified_kwargs)
        success = not isinstance(result, Exception) and not result.get('error')
        tracker.complete_task('nmap', success=success, result=result)
        return result
    
    async def dns_task():
        tracker.start_task('dns')
        result = await perform_dns_recon(**modified_kwargs)
        success = not isinstance(result, Exception) and not result.get('error')
        tracker.complete_task('dns', success=success, result=result)
        return result
    
    # Run tasks with live display
    with Live(tracker.generate_table(), refresh_per_second=4, console=console) as live:
        # Create tasks
        tasks = [
            asyncio.create_task(nmap_task()),
            asyncio.create_task(dns_task()),
        ]
        
        # Update display while tasks are running
        while not all(task.done() for task in tasks):
            live.update(tracker.generate_table())
            await asyncio.sleep(0.25)
        
        # Wait for all tasks to complete
        nmap_result, dns_result = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Final update to show completion
        live.update(tracker.generate_table())
    
    # Set up the results structure
    results = {
        "target": target,
        "timestamp": time.time(),
        "status": "partial"  # Default to partial in case some methods fail
    }
    
    # Process nmap results
    if isinstance(nmap_result, Exception):
        logger.error(f"Nmap scan failed: {nmap_result}")
        results["nmap_scan"] = {"error": f"Scan failed: {str(nmap_result)}"}
    else:
        results["nmap_scan"] = nmap_result
    
    # Process DNS results
    if isinstance(dns_result, Exception):
        logger.error(f"DNS recon failed: {dns_result}")
        results["dns_recon"] = {"error": f"DNS recon failed: {str(dns_result)}"}
    else:
        results["dns_recon"] = dns_result
    
    # Optionally run web content analysis if URLs are already present in state
    try:
        web_analysis = await analyze_web_content(**modified_kwargs)
        if web_analysis and isinstance(web_analysis, dict) and web_analysis.get('status') != 'error':
            results["web_analysis"] = web_analysis
    except Exception as e:
        logger.error(f"Web content analysis failed: {e}")
        results["web_analysis"] = {"error": f"Analysis failed: {str(e)}"}
    
    # Update overall status
    success_count = sum(1 for r in [nmap_result, dns_result]
                        if not isinstance(r, Exception))
    
    if success_count == 2:
        results["status"] = "completed"
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
            
            # No web_result handling here
            
            # Store web analysis results if available
            if "web_analysis" in results and (not isinstance(results["web_analysis"], dict) or not results["web_analysis"].get("error")):
                serializable_web_analysis = _ensure_serializable(results["web_analysis"])
                context.session.state['web_content_analysis'] = serializable_web_analysis
                print(f"[STATE] Stored web_content_analysis in session state")
            
            # Store the combined results in 'recon'
            serializable_results = _ensure_serializable(results)
            context.session.state['recon'] = serializable_results
            # Also store under 'aggregated_recon_data' for report compatibility
            context.session.state['aggregated_recon_data'] = serializable_results
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
            # Log but don't attempt deprecated global cache/file fallbacks
            logger.exception("Error storing combined recon in session state")
            print(f"[WARNING] Error storing in session state: {e}")
    else:
        logger.warning("Could not access session state to store combined recon results.")
        print("[WARNING] Could not store reconnaissance results in session state")
    
    return results
