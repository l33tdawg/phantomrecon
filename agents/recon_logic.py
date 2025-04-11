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

def perform_nmap_scan(context: ToolContext) -> Dict:
    """
    Performs Nmap scan using target from state and stores results in session state.

    Args:
        context (ToolContext): ADK ToolContext for accessing session state.

    Returns:
        Dict: The Nmap scan results (also stored in state['nmap_scan_results']).
    """
    # Get target from state (set by initial user interaction)
    target = context.session.state.get('initial_target')

    if not target:
        logger.warning("Target not found in session state for Nmap scan.")
        scan_data = {"scan": {}, "error": "Target not found in session state."}
    else:
        logger.info(f"Starting Nmap scan on target: {target}")
        scanner = nmap.PortScanner()
        # Enhanced Nmap arguments for more comprehensive scanning
        # -sV: Version detection
        # -sC: Default scripts (includes some vuln scanning)
        # -O: OS detection
        # --script vuln: Run vulnerability scanning scripts
        # -T4: Aggressive timing for faster scans (adjust if needed)
        # Consider adding -p- for all ports, but it will be slow.
        nmap_args = '-sV -sC -O --script vuln -T4'
        
        try:
            # Check if nmap is installed before scanning
            nmap_check_stdout, nmap_check_stderr, nmap_check_retcode = _run_command_detailed("nmap -V")
            if nmap_check_retcode != 0:
                 error_msg = f"Nmap command not found or failed check (code {nmap_check_retcode}). Please ensure nmap is installed and in PATH. Error: {nmap_check_stderr}"
                 logger.error(error_msg)
                 scan_data = {"scan": {}, "error": error_msg}
            else:
                 logger.info(f"Nmap version check successful: {nmap_check_stdout}")
                 scanner.scan(target, arguments=nmap_args)
                 scan_info = scanner.scaninfo()
                 if scan_info.get('error'):
                      error_msg = f"Nmap scan encountered errors: {scan_info['error']}"
                      logger.error(error_msg)
                      temp_scan_data = scanner.analyse_nmap_xml_scan()
                      if not temp_scan_data or not temp_scan_data.get('scan'):
                           scan_data = {"scan": {}, "error": error_msg}
                      else:
                           temp_scan_data["warning"] = error_msg
                           scan_data = temp_scan_data
                 else:
                     scan_data = scanner.analyse_nmap_xml_scan()
                     if not scan_data or not scan_data.get('scan'):
                          logger.warning(f"Nmap scan for {target} completed but yielded no host data.")
                          scan_data = {"scan": {}, "info": "Scan completed but no host data found."}
                     else:
                          logger.info(f"Nmap scan completed for {target}.")

        except nmap.PortScannerError as e:
            error_msg = f"Nmap execution error for target {target}: {e}"
            logger.error(error_msg)
            scan_data = {"scan": {}, "error": error_msg}
        except Exception as e:
            error_msg = f"Unexpected error during Nmap scan for {target}: {e}"
            logger.error(error_msg, exc_info=True)
            scan_data = {"scan": {}, "error": error_msg}

    # Store result in session state
    context.session.state['nmap_scan_results'] = scan_data
    logger.debug(f"Stored nmap_scan_results in session state: {list(scan_data.keys())}")

    # Return the result as well (can be useful for immediate checks)
    return scan_data

# Note: analyze_vulnerabilities logic is removed from here.
# It's better placed within the planner agent/tool which interprets the scan results. 

# --- DNS and WHOIS Recon ---

def perform_dns_recon(context: ToolContext) -> Dict[str, Any]:
    """
    Performs enhanced DNS/WHOIS recon using target from state and stores results in session state.
    Includes dig, nslookup, dig +trace, and attempts dig axfr.

    Args:
        context (ToolContext): ADK ToolContext.

    Returns:
        Dict[str, Any]: Recon results (also stored in state['dns_recon_results']).
    """
    target = context.session.state.get('initial_target')
        
    if not target:
        logger.warning("Target not found in session state for DNS recon.")
        results = {"error": "Target not found in session state."}
        context.session.state['dns_recon_results'] = results
        return results

    # Basic validation: Don't run DNS commands on pure IPs
    try:
        ipaddress.ip_address(target)
        logger.info(f"Target '{target}' is an IP address. Skipping DNS-specific lookups (dig, nslookup, AXFR).")
        # Still perform WHOIS if applicable
        results = {"target": target, "dns": {}, "whois": None, "errors": ["Target is IP, skipped DNS lookups."]}
        is_ip_target = True
    except ValueError:
        logger.info(f"Starting DNS/WHOIS reconnaissance for domain: {target}")
        results = {
            "target": target,
            "dns": { # Store results by tool/type
                 "dig": {},
                 "nslookup": {},
                 "trace": None,
                 "axfr_attempt": None
            },
            "whois": None,
            "errors": []
        }
        is_ip_target = False

    # --- Run Commands --- 
    if not is_ip_target:
        # 1. Basic dig Lookups
        dig_records = ["A", "MX", "NS", "TXT", "AAAA", "SOA", "ANY"]
        name_servers = []
        for record_type in dig_records:
            # Using +noall +answer for cleaner output
            stdout, stderr, retcode = _run_command_detailed(f"dig +noall +answer {target} {record_type}")
            if retcode != 0:
                results["errors"].append(f"dig {record_type}: Failed (code {retcode}) - {stderr}")
                results["dns"]["dig"][record_type] = []
            else:
                results["dns"]["dig"][record_type] = stdout.splitlines()
                # Store discovered Name Servers for AXFR attempt
                if record_type == "NS":
                    for line in results["dns"]["dig"][record_type]:
                         parts = line.split()
                         if len(parts) > 3:
                              ns = parts[-1].rstrip('.') # Get last part, remove trailing dot
                              if ns:
                                   name_servers.append(ns)
            # Short sleep to avoid overwhelming DNS servers
            time.sleep(0.5)

        # 2. Basic nslookup Lookups (often gives slightly different format/info)
        nslookup_records = ["A", "MX", "NS", "SOA", "ANY"]
        for record_type in nslookup_records:
            stdout, stderr, retcode = _run_command_detailed(f"nslookup -query={record_type} {target}")
            if retcode != 0:
                 results["errors"].append(f"nslookup {record_type}: Failed (code {retcode}) - {stderr}")
                 results["dns"]["nslookup"][record_type] = "Error"
            else:
                 results["dns"]["nslookup"][record_type] = stdout # Store full output
            time.sleep(0.5)

        # 3. dig +trace
        stdout, stderr, retcode = _run_command_detailed(f"dig +trace {target}")
        if retcode != 0:
             results["errors"].append(f"dig +trace: Failed (code {retcode}) - {stderr}")
             results["dns"]["trace"] = "Error executing trace."
        else:
             results["dns"]["trace"] = stdout
        time.sleep(0.5)
        
        # 4. Attempt Zone Transfer (AXFR)
        if name_servers:
             axfr_results = {}
             logger.info(f"Attempting Zone Transfer (AXFR) for {target} using NS: {name_servers}")
             for ns in name_servers:
                 stdout, stderr, retcode = _run_command_detailed(f"dig axfr @{ns} {target}", timeout=30)
                 if retcode == 0 and "Transfer failed." not in stdout and "connection refused" not in stderr.lower() and "timed out" not in stderr.lower():
                     logger.warning(f"SUCCESS: Zone Transfer likely succeeded from {ns} for {target}!")
                     axfr_results[ns] = {"status": "success", "output": stdout}
                     # Optional: break on first success?
                     # break 
                 elif retcode != 0 or "Transfer failed." in stdout or "connection refused" in stderr.lower() or "timed out" in stderr.lower():
                     logger.info(f"Zone Transfer failed from {ns} (code {retcode}): {stderr}")
                     axfr_results[ns] = {"status": "failed", "error": stderr, "output": stdout} 
                 else:
                     # Unexpected outcome
                     logger.warning(f"Zone Transfer from {ns} had unexpected outcome (code {retcode}): {stderr} / {stdout[:100]}...")
                     axfr_results[ns] = {"status": "unknown", "error": stderr, "output": stdout}
                 time.sleep(1) # Longer sleep for AXFR attempts
             results["dns"]["axfr_attempt"] = axfr_results
        else:
             logger.info("No Name Servers found, skipping Zone Transfer attempt.")
             results["dns"]["axfr_attempt"] = {"status": "skipped", "message": "No NS records found."}

    # --- WHOIS Lookup --- 
    # Determine if target is potentially private (avoids errors for internal IPs)
    # Use the original target string here
    is_private_ip_or_internal_domain = False
    if is_ip_target:
        is_private_ip_or_internal_domain = any(target.startswith(prefix) for prefix in ["192.168.", "10.", "172."])
    else: # For domains, check common internal TLDs
         is_private_ip_or_internal_domain = any(target.endswith(suffix) for suffix in [".local", ".internal", ".lan"])

    if not is_private_ip_or_internal_domain:
         stdout, stderr, retcode = _run_command_detailed(f"whois {target}")
         if retcode != 0:
             results["errors"].append(f"whois: Failed (code {retcode}) - {stderr}")
             results["whois"] = "Failed or unavailable"
         else:
             results["whois"] = stdout
    else:
         logger.info(f"Skipping WHOIS lookup for potentially private/internal target: {target}")
         results["whois"] = "Skipped (Private IP range or Internal Domain)"

    # Remove placeholder subdomains if we are doing real DNS
    if not is_ip_target and "subdomains" in results:
         del results["subdomains"] 
         
    logger.info(f"Finished DNS/WHOIS reconnaissance for: {target}")

    # Store result in session state
    context.session.state['dns_recon_results'] = results
    logger.debug("Stored dns_results in session state.")
    
    return results

# Helper function to run commands and get detailed output
# Note: Consider moving this to a shared utils module if used elsewhere
def _run_command_detailed(command: str, timeout: int = 15) -> Tuple[str, str, int]:
    """Helper function to run a shell command and return stdout, stderr, returncode."""
    try:
        logger.debug(f"Running command: {command}")
        # Use shlex.split for better handling of command arguments
        process = subprocess.run(shlex.split(command), capture_output=True, text=True, check=False, timeout=timeout)
        return process.stdout.strip(), process.stderr.strip(), process.returncode
    except FileNotFoundError:
        cmd_name = command.split()[0]
        err_msg = f"Error: Command '{cmd_name}' not found. Is it installed and in PATH?"
        logger.error(err_msg)
        return "", err_msg, -1 # Indicate file not found with -1
    except subprocess.TimeoutExpired:
        err_msg = f"Error: Command timed out after {timeout}s: {command}"
        logger.warning(err_msg)
        return "", err_msg, -2 # Indicate timeout with -2
    except Exception as e:
        err_msg = f"Unexpected error running command '{command}': {e}"
        logger.error(err_msg, exc_info=True)
        return "", err_msg, -3 # Indicate other error with -3

# --- Web Search and Analysis --- 

# Import the search function
try:
    from googlesearch import search
except ImportError:
    search = None # Flag if library isn't installed

def perform_web_search(context: ToolContext) -> Dict[str, Any]:
    """
    Performs a real web search for the target using the googlesearch library.
    Stores results in session state.

    Args:
        context (ToolContext): ADK ToolContext.

    Returns:
        Dict[str, Any]: Search results (also stored in state['web_search_results']).
    """
    target = context.session.state.get('initial_target')

    if not target:
        logger.warning("Target not found in session state for Web Search.")
        results = {"error": "Target not found in session state."}
        context.session.state['web_search_results'] = results
        return results
        
    if search is None:
        logger.error("The 'googlesearch-python' library is required but not installed. Skipping real web search.")
        results = {"error": "googlesearch-python library not installed.", "status": "skipped"}
        context.session.state['web_search_results'] = results
        return results
        
    logger.info(f"Performing web search for: {target}")
    query = f"site:{target} OR related:{target}" # Search for site and related domains
    search_results = []
    status = "error" # Default to error
    error_msg = None
    
    try:
        # Perform search, limit results (e.g., num=10), add delay (stop=10, pause=2)
        # Consider making num_results, pause configurable
        num_results = 10 
        pause_time = 2.0 
        logger.debug(f"Executing google search: query='{query}', num={num_results}, pause={pause_time}")
        search_results = list(search(query, num_results=num_results, sleep_interval=pause_time))
        status = "completed"
        logger.info(f"Found {len(search_results)} results for query: '{query}'")
        
    except Exception as e:
        # Handle potential search errors (e.g., rate limiting, network issues)
        error_msg = f"Error during web search for '{target}': {e}" 
        logger.error(error_msg, exc_info=True)
        status = "error" 

    results = {
        "target": target,
        "search_query": query,
        "results": search_results, # List of URLs found
        "status": status
    }
    if error_msg:
        results["error"] = error_msg

    # Store result in session state
    context.session.state['web_search_results'] = results
    logger.debug("Stored web_search_results in session state.")

    return results

def analyze_web_content(context: ToolContext) -> List[Dict[str, Any]]:
    """
    Fetches and analyzes basic elements for *all* relevant URLs found in web search results (state).
    Appends findings for each URL to state['web_analysis_results'].

    Args:
        context (ToolContext): ADK ToolContext containing session state.

    Returns:
        List[Dict[str, Any]]: A list of analysis result dictionaries for each URL processed in this run.
    """
    # Initialize results list in state if it doesn't exist
    if 'web_analysis_results' not in context.session.state:
        context.session.state['web_analysis_results'] = []

    current_run_analyses = []
    urls_to_analyze = context.session.state.get('web_search_results', {}).get('results', [])

    if not urls_to_analyze:
        logger.warning("No URLs found in state ('web_search_results') to analyze.")
        return current_run_analyses # Return empty list

    logger.info(f"Starting web content analysis for {len(urls_to_analyze)} URLs found in state.")

    # --- Loop through each URL --- 
    for url in urls_to_analyze:
        if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
            logger.warning(f"Skipping invalid URL format for analysis: {url}")
            continue
            
        logger.info(f"Analyzing content for: {url}")
        # Use a specific user-agent
        headers = {'User-Agent': 'PhantomRecon-Analyzer/1.0'}
        response = _safe_request(url, method="GET", allow_redirects=True, headers=headers)
        
        # Initialize analysis dict for this URL
        analysis = {
            "url": url,
            "status": "error",
            "http_status_code": None,
            "headers": {}, # Store relevant headers
            "title": None,
            "forms": [],
            "scripts": [],
            "comments": [],
            "links": {"internal": [], "external": []},
            "emails": [], # Store found emails
            "technologies": [], # Store identified technologies
            "error_message": "Request failed or returned no response."
        }

        if response is None:
            logger.warning(f"Failed to fetch {url} for analysis.")
            current_run_analyses.append(analysis)
            context.session.state['web_analysis_results'].append(analysis)
            continue # Move to the next URL
            
        analysis["http_status_code"] = response.status_code
        analysis.pop("error_message", None) 
        analysis["status"] = "completed"

        # Capture relevant headers
        relevant_headers = ['Server', 'X-Powered-By', 'Set-Cookie', 'Content-Type', 'X-Frame-Options', 'Content-Security-Policy']
        for header_name in relevant_headers:
            if header_name in response.headers:
                 analysis["headers"][header_name] = response.headers[header_name]
                 # Simple tech detection from headers
                 if header_name == 'Server' and response.headers[header_name] not in analysis["technologies"]:
                      analysis["technologies"].append(f"Server Header: {response.headers[header_name]}")
                 if header_name == 'X-Powered-By' and response.headers[header_name] not in analysis["technologies"]:
                      analysis["technologies"].append(f"X-Powered-By: {response.headers[header_name]}")

        if response.status_code >= 400:
            logger.warning(f"Received HTTP error {response.status_code} for {url}")
            analysis["error_message"] = f"HTTP Error {response.status_code}"
            analysis["status"] = "completed_with_errors"

        content_type = response.headers.get('Content-Type', '').lower()
        if 'html' not in content_type:
            logger.info(f"Skipping HTML analysis for non-HTML content-type ({content_type}) at {url}")
            analysis["status"] = "skipped_non_html"
            analysis["error_message"] = f"Content-type is not HTML ({content_type})"
            current_run_analyses.append(analysis)
            context.session.state['web_analysis_results'].append(analysis)
            continue # Move to the next URL

        # --- Perform HTML Parsing (inside the loop) --- 
        try:
            # Extract Emails using Regex before parsing HTML structure
            # Basic email regex - adjust for more complex cases if needed
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found_emails = re.findall(email_pattern, response.text)
            if found_emails:
                 analysis["emails"] = list(set(found_emails)) # Store unique emails
                 logger.info(f"Found {len(analysis['emails'])} email(s) on {url}")

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract Title
            if soup.title and soup.title.string:
                analysis["title"] = soup.title.string.strip()

            # Extract Meta Generator Tag for Tech Detection
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content') and meta_generator.get('content') not in analysis["technologies"]:
                analysis["technologies"].append(f"Generator: {meta_generator.get('content')}")
                logger.info(f"Identified generator tag: {meta_generator.get('content')}")

            # Extract Forms
            for form in soup.find_all('form'):
                form_details = {
                    "action": form.get('action', ''),
                    "method": form.get('method', 'get').lower(),
                    "inputs": []
                }
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        "tag": input_tag.name,
                        "type": input_tag.get('type', 'text'),
                        "name": input_tag.get('name')
                    }
                    # Add value only if it exists (avoiding None)
                    value = input_tag.get('value')
                    if value is not None:
                         input_info['value'] = value
                    form_details["inputs"].append(input_info)
                analysis["forms"].append(form_details)

            # Extract Script Sources & Basic Tech Check
            found_jquery = False
            found_react = False
            for script in soup.find_all('script'):
                src = script.get('src')
                script_content = script.string # Get inline script content

                if src:
                    analysis["scripts"].append(urljoin(url, src))
                    # Basic tech detection from script source URLs
                    if 'jquery' in src.lower() and not found_jquery:
                         analysis["technologies"].append("jQuery")
                         found_jquery = True
                    if ('react.js' in src.lower() or 'react.min.js' in src.lower()) and not found_react:
                         analysis["technologies"].append("React")
                         found_react = True
                elif script_content: # Check inline script content
                    if 'jQuery' in script_content or ' $.fn.' in script_content and not found_jquery:
                         analysis["technologies"].append("jQuery (likely)")
                         found_jquery = True
                    if 'React.createElement' in script_content and not found_react:
                         analysis["technologies"].append("React (likely)")
                         found_react = True

            # Check for React root element as another indicator
            if soup.find(id='root') or soup.find(id='react-root') or soup.find("div", attrs={"data-reactroot": True}):
                 if "React (likely)" not in analysis["technologies"] and "React" not in analysis["technologies"]:
                      analysis["technologies"].append("React (likely via root element)")

            # Extract Comments
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            for comment in comments:
                analysis["comments"].append(comment.strip())

            # Extract Links
            base_domain = urlparse(url).netloc
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(url, href)
                link_domain = urlparse(full_url).netloc
                if link_domain == base_domain:
                    analysis["links"]["internal"].append(full_url)
                elif link_domain:
                    analysis["links"]["external"].append(full_url)

            # Remove duplicates from links
            analysis["links"]["internal"] = list(set(analysis["links"]["internal"]))
            analysis["links"]["external"] = list(set(analysis["links"]["external"]))

        except Exception as e:
            logger.error(f"Error parsing HTML content for {url}: {e}", exc_info=True)
            analysis["error_message"] = f"HTML Parsing Error: {e}"
            analysis["status"] = "completed_with_errors"
        # --- End HTML Parsing --- 

        # Append results for this URL to state and current run list
        current_run_analyses.append(analysis)
        context.session.state['web_analysis_results'].append(analysis)
        logger.debug(f"Appended web analysis results for {url} to session state.")
    # --- End URL Loop --- 

    logger.info(f"Finished web content analysis for {len(current_run_analyses)} URLs.")
    return current_run_analyses # Return list of results from this run

# --- Aggregation Function ---

def aggregate_recon_data(context: ToolContext, parallel_results: Dict[str, Any]) -> Dict[str, Any]:
     """
     Aggregates results from parallel reconnaissance tools and web analysis.
     Reads nmap/dns/web_search from parallel_results dict.
     Reads web_analysis_results from session state.
     Writes final aggregated data to state['aggregated_recon_data'].

     Args:
          context (ToolContext): ADK ToolContext for accessing session state.
          parallel_results (Dict[str, Any]): The dictionary output from the Parallel recon_workflow agent.

     Returns:
          Dict[str, Any]: Dictionary containing aggregated recon data.
     """
     logger.info("Aggregating parallel reconnaissance and web analysis results...")
     
     # Get results from parallel execution
     nmap_results = parallel_results.get("Nmap Port Scanner", {})
     dns_results = parallel_results.get("DNS/WHOIS Recon", {})
     web_search_results = parallel_results.get("Web Search Simulator", {})
     
     # Get web analysis results from state (populated by web_analysis_tool)
     web_analysis_results = context.session.state.get('web_analysis_results', [])

     aggregated_data = {
         "recon_summary": {},
         "nmap_scan_results": nmap_results,
         "dns_recon_results": dns_results,
         "web_search_results": web_search_results,
         "web_analysis_results": web_analysis_results, # Include analysis results
         "errors": [] 
     }

     # Populate summary and collect errors
     if nmap_results and nmap_results.get("error"):
          aggregated_data["errors"].append(f"Nmap Error: {nmap_results['error']}")
     elif nmap_results and nmap_results.get("scan"):
         aggregated_data["recon_summary"]["nmap_hosts"] = list(nmap_results["scan"].keys())
     
     if dns_results and dns_results.get("error"):
          aggregated_data["errors"].append(f"DNS/WHOIS Error: {dns_results['error']}")
     elif dns_results:
         aggregated_data["recon_summary"]["discovered_subdomains"] = dns_results.get("subdomains", [])
         if dns_results.get("errors"): 
              aggregated_data["errors"].extend(dns_results["errors"])

     if web_search_results and web_search_results.get("error"):
          aggregated_data["errors"].append(f"Web Search Error: {web_search_results['error']}")
     elif web_search_results:
         aggregated_data["recon_summary"]["discovered_urls"] = web_search_results.get("results", [])
         
     # Add summary for web analysis
     if web_analysis_results:
          analyzed_urls = [res.get('url') for res in web_analysis_results if res and res.get('url')]
          aggregated_data["recon_summary"]["analyzed_urls_count"] = len(analyzed_urls)
          # Could add counts of forms, scripts found, etc.
     
     # Store the final aggregated data in the state
     context.session.state['aggregated_recon_data'] = aggregated_data
     logger.info(f"Finished aggregating all reconnaissance data. Summary: {aggregated_data['recon_summary']}")
     if aggregated_data["errors"]:
         logger.warning(f"Aggregation found errors in recon/analysis tools: {aggregated_data['errors']}")
     
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