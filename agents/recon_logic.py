#!/usr/bin/env python3
import nmap
import json
from typing import Dict, List, Optional, Any
import os
import logging
import subprocess
import shlex
from google.adk.tools import ToolContext # Import ToolContext

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

def perform_nmap_scan(context: ToolContext, target: Optional[str] = None) -> Dict:
    """
    Performs Nmap scan and stores results in session state.

    Args:
        context (ToolContext): ADK ToolContext for accessing session state.
        target (Optional[str]): Target IP or hostname. If None, tries to get from state or uses dummy.

    Returns:
        Dict: The Nmap scan results (also stored in state['nmap_results']).
    """
    # Get target from args or state (if passed from initial user input)
    if not target:
        target = context.session.state.get('initial_target')

    if not target:
        logger.info("No target specified for Nmap, using dummy data.")
        scan_data = _load_dummy_data()
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
            try:
                 subprocess.run(["nmap", "-V"], check=True, capture_output=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                 error_msg = "Nmap command not found. Please ensure nmap is installed and in PATH."
                 logger.error(error_msg)
                 scan_data = {"scan": {}, "error": error_msg}
            else:
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
    context.session.state['nmap_results'] = scan_data
    logger.debug(f"Stored nmap_results in session state: {list(scan_data.keys())}")

    # Return the result as well (can be useful for immediate checks)
    return scan_data

# Note: analyze_vulnerabilities logic is removed from here.
# It's better placed within the planner agent/tool which interprets the scan results. 

# --- DNS and WHOIS Recon ---

def _run_command(command: str) -> str:
    """Helper function to run a shell command and return its output."""
    try:
        logger.debug(f"Running command: {command}")
        # Use shlex.split for better handling of command arguments
        process = subprocess.run(shlex.split(command), capture_output=True, text=True, check=True, timeout=30)
        return process.stdout.strip()
    except FileNotFoundError:
        cmd_name = command.split()[0]
        logger.error(f"Command not found: '{cmd_name}'. Is it installed and in PATH?")
        return f"Error: Command '{cmd_name}' not found."
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {command}")
        return "Error: Command timed out."
    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{command}' failed with error: {e.stderr}")
        return f"Error running command: {e.stderr}"
    except Exception as e:
        logger.error(f"Unexpected error running command '{command}': {e}", exc_info=True)
        return f"Unexpected error: {e}"

def perform_dns_recon(context: ToolContext, target: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs DNS/WHOIS recon and stores results in session state.

    Args:
        context (ToolContext): ADK ToolContext.
        target (Optional[str]): Target domain/IP. If None, tries to get from state.

    Returns:
        Dict[str, Any]: Recon results (also stored in state['dns_results']).
    """
    if not target:
        target = context.session.state.get('initial_target')
        
    if not target:
        results = {"error": "No target specified for DNS recon."}
        context.session.state['dns_results'] = results
        return results

    logger.info(f"Starting DNS/WHOIS reconnaissance for: {target}")
    results = {
        "target": target,
        "dns": {},
        "whois": None,
        "subdomains": [], # Initialize subdomains list
        "errors": []
    }

    # DNS Lookups using dig
    dns_records = ["A", "MX", "NS", "TXT", "AAAA"]
    for record_type in dns_records:
        output = _run_command(f"dig +short {target} {record_type}")
        if "Error:" in output:
            results["errors"].append(f"dig {record_type}: {output}")
        results["dns"][record_type] = output.splitlines() if output and "Error:" not in output else []

    # WHOIS Lookup
    is_private_ip = any(target.startswith(prefix) for prefix in ["192.168.", "10.", "172."])
    if not is_private_ip:
         whois_output = _run_command(f"whois {target}")
         if "Error:" in whois_output:
             results["errors"].append(f"whois: {whois_output}")
             results["whois"] = "Failed or unavailable"
         else:
             results["whois"] = whois_output
    else:
         logger.info(f"Skipping WHOIS lookup for potentially private target: {target}")
         results["whois"] = "Skipped (Private IP range)"

    # Simulate Subdomains (replace with real tools later)
    results["subdomains"] = [f"subdomain1.{target}", f"www.{target}"]
    logger.info(f"Finished DNS/WHOIS reconnaissance for: {target}")

    # Store result in session state
    context.session.state['dns_results'] = results
    logger.debug("Stored dns_results in session state.")
    
    return results

# --- Web Search and Analysis (Placeholders) ---

def perform_web_search(context: ToolContext, target: Optional[str] = None) -> Dict[str, Any]:
    """
    Placeholder: Simulates web search and stores results in session state.

    Args:
        context (ToolContext): ADK ToolContext.
        target (Optional[str]): Target domain/company. If None, tries to get from state.

    Returns:
        Dict[str, Any]: Simulated search results (also stored in state['web_search_results']).
    """
    if not target:
        target = context.session.state.get('initial_target')

    if not target:
        results = {"error": "No target specified for Web Search."}
        context.session.state['web_search_results'] = results
        return results
        
    logger.info(f"Simulating web search for: {target}")
    # Simulate finding common web addresses
    simulated_urls = [f"http://{target}", f"https://{target}", f"https://www.{target}"]
    # Add based on common subdomains found
    simulated_urls.extend([f"http://subdomain1.{target}", f"https://support.{target}"])
    
    # Remove duplicates and potentially invalid URLs (basic check)
    valid_urls = list(set(u for u in simulated_urls if '.' in u.split('/')[-1])) # Very basic check

    results = {
        "target": target,
        "search_query": f"related websites for {target}",
        "results": valid_urls,
        "status": "simulated"
    }

    # Store result in session state
    context.session.state['web_search_results'] = results
    logger.debug("Stored web_search_results in session state.")

    return results

def analyze_web_content(context: ToolContext, url: Optional[str] = None) -> Dict[str, Any]:
    """
    Placeholder: Simulates web analysis and stores results in session state.

    Args:
        context (ToolContext): ADK ToolContext.
        url (Optional[str]): URL to analyze. If None, maybe pick one from state['web_search_results'].

    Returns:
        Dict[str, Any]: Simulated analysis findings (potentially appended to state['web_analysis_results']).
    """
    if not url:
        # Example: Try to get a URL from previous web search results
        web_results = context.session.state.get('web_search_results', {}).get('results', [])
        if web_results:
            url = web_results[0] # Analyze the first found URL
        else:
            results = {"error": "No URL provided or found in state for web analysis."}
            # Optionally store this error state? Maybe not necessary for analysis.
            return results
            
    logger.info(f"Simulating web content analysis for: {url}")
    # Simulate finding common elements
    findings = {
        "forms": [{"action": "/login", "fields": ["username", "password"]}],
        "script_tags": ["/js/jquery.min.js", "/js/app.js"],
        "comments": ["TODO: Remove debug endpoint /api/v1/debug"],
        "potential_endpoints": ["/api/users", "/api/v1/"],
        "external_links": [f"https://partner.{url.split('.')[-2]}.com"]
    }
    results = {
        "url": url,
        "status": "simulated",
        "findings": findings
    }

    # Append results to a list in the state
    if 'web_analysis_results' not in context.session.state:
        context.session.state['web_analysis_results'] = []
    context.session.state['web_analysis_results'].append(results)
    logger.debug(f"Appended web analysis results for {url} to session state.")

    return results

# --- Aggregation Function ---

def aggregate_recon_data(context: ToolContext, parallel_results: Dict[str, Any]) -> Dict[str, Any]:
     """
     Aggregates results from parallel reconnaissance tools.

     Args:
          context (ToolContext): ADK ToolContext for accessing session state.
          parallel_results (Dict[str, Any]): The dictionary output from the Parallel recon_workflow agent,
                                             e.g., {"Nmap Port Scanner": {...}, "DNS/WHOIS Recon": {...}, ...}

     Returns:
          Dict[str, Any]: Dictionary containing aggregated recon data (also stored in state['aggregated_recon_data']).
     """
     logger.info("Aggregating parallel reconnaissance results...")
     
     # Initialize with data from the parallel execution results
     # Map tool names to desired keys in the aggregated structure
     nmap_results = parallel_results.get("Nmap Port Scanner", {})
     dns_results = parallel_results.get("DNS/WHOIS Recon", {})
     web_search_results = parallel_results.get("Web Search Simulator", {})
     # web_analysis_results = context.session.state.get('web_analysis_results', []) # Analysis might run separately or be triggered differently

     aggregated_data = {
         "recon_summary": {},
         "nmap_scan_results": nmap_results,
         "dns_recon_results": dns_results,
         "web_search_results": web_search_results,
         # "web_analysis_results": web_analysis_results, # Not directly from this parallel run
         "errors": [] # Collect errors from individual tools
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
         if dns_results.get("errors"): # Append specific tool errors
              aggregated_data["errors"].extend(dns_results["errors"])

     if web_search_results and web_search_results.get("error"):
          aggregated_data["errors"].append(f"Web Search Error: {web_search_results['error']}")
     elif web_search_results:
         aggregated_data["recon_summary"]["discovered_urls"] = web_search_results.get("results", [])
     
     # if web_analysis_results:
     #      aggregated_data["recon_summary"]["analyzed_urls_count"] = len(web_analysis_results)

     # Store the final aggregated data in the state
     context.session.state['aggregated_recon_data'] = aggregated_data
     logger.info(f"Finished aggregating reconnaissance data. Summary: {aggregated_data['recon_summary']}")
     if aggregated_data["errors"]:
         logger.warning(f"Aggregation found errors in recon tools: {aggregated_data['errors']}")
     
     return aggregated_data # Return the aggregated data 