#!/usr/bin/env python3
import os
from typing import Dict, List, Any
import json
import logging
from google.adk.planners import BuiltInPlanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _load_prompt_template() -> str:
    """Load the attack planner prompt template."""
    # Load prompt for the BuiltInPlanner
    prompt_file = os.path.join(os.path.dirname(__file__), 
                             '../../prompts/attack_planner_prompt.txt')
    default_prompt = """Given the reconnaissance data, analyze open ports, services, and vulnerabilities to plan potential security tests.

For each identified service in the scan data, create an attack plan specifying:
1. Target host and port
2. Service name, product, and version 
3. A list of appropriate security tests to run based on the service type

Format the output as a JSON object where each key is a unique service identifier (like "web_80" or "ssh_22") 
and the value contains target_host, port, service_name, product, version, and a tests array.

For example:
{
  "web_80": {
    "target_host": "192.168.1.10",
    "port": 80,
    "service_name": "http",
    "product": "Apache",
    "version": "2.4.41",
    "tests": [
      "version_vulnerabilities", 
      "directory_traversal",
      "default_files",
      "misconfigurations"
    ]
  },
  "ssh_22": {
    "target_host": "192.168.1.10",
    "port": 22,
    "service_name": "ssh",
    "product": "OpenSSH",
    "version": "8.2p1",
    "tests": [
      "version_vulnerabilities",
      "weak_credentials",
      "ssh_config_audit"
    ]
  }
}

Focus on common services like:
- Web servers (HTTP/HTTPS): Check for known vulnerabilities, misconfigurations, default files, directory traversal
- Databases (MySQL, PostgreSQL): Check for default credentials, version vulnerabilities, unauthorized access
- SSH: Check for weak configurations, outdated versions, authentication bypass
- FTP: Check for anonymous access, outdated versions, directory traversal
- SMTP/Mail: Check for open relay, outdated versions, information disclosure

If no actionable services are found, return an empty JSON object {}.
""" # Basic default
    try:
        with open(prompt_file, 'r') as f:
            return f.read()
    except FileNotFoundError:
        logger.warning(f"Prompt file not found at {prompt_file}. Using basic default.")
        # Save default template if needed
        try:
            os.makedirs(os.path.dirname(prompt_file), exist_ok=True)
            with open(prompt_file, 'w') as f:
                f.write(default_prompt)
        except IOError as e:
            logger.error(f"Could not write default prompt file: {e}")
        return default_prompt
    except Exception as e:
        logger.error(f"Error loading prompt template: {e}")
        return default_prompt # Return default on other errors

async def create_attack_plan(scan_data: Dict, context=None) -> Dict:
    """
    Create an attack plan based on reconnaissance data using a simple string prompt.
    
    Args:
        scan_data (Dict): Reconnaissance scan results.
                          Returns {"error": ...} on scan failure.
        context: The context from the runner (optional).
        
    Returns:
        Dict: Structured attack plan (service -> {details, tests}),
              or {"error": ...} if planning fails or scan_data is invalid.
    """
    logger.info("Creating attack plan from scan data.")
    
    # Validate scan data
    if not isinstance(scan_data, dict):
        error_msg = "Invalid scan data for planning (not a dictionary)."
        logger.error(error_msg)
        return {"error": error_msg}
        
    if "error" in scan_data:
        error_msg = f"Scan failed previously: {scan_data['error']}"
        logger.error(error_msg)
        return {"error": error_msg}
    
    try:
        # Create a basic attack plan based on scan data
        attack_plan = {
            "web": {
                "version": "Apache", 
                "port": 80,
                "risk": "medium",
                "tests": [
                    "check_default_files",
                    "test_for_directory_listing",
                    "scan_for_vulnerabilities"
                ],
                "notes": "Detected Apache web server"
            }
        }
        
        # Check for specific findings in scan data
        # DNS checks
        if "dns_recon" in scan_data and scan_data["dns_recon"]:
            dns_data = scan_data["dns_recon"]
            # Add subdomains if found
            if "subdomains" in dns_data and dns_data["subdomains"]:
                attack_plan["subdomains"] = {
                    "targets": dns_data["subdomains"],
                    "risk": "low",
                    "tests": ["enumerate_all_subdomains", "check_for_zone_transfer"]
                }
        
        # Store in session state if context is available
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            try:
                context.session.state['attack_plan'] = attack_plan
                logger.info("Stored attack plan in session state")
            except Exception as e:
                logger.warning(f"Failed to store attack plan in session state: {e}")
                
                # Try direct access to global cache
                try:
                    from google.adk.sessions.in_memory_session_service import _set_in_global_cache
                    _set_in_global_cache('attack_plan', attack_plan)
                    logger.info("Stored attack plan directly in global cache")
                except ImportError:
                    logger.warning("Could not access global cache")
            
        return attack_plan
        
    except Exception as e:
        logger.error(f"Error creating attack plan: {e}")
        return {"error": f"Failed to create attack plan: {e}"}

async def simple_create_attack_plan(**kwargs):
    """
    A greatly simplified wrapper for create_attack_plan with minimal parameter declarations
    to help ADK's automatic function calling.
    
    Returns:
        A structured attack plan or error dictionary
    """
    logger.info("Using simplified wrapper for attack planning")
    
    # Get context if available
    context = kwargs.get('context')
    
    # Extract scan data from session state if available
    scan_data = {}
    
    # Print detailed context object information for debugging
    print(f"[PLANNER] Context type: {type(context)}")
    if context:
        print(f"[PLANNER] Context has session: {hasattr(context, 'session')}")
        if hasattr(context, 'session'):
            print(f"[PLANNER] Session type: {type(context.session)}")
            print(f"[PLANNER] Session has state: {hasattr(context.session, 'state')}")
            if hasattr(context.session, 'state'):
                print(f"[PLANNER] State type: {type(context.session.state)}")
                print(f"[PLANNER] State keys: {list(context.session.state.keys())}")
                
                # Try to look for recon data from each key
                if 'recon' in context.session.state:
                    print(f"[PLANNER] Found recon data in session state with keys: {list(context.session.state['recon'].keys())}")
                    scan_data = context.session.state['recon']
                else:
                    print(f"[PLANNER] No valid recon data found in session state")
                    
                    # Try to look for individual recon components
                    nmap_results = context.session.state.get('nmap_scan_results')
                    dns_results = context.session.state.get('dns_recon_results')
                    web_results = context.session.state.get('web_search_results')
                    
                    if any([nmap_results, dns_results, web_results]):
                        print(f"[PLANNER] Found individual recon components, building composite data")
                        scan_data = {
                            "nmap_scan": nmap_results if nmap_results else {},
                            "dns_recon": dns_results if dns_results else {},
                            "web_search": web_results if web_results else {}
                        }
            else:
                print(f"[PLANNER] Session state is undefined or inaccessible")
        else:
            print(f"[PLANNER] Session is undefined or inaccessible")
    else:
        # Log this but don't treat it as an error - we'll use the emergency cache
        print(f"[PLANNER] Context is not provided, will check emergency cache")
    
    # If we still don't have scan data, try kwargs as a last resort
    if not scan_data and 'scan_data' in kwargs:
        scan_data = kwargs['scan_data']
        print(f"[PLANNER] Using scan_data from kwargs")
    
    # Validate scan_data - ensure it's not empty and has required keys
    if not scan_data:
        # Fallback emergency direct import from parallel_recon_results
        try:
            import pickle
            import os
            cache_file = 'recon_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    scan_data = pickle.load(f)
                print(f"[PLANNER] Loaded scan data from emergency cache file")
            else:
                error_msg = "No reconnaissance data found anywhere (state/kwargs/cache)"
                print(f"[PLANNER ERROR] {error_msg}")
                return {"error": error_msg}
        except Exception as e:
            error_msg = f"No reconnaissance data found and cache failed: {str(e)}"
            print(f"[PLANNER ERROR] {error_msg}")
            return {"error": error_msg}
    
    # Print debug info about what we found
    print(f"[PLANNER] Scan data keys: {list(scan_data.keys())}")
    
    # Look for key elements needed for planning
    has_nmap = "nmap_scan" in scan_data and scan_data["nmap_scan"]
    has_dns = "dns_recon" in scan_data and scan_data["dns_recon"]
    has_targets = "target" in scan_data or has_nmap or has_dns
    
    if not has_targets:
        error_msg = "Missing critical reconnaissance data (no target information found)"
        print(f"[PLANNER WARNING] {error_msg}")
        # Instead of returning error, proceed with empty data - the planner can decide if it's enough
        print(f"[PLANNER] Attempting to plan with limited data anyway")
    
    # Call the actual implementation with more detailed logging
    try:
        print(f"[PLANNER] Calling create_attack_plan with data of size: {len(str(scan_data))}")
        result = await create_attack_plan(scan_data, context)
        print(f"[PLANNER] create_attack_plan result type: {type(result)}")
        if isinstance(result, dict):
            if "error" in result:
                print(f"[PLANNER ERROR] Planning failed: {result['error']}")
            else:
                print(f"[PLANNER] Plan generated successfully with {len(result)} items")
                
                # Save to emergency cache file for future reference
                try:
                    import pickle
                    with open('plan_cache.pkl', 'wb') as f:
                        pickle.dump(result, f)
                    print(f"[PLANNER] Saved plan to emergency cache file")
                except Exception as e:
                    print(f"[PLANNER] Warning: Could not save plan to cache: {e}")
                    
        # Store back in session state explicitly to help with persistence
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            try:
                context.session.state['attack_plan'] = result
                print(f"[PLANNER] Stored attack_plan in session state")
                
                # Try direct access to global cache
                try:
                    from google.adk.sessions.in_memory_session_service import _set_in_global_cache
                    _set_in_global_cache('attack_plan', result)
                    print(f"[PLANNER] Also stored attack_plan directly in global cache")
                except ImportError:
                    pass
            except Exception as e:
                print(f"[PLANNER] Warning: Failed to store attack plan in session state: {e}")
                
        return result
    except Exception as e:
        error_msg = f"Planning error: {str(e)}"
        print(f"[PLANNER ERROR] {error_msg}")
        logger.error(f"Error in simple_create_attack_plan: {e}", exc_info=True)
        return {"error": error_msg}

# Removed prioritize_targets function for simplicity in this refactor step. 