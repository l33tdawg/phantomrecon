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
    Create an attack plan based on reconnaissance data using ADK's BuiltInPlanner.
    
    Args:
        scan_data (Dict): Reconnaissance scan results.
                          Returns {"error": ...} on scan failure.
        context: The context from the runner (optional).
        
    Returns:
        Dict: Structured attack plan (service -> {details, tests}),
              or {"error": ...} if planning fails or scan_data is invalid.
    """
    logger.info("Creating attack plan from scan data using ADK BuiltInPlanner.")
    
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
        # We'll use the context if provided, otherwise proceed without session state
        # The context would be passed from the agent runner
        
        # Get the planner instruction from the template
        instruction = _load_prompt_template()
        
        # Create the BuiltInPlanner
        planner = BuiltInPlanner(
            instruction=instruction,
            output_key="attack_plan"
        )
        
        # Format the scan data into a more readable format for the LLM
        formatted_scan = json.dumps(scan_data, indent=2)
        
        # Run the planner
        user_message = f"""Here is the reconnaissance scan data for analysis:
```json
{formatted_scan}
```
Based on this data, generate an attack plan following the instructions."""
        
        # Execute the planner
        result = await planner.run(user_message)
        
        # Process the result
        if isinstance(result, dict):
            logger.info(f"BuiltInPlanner generated attack plan with {len(result)} target(s).")
            
            # Store in session state if context is available
            if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
                context.session.state['attack_plan'] = result
                
            return result
        else:
            logger.warning(f"BuiltInPlanner returned non-dict result: {type(result)}")
            return {"error": f"Planner returned invalid result type: {type(result)}"}
            
    except Exception as e:
        logger.error(f"Error using BuiltInPlanner for attack planning: {e}")
        return {"error": f"Failed to create attack plan: {e}"}

async def simple_create_attack_plan(**kwargs):
    """
    A greatly simplified wrapper for create_attack_plan with minimal parameter declarations
    to help ADK's automatic function calling.
    
    Returns:
        A structured attack plan or error dictionary
    """
    logger.info("Using greatly simplified wrapper for attack planning")
    
    # Get context if available
    context = kwargs.get('context')
    
    # Extract scan data from session state if available
    scan_data = {}
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        print(f"[PLANNER] State Keys: {list(context.session.state.keys())}")
        
        # Check for 'recon' key first
        recon_data = context.session.state.get('recon', None)
        if recon_data and isinstance(recon_data, dict):
            print(f"[PLANNER] Found recon data in session state with keys: {list(recon_data.keys())}")
            scan_data = recon_data
        else:
            print(f"[PLANNER] No valid recon data found in session state")
            
            # Try to look for individual recon components
            nmap_results = context.session.state.get('nmap_scan_results', None)
            dns_results = context.session.state.get('dns_recon_results', None)
            web_results = context.session.state.get('web_search_results', None)
            
            if any([nmap_results, dns_results, web_results]):
                print(f"[PLANNER] Found individual recon components, building composite data")
                scan_data = {
                    "nmap_scan": nmap_results if nmap_results else {},
                    "dns_recon": dns_results if dns_results else {},
                    "web_search": web_results if web_results else {}
                }
    else:
        print(f"[PLANNER] No access to session state")
        
    # Check if we can get scan_data from kwargs
    if not scan_data and 'scan_data' in kwargs:
        scan_data = kwargs['scan_data']
        print(f"[PLANNER] Using scan_data from kwargs")
    
    # Validate scan_data - ensure it's not empty and has required keys
    if not scan_data:
        error_msg = "No reconnaissance data found in session state or kwargs"
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
        print(f"[PLANNER ERROR] {error_msg}")
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
        return result
    except Exception as e:
        error_msg = f"Planning error: {str(e)}"
        print(f"[PLANNER ERROR] {error_msg}")
        logger.error(f"Error in simple_create_attack_plan: {e}", exc_info=True)
        return {"error": error_msg}

# Removed prioritize_targets function for simplicity in this refactor step. 