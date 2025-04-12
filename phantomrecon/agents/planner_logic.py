#!/usr/bin/env python3
import os
from typing import Dict, List
import json
import logging
# Removed LangChain/OpenAI imports

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _load_prompt_template() -> str:
    """Load the attack planner prompt template (for future LLM use)."""
    # Although not used by the rule-based planner now, keep for Gemini integration
    prompt_file = os.path.join(os.path.dirname(__file__), 
                             '../prompts/attack_planner_prompt.txt')
    default_prompt = """PROMPT MISSING: Default planner prompt.""" # Basic default
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

def create_plan_from_scan(scan_data: Dict) -> Dict:
    """
    Create an attack plan based on reconnaissance data using rule-based logic.
    
    Args:
        scan_data (Dict): Reconnaissance scan results (from perform_nmap_scan).
                          Expected structure includes keys like 'scan'.
                          Returns {"error": ...} on scan failure.
        
    Returns:
        Dict: Structured attack plan (service -> {details, tests}),
              or {"error": ...} if planning fails or scan_data is invalid.
    """
    logger.info("Creating attack plan from scan data.")
    
    if not isinstance(scan_data, dict) or "scan" not in scan_data:
        error_msg = "Invalid or missing scan data for planning."
        logger.error(error_msg)
        if isinstance(scan_data, dict) and "error" in scan_data:
             error_msg = f"Scan failed previously: {scan_data['error']}"
        return {"error": error_msg}

    attack_plan = {}
    target_host = "Unknown" # Default target host

    try:
        # Process scan results - Assumes scan_data structure from python-nmap
        for host, host_data in scan_data.get("scan", {}).items():
            target_host = host # Store the host IP/name
            addresses = host_data.get("addresses", {})
            ip_address = addresses.get("ipv4") or addresses.get("ipv6") or host
            
            for port_info in host_data.get("tcp", {}).values(): # Check TCP ports
                state = port_info.get("state")
                if state == "open":
                    service_name = port_info.get("name", "unknown")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "N/A")
                    port_num = port_info.get("port") # This might be string, convert later if needed

                    # Rule-based mapping: Add services and basic tests
                    if "http" in service_name and ("Apache" in product or "nginx" in product or "IIS" in product):
                        service_key = f"web_{port_num}" # Unique key per port
                        attack_plan[service_key] = {
                            "target_host": ip_address,
                            "port": port_num,
                            "service_name": service_name,
                            "product": product,
                            "version": version,
                            "tests": [
                                "version_vulnerabilities",
                                "directory_traversal",
                                "default_files",
                                "misconfigurations"
                            ]
                        }
                        logger.info(f"Added Web target: {product} on {ip_address}:{port_num}")

                    elif "mysql" in service_name:
                        service_key = f"sql_{port_num}"
                        attack_plan[service_key] = {
                            "target_host": ip_address,
                            "port": port_num,
                            "service_name": service_name,
                            "product": product,
                            "version": version,
                            "tests": [
                                "version_vulnerabilities",
                                "default_credentials",
                                "user_privileges",
                                "information_disclosure"
                            ]
                        }
                        logger.info(f"Added SQL target: {product} on {ip_address}:{port_num}")
                        
                    # Add more rules for other services (e.g., SSH, FTP)
                    elif "ssh" in service_name:
                        service_key = f"ssh_{port_num}"
                        attack_plan[service_key] = {
                             "target_host": ip_address,
                             "port": port_num,
                             "service_name": service_name,
                             "product": product,
                             "version": version,
                             "tests": [
                                 "version_vulnerabilities",
                                 "weak_credentials",
                                 "ssh_config_audit"
                             ]
                        }
                        logger.info(f"Added SSH target: {product} on {ip_address}:{port_num}")

        if not attack_plan:
            logger.warning(f"No actionable services found in scan data for host {target_host}.")
            return {"info": f"No actionable services found for {target_host}"} # Not an error, but no plan

        logger.info(f"Generated attack plan with {len(attack_plan)} target(s).")
        return attack_plan

    except Exception as e:
        logger.error(f"Error processing scan data during planning: {e}")
        return {"error": f"Failed to create attack plan: {e}"}

# Removed prioritize_targets function for simplicity in this refactor step. 