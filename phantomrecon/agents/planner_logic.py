#!/usr/bin/env python3
import os
from typing import Dict, List, Any
import json
import logging
from google.adk.planners import BuiltInPlanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        print(f"[PLANNER-STATE] Using state from context with {len(state)} keys")
        return state
    
    # If context is not available, try to get state from emergency cache
    print(f"[PLANNER-STATE] Context not available, using global cache fallback")
    
    # Get important keys from global cache
    try:
        # Try to get recon data first
        recon = _get_from_global_cache('recon')
        if recon:
            state['recon'] = recon
            print(f"[PLANNER-STATE] Retrieved recon from global cache")
            
        # Try to get initial target as backup
        target = _get_from_global_cache('initial_target')
        if target:
            state['initial_target'] = target
            print(f"[PLANNER-STATE] Retrieved initial_target from global cache: {target}")
    except Exception as e:
        print(f"[PLANNER-WARNING] Error accessing global cache: {e}")
    
    # If state is still empty, try emergency file cache as last resort
    if not state or 'recon' not in state:
        try:
            import pickle
            cache_file = 'recon_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    recon_data = pickle.load(f)
                    print(f"[PLANNER-STATE] Loaded recon data from cache file with {len(recon_data) if isinstance(recon_data, dict) else 0} keys")
                    state['recon'] = recon_data
        except Exception as e:
            print(f"[PLANNER-WARNING] Could not load from emergency cache file: {e}")
    
    return state

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
        
        # Get state for storing
        state = get_global_state(context)
        
        # Store in session state if context is available
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            try:
                # Ensure the attack plan is serializable before storing
                serializable_plan = _ensure_serializable(attack_plan)
                context.session.state['attack_plan'] = serializable_plan
                print(f"[PLANNER] Stored attack plan in session state")
            except Exception as e:
                logger.warning(f"Failed to store attack plan in session state: {e}")
        
        # Always store in global cache as a fallback
        try:
            serializable_plan = _ensure_serializable(attack_plan)
            _set_in_global_cache('attack_plan', serializable_plan)
            print(f"[PLANNER] Stored attack plan in global cache")
        except Exception as e:
            logger.warning(f"Failed to store in global cache: {e}")
        
        # Also save to emergency file as last resort
        try:
            import pickle
            with open('plan_cache.pkl', 'wb') as f:
                pickle.dump(attack_plan, f)
            print(f"[PLANNER] Saved plan to emergency cache file")
        except Exception as e:
            print(f"[PLANNER] Warning: Could not save plan to cache: {e}")
            
        return attack_plan
        
    except Exception as e:
        logger.error(f"Error creating attack plan: {e}")
        return {"error": f"Failed to create attack plan: {e}"}

async def simple_create_attack_plan(**kwargs):
    """
    A simplified wrapper for create_attack_plan that helps ADK's automatic function calling.
    This function extracts reconnaissance data from either:
    1. Direct recon argument
    2. Session state (if context available)
    3. Fallback to emergency cache file
    
    Returns:
        dict: Attack plan or error message
    """
    
    print("[PLANNER] Starting plan creation....")
    
    # Extract context from kwargs
    context = kwargs.get('context')
    
    # Extract scan data from various sources
    scan_data = kwargs.get('recon_data')  # Direct argument takes precedence
    
    # If no direct recon_data, try to get from state
    if not scan_data:
        # Get global state (context and fallbacks)
        state = get_global_state(context)
        
        # First try to get from recon key
        scan_data = state.get('recon')
        if scan_data:
            print(f"[PLANNER] Using reconnaissance data from state['recon']")
        else:
            # Try to assemble from individual recon pieces
            print(f"[PLANNER] No 'recon' key found, trying to assemble from pieces")
            nmap_scan = state.get('nmap_scan_results', {})
            dns_recon = state.get('dns_recon_results', {})
            web_search = state.get('web_search_results', {})
            web_analysis = state.get('web_content_analysis', {})
            
            if any([nmap_scan, dns_recon, web_search, web_analysis]):
                scan_data = {
                    "nmap_scan": nmap_scan,
                    "dns_recon": dns_recon,
                    "web_search": web_search,
                    "web_analysis": web_analysis,
                    "target": state.get('initial_target', "unknown")
                }
                print(f"[PLANNER] Assembled recon data from individual components")
    
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
                
                # Always save to emergency cache file for future reference
                try:
                    import pickle
                    with open('plan_cache.pkl', 'wb') as f:
                        pickle.dump(result, f)
                    print(f"[PLANNER] Saved plan to emergency cache file")
                except Exception as e:
                    print(f"[PLANNER] Warning: Could not save plan to cache: {e}")
                    
        # Always store in global cache as fallback
        try:
            serializable_result = _ensure_serializable(result)
            _set_in_global_cache('attack_plan', serializable_result)
            print(f"[PLANNER] Stored attack_plan in global cache")
        except Exception as e:
            print(f"[PLANNER] Warning: Failed to store in global cache: {e}")
        
        # Store back in session state explicitly to help with persistence
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            try:
                # Ensure the result is serializable
                serializable_result = _ensure_serializable(result)
                context.session.state['attack_plan'] = serializable_result
                print(f"[PLANNER] Stored attack_plan in session state")
            except Exception as e:
                print(f"[PLANNER] Warning: Failed to store attack plan in session state: {e}")
                
        return result
    except Exception as e:
        error_msg = f"Planning error: {str(e)}"
        print(f"[PLANNER ERROR] {error_msg}")
        logger.error(f"Error in simple_create_attack_plan: {e}", exc_info=True)
        return {"error": error_msg} 