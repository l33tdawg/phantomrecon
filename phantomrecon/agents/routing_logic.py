#!/usr/bin/env python3
from typing import Dict, Any, Optional, Union
import logging
import json
from google.adk.tools import ToolContext
from google.adk.agents import Agent
import os
import pickle

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
        logger.info(f"Using state from context with {len(state)} keys: {list(state.keys())}")
        return state
    
    # If context is not available, try to get state from emergency cache
    logger.info(f"Context not available, using global cache fallback")
    
    # Get important keys from global cache
    try:
        # Try to get attack plan first
        attack_plan = _get_from_global_cache('attack_plan')
        if attack_plan:
            state['attack_plan'] = attack_plan
            logger.info(f"Retrieved attack_plan from global cache")
    except Exception as e:
        logger.warning(f"Error accessing global cache: {e}")
    
    # If state is still empty, try emergency file cache as last resort
    if not state or 'attack_plan' not in state:
        try:
            cache_file = 'plan_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    attack_plan = pickle.load(f)
                    state['attack_plan'] = attack_plan
                    logger.info(f"Loaded attack_plan from emergency cache file")
        except Exception as e:
            logger.warning(f"Could not load attack plan from cache file: {e}")
    
    # Last resort - try to find a valid attack plan among the most common keys
    # that might have been used by the planner
    if not state or 'attack_plan' not in state:
        try:
            for key in ['plan', 'attackPlan', 'attack_plan_result', 'planner_output', 'planning_result']:
                plan_data = _get_from_global_cache(key)
                if plan_data:
                    state['attack_plan'] = plan_data
                    logger.info(f"Found attack plan under alternate key: {key}")
                    break
        except Exception as e:
            logger.warning(f"Error checking alternate plan keys: {e}")
    
    # Check if we found attack plan through any method
    if 'attack_plan' in state:
        logger.info(f"Successfully retrieved attack plan via fallback mechanisms")
    else:
        logger.warning(f"Failed to find attack plan through any method")
        
    return state

def decide_next_exploit(context: ToolContext) -> str:
    """
    Decide the next exploitation step based on the attack plan.
    
    Args:
        context: The tool context with session state
        
    Returns:
        The next exploitation step as a string ("ssh", "vulnscan", "webapp", "report")
    """
    # Get the attack plan from state
    logging.info("Deciding next exploitation step based on attack plan")
    state = get_global_state(context)
    attack_plan = state.get('attack_plan')
    
    if attack_plan is None:
        logging.warning("No attack plan found in state, proceeding to reporting")
        return None
        
    # Handle the case where attack_plan is a string (JSON serialized)
    logging.info(f"Attack plan type: {type(attack_plan)}")
    if isinstance(attack_plan, str):
        try:
            attack_plan = json.loads(attack_plan)
            logging.info(f"Successfully parsed attack plan string as JSON")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse attack plan string as JSON: {str(e)}")
            return None
    
    # Log the attack plan for debugging
    try:
        logging.info(f"Attack plan content: {json.dumps(attack_plan, indent=2)}")
    except:
        logging.info(f"Attack plan content (non-serializable): {str(attack_plan)}")
    
    # Ensure attack_plan is a dictionary after parsing
    if not isinstance(attack_plan, dict):
        logging.error(f"Attack plan is not a dictionary: {type(attack_plan)}")
        logging.error(f"Attack plan content: {attack_plan}")
        return None
            
    # Get exploit results to check what's already been done
    exploit_results = state.get('exploit_results', [])
    if not isinstance(exploit_results, list):
        exploit_results = [exploit_results]
        
    completed_exploits = set()
    for result in exploit_results:
        if isinstance(result, dict) and 'type' in result:
            completed_exploits.add(result['type'])
    
    # Find the highest priority attack that hasn't been completed yet
    highest_priority = -1
    next_exploit = None
    
    # Check for all possible service keys with different naming patterns
    web_keys = ['web_exploit', 'web', 'webapp', 'http', 'https']
    ssh_keys = ['ssh_exploit', 'ssh', 'secure_shell']
    sql_keys = ['sql_exploit', 'sql', 'database', 'mysql', 'postgresql']
    
    # Try to find web exploit plans
    for key in web_keys:
        if key in attack_plan:
            value = attack_plan[key]
            if isinstance(value, dict) and value.get('recommended', False) and 'web' not in completed_exploits:
                priority = value.get('priority', 0)
                if priority > highest_priority:
                    highest_priority = priority
                    next_exploit = 'web'
    
    # Try to find SSH exploit plans
    for key in ssh_keys:
        if key in attack_plan:
            value = attack_plan[key]
            if isinstance(value, dict) and value.get('recommended', False) and 'ssh' not in completed_exploits:
                priority = value.get('priority', 0)
                if priority > highest_priority:
                    highest_priority = priority
                    next_exploit = 'ssh'
    
    # Try to find SQL exploit plans
    for key in sql_keys:
        if key in attack_plan:
            value = attack_plan[key]
            if isinstance(value, dict) and value.get('recommended', False) and 'sql' not in completed_exploits:
                priority = value.get('priority', 0)
                if priority > highest_priority:
                    highest_priority = priority
                    next_exploit = 'sql'
    
    # If still no exploit found, use the old approach of looking for specific keys
    if next_exploit is None:
        for key, value in attack_plan.items():
            # Skip non-exploit entries like "target" or "summary"
            if key not in ['ssh_exploit', 'web_exploit', 'vuln_scan_exploit', 'sql_exploit']:
                continue
                
            # Convert the key to a simpler form for comparison
            exploit_type = key.replace('_exploit', '')
            
            # Check if this exploit has been recommended and not yet completed
            if (isinstance(value, dict) and 
                value.get('recommended', False) and 
                exploit_type not in completed_exploits):
                priority = value.get('priority', 0)
                if priority > highest_priority:
                    highest_priority = priority
                    next_exploit = exploit_type
    
    if next_exploit:
        logging.info(f"Selected next exploitation step: {next_exploit}")
        return next_exploit
    else:
        logging.info("No more exploitation steps to perform, proceeding to reporting")
        return None

def simple_decide_next_exploit(**kwargs: Any) -> Optional[str]:
    """
    Simplified wrapper for decide_next_exploit. Takes the same parameters.
    
    Returns:
        Optional[str]: The name of the next agent/tool to execute
                      or None to move to reporting.
    """
    logger.info("Using simplified router for exploitation")
    context = kwargs.get('context')
    print(f"[ROUTER] Starting exploit routing...")
    
    if context:
        print(f"[ROUTER] Context available for routing")
        if hasattr(context, 'session') and hasattr(context.session, 'state'):
            print(f"[ROUTER] State available with keys: {list(context.session.state.keys())}")
            if 'attack_plan' in context.session.state:
                print(f"[ROUTER] Attack plan found in state")
            else:
                print(f"[ROUTER] Attack plan not found in state, will check fallbacks")
    else:
        print(f"[ROUTER] No context available for routing, using fallbacks")
    
    result = decide_next_exploit(context)
    print(f"[ROUTER] Router decision: {result}")
    return result 