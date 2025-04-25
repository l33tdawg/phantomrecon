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
            # Ensure attack_plan is a dictionary, not a string
            if isinstance(attack_plan, str):
                try:
                    # Try to parse it as JSON
                    parsed_plan = json.loads(attack_plan)
                    attack_plan = parsed_plan
                    logger.info(f"Successfully parsed attack_plan string from global cache as JSON")
                except json.JSONDecodeError as e:
                    # If it's not valid JSON but is a string, it might be a pickled object
                    # or another format. Use a default empty plan with a warning.
                    logger.warning(f"Retrieved attack_plan as string but not valid JSON: {e}")
                    attack_plan = {"web_exploit": {"recommended": True, "priority": 10}}
                    
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
                    
                    # Ensure attack_plan is a dictionary, not a string
                    if isinstance(attack_plan, str):
                        try:
                            # Try to parse it as JSON
                            parsed_plan = json.loads(attack_plan)
                            attack_plan = parsed_plan
                            logger.info(f"Successfully parsed attack_plan string from cache file as JSON")
                        except json.JSONDecodeError as e:
                            # If it's not valid JSON but is a string, use default
                            logger.warning(f"Retrieved attack_plan as string but not valid JSON: {e}")
                            attack_plan = {"web_exploit": {"recommended": True, "priority": 10}}
                    
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
                    # Ensure plan_data is a dictionary, not a string
                    if isinstance(plan_data, str):
                        try:
                            # Try to parse it as JSON
                            parsed_plan = json.loads(plan_data)
                            plan_data = parsed_plan
                            logger.info(f"Successfully parsed plan string from alternate key {key} as JSON")
                        except json.JSONDecodeError as e:
                            # If it's not valid JSON but is a string, check for default structure
                            logger.warning(f"Retrieved plan from {key} as string but not valid JSON: {e}")
                            plan_data = {"web_exploit": {"recommended": True, "priority": 10}}
                    
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
        print("[ROUTER DEBUG] No attack plan found in state")
        return None
        
    # Handle the case where attack_plan is a string (JSON serialized)
    logging.info(f"Attack plan type: {type(attack_plan)}")
    print(f"[ROUTER DEBUG] Attack plan type: {type(attack_plan)}")
    if isinstance(attack_plan, str):
        try:
            attack_plan = json.loads(attack_plan)
            logging.info(f"Successfully parsed attack plan string as JSON")
            print(f"[ROUTER DEBUG] Successfully parsed attack plan string as JSON")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse attack plan string as JSON: {str(e)}")
            print(f"[ROUTER DEBUG] Failed to parse attack plan string as JSON: {str(e)}")
            # Create a fallback plan with at least one exploit to try
            logging.info(f"Using fallback attack plan with default web exploit")
            print(f"[ROUTER DEBUG] Using fallback attack plan with default web exploit")
            attack_plan = {
                "web_exploit": {
                    "recommended": True,
                    "priority": 10,
                    "tests": ["check_default_files", "test_for_directory_listing"]
                }
            }
    
    # Log the attack plan for debugging
    try:
        print(f"[ROUTER DEBUG] Attack plan keys: {list(attack_plan.keys())}")
        print(f"[ROUTER DEBUG] Attack plan: {json.dumps(attack_plan, indent=2)}")
    except:
        print(f"[ROUTER DEBUG] Attack plan (non-serializable): {str(attack_plan)}")
    
    # Ensure attack_plan is a dictionary after parsing
    if not isinstance(attack_plan, dict):
        logging.error(f"Attack plan is not a dictionary: {type(attack_plan)}")
        logging.error(f"Attack plan content: {attack_plan}")
        print(f"[ROUTER DEBUG] Attack plan is not a dictionary: {type(attack_plan)}")
        print(f"[ROUTER DEBUG] Attack plan content: {attack_plan}")
        return None
            
    # Get exploit results to check what's already been done
    exploit_results = state.get('exploit_results', [])
    if not isinstance(exploit_results, list):
        exploit_results = [exploit_results]
    
    print(f"[ROUTER DEBUG] Completed exploits: {exploit_results}")
        
    completed_exploits = set()
    for result in exploit_results:
        if isinstance(result, dict) and 'type' in result:
            completed_exploits.add(result['type'])
    
    print(f"[ROUTER DEBUG] Completed exploit types: {completed_exploits}")
    
    # Find the highest priority attack that hasn't been completed yet
    highest_priority = -1
    next_exploit = None
    
    # Check for all possible service keys with different naming patterns
    web_keys = ['web_exploit', 'web', 'webapp', 'http', 'https']
    ssh_keys = ['ssh_exploit', 'ssh', 'secure_shell']
    sql_keys = ['sql_exploit', 'sql', 'database', 'mysql', 'postgresql']
    
    print(f"[ROUTER DEBUG] Looking for web exploits in keys: {web_keys}")
    print(f"[ROUTER DEBUG] Looking for SSH exploits in keys: {ssh_keys}")
    print(f"[ROUTER DEBUG] Looking for SQL exploits in keys: {sql_keys}")
    
    # Try to find web exploit plans
    for key in web_keys:
        if key in attack_plan:
            value = attack_plan[key]
            print(f"[ROUTER DEBUG] Found web key: {key}, value: {value}")
            if isinstance(value, dict):
                # Check if recommended flag exists and is True, or default to True if not present
                recommended = value.get('recommended', True)  # Default to True if not specified
                print(f"[ROUTER DEBUG] Web exploit recommended: {recommended}")
                
                if recommended and 'web' not in completed_exploits:
                    priority = value.get('priority', 5)  # Default priority of 5
                    print(f"[ROUTER DEBUG] Web exploit priority: {priority}")
                    
                    if priority > highest_priority:
                        highest_priority = priority
                        next_exploit = 'web'
                        print(f"[ROUTER DEBUG] Selected web exploit with priority {priority}")
    
    # Try to find SSH exploit plans
    for key in ssh_keys:
        if key in attack_plan:
            value = attack_plan[key]
            print(f"[ROUTER DEBUG] Found SSH key: {key}, value: {value}")
            if isinstance(value, dict):
                # Default to True if recommended is not specified
                recommended = value.get('recommended', True)
                print(f"[ROUTER DEBUG] SSH exploit recommended: {recommended}")
                
                if recommended and 'ssh' not in completed_exploits:
                    priority = value.get('priority', 5)
                    print(f"[ROUTER DEBUG] SSH exploit priority: {priority}")
                    
                    if priority > highest_priority:
                        highest_priority = priority
                        next_exploit = 'ssh'
                        print(f"[ROUTER DEBUG] Selected SSH exploit with priority {priority}")
    
    # Try to find SQL exploit plans
    for key in sql_keys:
        if key in attack_plan:
            value = attack_plan[key]
            print(f"[ROUTER DEBUG] Found SQL key: {key}, value: {value}")
            if isinstance(value, dict):
                # Default to True if recommended is not specified
                recommended = value.get('recommended', True)
                print(f"[ROUTER DEBUG] SQL exploit recommended: {recommended}")
                
                if recommended and 'sql' not in completed_exploits:
                    priority = value.get('priority', 5)
                    print(f"[ROUTER DEBUG] SQL exploit priority: {priority}")
                    
                    if priority > highest_priority:
                        highest_priority = priority
                        next_exploit = 'sql'
                        print(f"[ROUTER DEBUG] Selected SQL exploit with priority {priority}")
    
    # If we found an exploit, return it
    if next_exploit:
        print(f"[ROUTER] Selected next exploitation step: {next_exploit}")
        logging.info(f"Selected next exploitation step: {next_exploit}")
        return next_exploit
    else:
        print(f"[ROUTER] No exploitation steps found in attack plan, proceeding to reporting")
        print(f"[ROUTER DEBUG] No valid exploits were found in the attack plan with recommended=True and proper priority")
        print(f"[ROUTER DEBUG] Make sure your attack plan contains entries with keys like: {web_keys + ssh_keys + sql_keys}")
        print(f"[ROUTER DEBUG] And each entry should be a dictionary with recommended=True and a positive priority value")
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