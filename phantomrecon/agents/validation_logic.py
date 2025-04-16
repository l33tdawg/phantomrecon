#!/usr/bin/env python3
import json
from typing import Dict, Any
import logging
from google.adk.tools import ToolContext

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

logger = logging.getLogger(__name__)

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
        print(f"[VALIDATION-STATE] Using state from context with {len(state)} keys")
        return state
    
    # If context is not available, try to get state from emergency cache
    print(f"[VALIDATION-STATE] Context not available, using global cache fallback")
    
    # Get important keys from global cache
    try:
        # Try to get attack plan first (for validation)
        attack_plan = _get_from_global_cache('attack_plan')
        if attack_plan:
            state['attack_plan'] = attack_plan
            print(f"[VALIDATION-STATE] Retrieved attack_plan from global cache")
            
        # Also get initial target
        target = _get_from_global_cache('initial_target')
        if target:
            state['initial_target'] = target
            print(f"[VALIDATION-STATE] Retrieved initial_target from global cache")
    except Exception as e:
        print(f"[VALIDATION-WARNING] Error accessing global cache: {e}")
    
    # If state is still empty, try emergency file cache as last resort
    if not state or 'attack_plan' not in state:
        try:
            import pickle
            import os
            plan_cache_file = 'plan_cache.pkl'
            if os.path.exists(plan_cache_file):
                with open(plan_cache_file, 'rb') as f:
                    attack_plan = pickle.load(f)
                    state['attack_plan'] = attack_plan
                    print(f"[VALIDATION-STATE] Loaded attack_plan from cache file")
        except Exception as e:
            print(f"[VALIDATION-WARNING] Could not load attack plan from cache file: {e}")
    
    return state

async def validate_attack_plan(raw_planner_output: Any) -> Dict:
    """
    Validates the output from the ADK BuiltInPlanner.
    Ensures it's valid JSON and attempts basic structure checks.
    Stores the validated (or error) plan in state['attack_plan'].

    Args:
        raw_planner_output (Any): The raw output from the preceding planner.

    Returns:
        Dict: The validated attack plan dictionary, or a dictionary with an 'error' key.
    """
    logger.info("Validating ADK planner output...")
    
    # Get the current context from the tool's context parameter
    context = None
    try:
        # We'll get the context from the runner or we can have it passed as a parameter
        # For now, let's return an error if we don't have context
        if not context:
            return {"error": "Context not available for validation"}
    except Exception as e:
        logger.error(f"Error accessing context: {e}")
        return {"error": f"Context error: {e}"}
    
    # Initialize with default error state
    validated_plan = {"error": "Validation failed: Unknown reason"}
    
    # Planner output should already be a dictionary if using ADK BuiltInPlanner
    if isinstance(raw_planner_output, dict):
        # ADK already parsed it as JSON
        logger.debug("Planner output is a dictionary, as expected from ADK BuiltInPlanner.")
        plan_data = raw_planner_output
    elif isinstance(raw_planner_output, str):
        # In case the planner returned a string (JSON), try to parse it
        logger.debug("Planner output is a string, attempting JSON parse.")
        try:
            # Clean up potential markdown code blocks if LLM included them
            cleaned_output = raw_planner_output.strip()
            if cleaned_output.startswith("```json"):
                cleaned_output = cleaned_output[7:]
            if cleaned_output.endswith("```"):
                cleaned_output = cleaned_output[:-3]
            cleaned_output = cleaned_output.strip()
            
            plan_data = json.loads(cleaned_output)
            if not isinstance(plan_data, dict):
                raise TypeError("Parsed JSON is not a dictionary.")
        except json.JSONDecodeError as e:
            error_msg = f"Validation failed: Planner output is not valid JSON. Error: {e}. Output: {raw_planner_output[:500]}..."
            logger.error(error_msg)
            validated_plan = {"error": error_msg}
            
            # Store in state (context and global cache)
            if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
                context.session.state['attack_plan'] = validated_plan
            
            # Store in global cache
            try:
                _set_in_global_cache('attack_plan', validated_plan)
            except Exception:
                pass
                
            return validated_plan
        except TypeError as e:
            error_msg = f"Validation failed: Planner output JSON is not a dictionary. Type: {type(plan_data)}. Error: {e}"
            logger.error(error_msg)
            validated_plan = {"error": error_msg}
            
            # Store in state (context and global cache)
            if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
                context.session.state['attack_plan'] = validated_plan
                
            # Store in global cache
            try:
                _set_in_global_cache('attack_plan', validated_plan)
            except Exception:
                pass
                
            return validated_plan
    else:
        error_msg = f"Validation failed: Planner output type unexpected. Type: {type(raw_planner_output)}"
        logger.error(error_msg)
        validated_plan = {"error": error_msg}
        
        # Store in state (context and global cache)
        if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
            context.session.state['attack_plan'] = validated_plan
            
        # Store in global cache
        try:
            _set_in_global_cache('attack_plan', validated_plan)
        except Exception:
            pass
            
        return validated_plan

    # Basic Structure Check (can be expanded)
    if not plan_data: # Allow empty plan if no targets found
        logger.info("Planner returned an empty plan (no targets found or planned). Proceeding.")
        validated_plan = {}
    else:
        valid_structure = True
        for key, value in plan_data.items():
            if not isinstance(value, dict) or not all(k in value for k in ['target_host', 'port', 'service_name', 'product', 'version', 'tests']) or not isinstance(value['tests'], list):
                valid_structure = False
                error_msg = f"Validation failed: Plan item '{key}' has incorrect structure or missing keys."
                logger.error(error_msg)
                validated_plan = {"error": error_msg, "invalid_item": key, "item_value": value}
                break 
        
        if valid_structure:
            logger.info("Attack plan JSON structure validation passed.")
            validated_plan = plan_data

    # Store the final validated plan (or error) in state if context is available
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        context.session.state['attack_plan'] = validated_plan
        logger.debug("Stored validated attack_plan in session state.")
        
    # Also store in global cache as backup
    try:
        _set_in_global_cache('attack_plan', validated_plan)
        logger.debug("Stored validated attack_plan in global cache.")
    except Exception as e:
        logger.warning(f"Failed to store attack_plan in global cache: {e}")

    return validated_plan 