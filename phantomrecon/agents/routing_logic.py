#!/usr/bin/env python3
from typing import Dict, Any, Optional, Union
import logging
from google.adk.tools import ToolContext
from google.adk.agents import Agent

logger = logging.getLogger(__name__)

def decide_next_exploit(context: ToolContext, **kwargs: Any) -> Optional[str]:
    """
    Decides which exploit tool to run next based on the attack plan in state.
    This function is intended to be used by a RouterAgent or similar mechanism.

    Args:
        context (ToolContext): ADK ToolContext for accessing session state.
        **kwargs: Catches any preceding output passed by ADK sequence.

    Returns:
        Optional[str]: The name of the next agent/tool to execute 
                       (e.g., 'Web Exploit Executor', 'SQL Exploit Executor'), 
                       or None to signify moving to the default next step (reporting).
    """
    logger.info("Routing exploits...")
    attack_plan = None
    
    # First try to get attack plan from context
    if hasattr(context, 'session') and hasattr(context.session, 'state'):
        attack_plan = context.session.state.get('attack_plan')
    
    # If no attack plan in context, try global cache
    if not attack_plan:
        try:
            from google.adk.sessions.in_memory_session_service import _get_from_global_cache
            attack_plan = _get_from_global_cache('attack_plan')
            logger.info("Retrieved attack plan from global cache")
        except (ImportError, Exception) as e:
            logger.warning(f"Could not access global cache: {e}")
            
    # Still no attack plan? Try emergency file cache
    if not attack_plan:
        try:
            import pickle
            import os
            cache_file = 'plan_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    attack_plan = pickle.load(f)
                logger.info("Loaded attack plan from emergency cache file")
        except Exception as e:
            logger.warning(f"Could not load attack plan from cache file: {e}")

    # If still no valid attack plan, return None
    if not isinstance(attack_plan, dict) or not attack_plan or attack_plan.get("error"):
        logger.warning("No valid attack plan found. Skipping exploit phase.")
        return None # Proceed to reporting

    # Keep track of which exploits we've already attempted
    attempted_exploits = set()
    if hasattr(context, 'session') and hasattr(context.session, 'state'):
        attempted_exploits = context.session.state.setdefault('attempted_exploits', set())

    # Check for Web exploits if not already attempted
    if 'Web Exploit Executor' not in attempted_exploits:
        # Check for any web-related entries in attack plan
        has_web = False
        for k, v in attack_plan.items():
            if k == 'web' or k.startswith('web_') or k == 'subdomains':
                has_web = True
                break
                
        if has_web:
            logger.info("Routing to Web Exploit Executor.")
            if hasattr(context, 'session') and hasattr(context.session, 'state'):
                attempted_exploits.add('Web Exploit Executor')
                context.session.state['attempted_exploits'] = attempted_exploits # Update state
            return 'Web Exploit Executor' # Name must match the agent name in the main workflow

    # Check for SQL exploits if not already attempted
    if 'SQL Exploit Executor' not in attempted_exploits:
        # Check for any SQL-related entries in attack plan
        has_sql = False
        for k, v in attack_plan.items():
            if k == 'sql' or k.startswith('sql_') or k.startswith('database_'):
                has_sql = True
                break
                
        if has_sql:
            logger.info("Routing to SQL Exploit Executor.")
            if hasattr(context, 'session') and hasattr(context.session, 'state'):
                attempted_exploits.add('SQL Exploit Executor')
                context.session.state['attempted_exploits'] = attempted_exploits # Update state
            return 'SQL Exploit Executor' # Name must match the agent name in the main workflow
            
    # Add checks for other exploit types (e.g., SSH) here...

    # If all relevant planned exploits have been attempted, proceed to next step (report)
    logger.info("All planned/attempted exploits routed. Proceeding to next step.")
    return None 

def simple_decide_next_exploit(**kwargs):
    """
    A simplified wrapper for decide_next_exploit that helps ADK's automatic function calling.
    
    Returns:
        The name of the next tool/agent to execute, or None
    """
    print("[ROUTER] Using simplified router function")
    context = kwargs.get('context')
    
    if not context:
        print("[ROUTER] Context not provided, using emergency cache mechanism")
        # Create a minimal context-like object with required attributes
        class MinimalContext:
            pass
            
        minimal_context = MinimalContext()
        minimal_context.session = MinimalContext()
        minimal_context.session.state = {}
        
        return decide_next_exploit(minimal_context)
    
    return decide_next_exploit(context) 