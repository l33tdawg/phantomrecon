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
    attack_plan = context.session.state.get('attack_plan')
    # Keep track of which exploits we've already attempted in this session
    attempted_exploits = context.session.state.setdefault('attempted_exploits', set())

    if not isinstance(attack_plan, dict) or not attack_plan or attack_plan.get("error"):
        logger.warning("No valid attack plan found in state. Skipping exploit phase.")
        return None # Proceed to reporting

    # Check for Web exploits if not already attempted
    if 'Web Exploit Executor' not in attempted_exploits:
        web_targets = {k: v for k, v in attack_plan.items() if k.startswith('web_')}
        if web_targets:
            logger.info("Routing to Web Exploit Executor.")
            attempted_exploits.add('Web Exploit Executor')
            context.session.state['attempted_exploits'] = attempted_exploits # Update state
            return 'Web Exploit Executor' # Name must match the agent name in the main workflow

    # Check for SQL exploits if not already attempted
    if 'SQL Exploit Executor' not in attempted_exploits:
        sql_targets = {k: v for k, v in attack_plan.items() if k.startswith('sql_')}
        if sql_targets:
            logger.info("Routing to SQL Exploit Executor.")
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
        print("[ROUTER] No context provided, cannot determine next exploit")
        return None
        
    return decide_next_exploit(context) 