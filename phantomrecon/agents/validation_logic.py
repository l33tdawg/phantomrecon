#!/usr/bin/env python3
import json
from typing import Dict, Any
import logging
from google.adk.tools import ToolContext

logger = logging.getLogger(__name__)

def validate_attack_plan(context: ToolContext, raw_planner_output: Any) -> Dict:
    """
    Validates the output from the LLM planning agent.
    Ensures it's valid JSON and attempts basic structure checks.
    Stores the validated (or error) plan in state['attack_plan'].

    Args:
        context (ToolContext): ADK ToolContext.
        raw_planner_output (Any): The raw output from the preceding LlmAgent.

    Returns:
        Dict: The validated attack plan dictionary, or a dictionary with an 'error' key.
    """
    logger.info("Validating LLM planner output...")
    validated_plan = {"error": "Validation failed: Unknown reason"}
    
    if isinstance(raw_planner_output, dict):
        # If ADK already parsed it as JSON (due to response_mime_type)
        logger.debug("Planner output already parsed as dict by ADK.")
        plan_data = raw_planner_output
    elif isinstance(raw_planner_output, str):
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
            context.session.state['attack_plan'] = validated_plan
            return validated_plan
        except TypeError as e:
            error_msg = f"Validation failed: Planner output JSON is not a dictionary. Type: {type(plan_data)}. Error: {e}"
            logger.error(error_msg)
            validated_plan = {"error": error_msg}
            context.session.state['attack_plan'] = validated_plan
            return validated_plan
    else:
        error_msg = f"Validation failed: Planner output type unexpected. Type: {type(raw_planner_output)}"
        logger.error(error_msg)
        validated_plan = {"error": error_msg}
        context.session.state['attack_plan'] = validated_plan
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

    # Store the final validated plan (or error) in state
    context.session.state['attack_plan'] = validated_plan
    logger.debug("Stored validated attack_plan in session state.")

    return validated_plan 