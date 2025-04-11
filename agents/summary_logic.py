#!/usr/bin/env python3
import json
import logging
from typing import Dict, Any
from google.adk.tools import ToolContext

logger = logging.getLogger(__name__)

def prepare_summary_input(context: ToolContext, **kwargs: Any) -> Dict:
    """
    Gathers reconnaissance, plan, and exploit results from state 
    and formats them into a dictionary for the summarizer LLM.
    Stores the formatted dictionary in state['summary_input'].
    """
    logger.info("Preparing input data for report summarization...")
    recon_data = context.session.state.get('aggregated_recon_data', {})
    attack_plan = context.session.state.get('attack_plan', {})
    exploit_results = context.session.state.get('exploit_results', [])
    
    # Basic check to ensure essential data exists
    if not recon_data or not exploit_results:
        logger.warning("Missing reconnaissance or exploit results in state. Cannot prepare summary input.")
        summary_input = {"error": "Missing essential data for summary generation."}
        context.session.state['summary_input'] = summary_input
        return summary_input # Return error state
        
    # Create the input dictionary, potentially cleaning or simplifying data if needed
    summary_input = {
        "reconnaissance_summary": recon_data.get("recon_summary", {}),
        "attack_plan": attack_plan if not attack_plan.get("error") else {"error": "Plan validation failed"}, # Pass plan or error
        "exploit_results": exploit_results 
        # Consider adding specific service details from recon_data if helpful 
    }
    
    # Store the prepared input in state
    context.session.state['summary_input'] = summary_input
    logger.debug("Stored summary_input in session state.")
    
    # Return the input data itself (ADK passes this to the next agent)
    return summary_input 

def store_report_summary(context: ToolContext, raw_summary_output: Any) -> Dict:
    """
    Validates the JSON output from the report summarizer LLM.
    Stores the validated summary and risk score in state['report_summary'].
    """
    logger.info("Validating report summary output from LLM...")
    validated_summary = {"error": "Summary validation failed: Unknown reason"}
    
    summary_data = None
    if isinstance(raw_summary_output, dict):
        logger.debug("Summarizer output already parsed as dict by ADK.")
        summary_data = raw_summary_output
    elif isinstance(raw_summary_output, str):
        logger.debug("Summarizer output is a string, attempting JSON parse.")
        try:
            cleaned_output = raw_summary_output.strip()
            if cleaned_output.startswith("```json"):
                cleaned_output = cleaned_output[7:]
            if cleaned_output.endswith("```"):
                cleaned_output = cleaned_output[:-3]
            cleaned_output = cleaned_output.strip()
            summary_data = json.loads(cleaned_output)
            if not isinstance(summary_data, dict):
                raise TypeError("Parsed JSON is not a dictionary.")
        except (json.JSONDecodeError, TypeError) as e:
            error_msg = f"Validation failed: Summarizer output is not valid JSON dict. Error: {e}. Output: {raw_summary_output[:500]}..."
            logger.error(error_msg)
            validated_summary = {"error": error_msg}
            context.session.state['report_summary'] = validated_summary
            return validated_summary # Return error state
    else:
        error_msg = f"Validation failed: Summarizer output type unexpected. Type: {type(raw_summary_output)}"
        logger.error(error_msg)
        validated_summary = {"error": error_msg}
        context.session.state['report_summary'] = validated_summary
        return validated_summary

    # Validate structure and content
    required_keys = ["overall_risk", "executive_summary_md"]
    if not all(key in summary_data for key in required_keys):
        error_msg = f"Validation failed: Summarizer output missing required keys ({required_keys}). Output: {summary_data}"
        logger.error(error_msg)
        validated_summary = {"error": error_msg}
    elif not isinstance(summary_data["overall_risk"], str) or not summary_data["overall_risk"]:
        error_msg = f"Validation failed: 'overall_risk' is not a non-empty string. Output: {summary_data}"
        logger.error(error_msg)
        validated_summary = {"error": error_msg}
    elif not isinstance(summary_data["executive_summary_md"], str) or not summary_data["executive_summary_md"]:
        error_msg = f"Validation failed: 'executive_summary_md' is not a non-empty string. Output: {summary_data}"
        logger.error(error_msg)
        validated_summary = {"error": error_msg}
    else:
        # Looks valid
        logger.info("LLM Report Summary validation passed.")
        validated_summary = summary_data
        
    # Store the validated summary (or error) in state
    context.session.state['report_summary'] = validated_summary
    logger.debug("Stored validated report_summary in session state.")

    return validated_summary 