#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from google.adk.agents import Agent, LlmAgent
# Note: SequentialAgent and ParallelAgent might not exist in ADK 0.1.0
# Let's use a simpler approach with just regular LlmAgent
from google.adk.tools import FunctionTool
import logging
import json
from typing import Optional, Dict, Any

# Import the logic functions
from ..agents.recon_logic import (
    perform_nmap_scan,
    perform_dns_recon,
    perform_web_search,
    analyze_web_content,
    aggregate_recon_data
)
from ..agents.exploit_web_logic import run_web_exploits
from ..agents.exploit_sql_logic import run_sql_exploits
from ..agents.exploit_ssh_logic import run_ssh_exploits
from ..agents.report_logic import generate_final_report
from ..agents.routing_logic import decide_next_exploit
from ..agents.validation_logic import validate_attack_plan
# Import new summary logic
from ..agents.summary_logic import prepare_summary_input, store_report_summary

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Prompt Loading --- 
def load_prompt(filename: str) -> str:
    """Loads a prompt from the prompts directory."""
    # Go up two levels from phantomrecon/agent/ to reach project root
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    prompt_path = os.path.join(project_root, 'prompts', filename)
    try:
        with open(prompt_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"Prompt file not found: {prompt_path}")
        return "ERROR: Prompt not found."
    except Exception as e:
        logger.error(f"Error loading prompt {prompt_path}: {e}")
        return f"ERROR: Could not load prompt - {e}"

# Load the summarizer prompt
summarizer_prompt_template = load_prompt("report_summarizer_prompt.txt")

# --- Define Tools with simplified FunctionTool calls ---
def store_target_in_state(context, target: str) -> str:
    """Stores the validated target IP or domain in the session state."""
    logger.info(f"Storing target '{target}' in session state.")
    if not target:
        logger.warning("Attempted to store an empty target.")
        return "Error: No target provided. Please provide a valid IP address or website name."
    context.session.state['initial_target'] = target
    return f"OK. Target '{target}' stored. Proceeding with the assessment."

# Simple FunctionTool initialization with only func parameter
store_target_tool = FunctionTool(func=store_target_in_state)
nmap_tool = FunctionTool(func=perform_nmap_scan)
dns_tool = FunctionTool(func=perform_dns_recon)
web_search_tool = FunctionTool(func=perform_web_search)
web_analysis_tool = FunctionTool(func=analyze_web_content)
aggregation_tool = FunctionTool(func=aggregate_recon_data)
plan_validation_tool = FunctionTool(func=validate_attack_plan)
prepare_summary_input_tool = FunctionTool(func=prepare_summary_input)
store_summary_tool = FunctionTool(func=store_report_summary)
web_exploit_tool = FunctionTool(func=run_web_exploits)
sql_exploit_tool = FunctionTool(func=run_sql_exploits)
ssh_exploit_tool = FunctionTool(func=run_ssh_exploits)
report_tool = FunctionTool(func=generate_final_report)

# Load the planning prompt 
planner_prompt_template = load_prompt("attack_planner_prompt.txt")

# Basic setup for LLM agent
planning_agent = LlmAgent(
    name="planning_agent",
    model="gemini-1.5-flash-latest",
    instruction=planner_prompt_template
)

report_summarizer_agent = LlmAgent(
    name="report_summarizer_agent",
    model="gemini-1.5-flash-latest",
    instruction=summarizer_prompt_template
)

# Create a simple LlmAgent as the root agent
root_agent = LlmAgent(
    name="PhantomRecon_Agent",
    model="gemini-1.5-flash-latest",
    instruction="""You are the friendly user-facing agent for the PhantomRecon security tool.
1. Greet the user warmly.
2. Ask the user for the target IP address or website name they want to assess.
3. Once the user provides a target, *confirm* it with them (e.g., "Okay, I will assess target X. Is that correct?").
4. If the user confirms, use the provided tool to save the confirmed target.
5. After the target is stored successfully, inform the user that the assessment workflow is now starting.""",
    tools=[store_target_tool]
)

logger.info("PhantomRecon ADK Agent initialized for interactive web UI.")

# Next Steps:
# 1. Update recon logic functions (perform_nmap_scan, etc.) to accept ToolContext and read state['initial_target']
# 2. Implement Real SQL/SSH Exploits.
# 3. Implement Real Web Search.
# 4. Refine LLM Planner & Error Handling.
# 5. Testing.
