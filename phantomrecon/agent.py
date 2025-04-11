#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from google.adk.agents import Agent, LlmAgent, Sequential, Parallel, RouterAgent, ToolContext
from google.adk.tools import FunctionTool
import logging
import json
from typing import Optional, Dict, Any

# Import the logic functions 
from agents.recon_logic import (
    perform_nmap_scan, 
    perform_dns_recon, 
    perform_web_search, 
    analyze_web_content,
    aggregate_recon_data
)
from agents.exploit_web_logic import run_web_exploits
from agents.exploit_sql_logic import run_sql_exploits
from agents.exploit_ssh_logic import run_ssh_exploits
from agents.report_logic import generate_final_report
from agents.routing_logic import decide_next_exploit
from agents.validation_logic import validate_attack_plan
# Import new summary logic
from agents.summary_logic import prepare_summary_input, store_report_summary

# Load environment variables 
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Prompt Loading --- 
def load_prompt(filename: str) -> str:
    """Loads a prompt from the prompts directory."""
    prompt_path = os.path.join(os.path.dirname(__file__), '../prompts', filename)
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

# --- Define Store Target Tool --- 
def store_target_in_state(context: ToolContext, target: str) -> str:
    """Stores the validated target IP or domain in the session state."""
    logger.info(f"Storing target '{target}' in session state.")
    # Potential Improvement: Add basic validation (IP format, plausible domain)
    if not target:
        logger.warning("Attempted to store an empty target.")
        return "Error: No target provided. Please provide a valid IP address or website name."
    context.session.state['initial_target'] = target
    return f"OK. Target '{target}' stored. Proceeding with the assessment."

store_target_tool = FunctionTool(
    func=store_target_in_state,
    name="StoreTargetTool",
    description="Use this tool ONLY to save the target IP address or website provided by the user into the session state BEFORE starting the main security workflow. Takes the target string as input."
)

# --- Define Recon Tools (Updated Descriptions) --- 

nmap_tool = FunctionTool(
    func=perform_nmap_scan, 
    name="Nmap Port Scanner",
    description="Performs Nmap scan. Reads target from state['initial_target']. Writes results to state['nmap_scan_results']."
)

dns_tool = FunctionTool(
    func=perform_dns_recon, 
    name="DNS/WHOIS Recon",
    description="Performs DNS/WHOIS lookups. Reads target from state['initial_target']. Writes results to state['dns_recon_results']. Requires dig/whois."
)

web_search_tool = FunctionTool(
    func=perform_web_search, 
    name="Web Search Tool",
    description="Performs a Google search for the target domain. Reads target from state['initial_target']. Writes results (list of URLs) to state['web_search_results']. Requires googlesearch-python."
)

# --- Define Web Analysis Tool --- 
web_analysis_tool = FunctionTool(
    func=analyze_web_content,
    name="Web Content Analyzer",
    description="Reads URLs from web search results in state. Fetches and performs basic analysis (forms, scripts, comments, links) for each URL. Appends all analysis results to state['web_analysis_results']."
)

# --- Define Recon Aggregation Tool --- 
aggregation_tool = FunctionTool(
    func=aggregate_recon_data, 
    name="Recon Data Aggregator",
    description="Receives results dict from parallel recon tools, reads web analysis results from state, and aggregates them. Writes to state['aggregated_recon_data']."
    # Note: This tool now implicitly depends on web_analysis_results being in state.
)

# --- Define Recon Workflow Agent (Parallel) --- 
recon_workflow = Parallel(
    name="Reconnaissance Workflow",
    description="Executes Nmap, DNS/WHOIS, and Web Search in parallel.",
    agents=[
        nmap_tool, 
        dns_tool, 
        web_search_tool,
    ]
)

# --- Define Planning Agent (LLM-based) --- 

# Load the planning prompt 
planner_prompt_template = load_prompt("attack_planner_prompt.txt")

planning_agent = LlmAgent(
    name="Attack Planner Agent",
    description="Analyzes aggregated reconnaissance data using an LLM (Gemini) to generate a prioritized JSON attack plan.",
    model="gemini-1.5-flash-latest",
    instruction=planner_prompt_template,
    response_mime_type="application/json"
)

# --- Define Plan Validation Tool --- 
plan_validation_tool = FunctionTool(
    func=validate_attack_plan,
    name="Attack Plan Validator",
    description="Validates the JSON output from the planning agent and stores the clean plan in state."
)

# --- Define Report Summarization Tools & Agent ---
prepare_summary_input_tool = FunctionTool(
    func=prepare_summary_input,
    name="Prepare Summary Input Tool",
    description="Gathers required data from state and formats it as input for the summarizer agent. Stores input in state['summary_input']."
)

report_summarizer_agent = LlmAgent(
    name="Report Summarizer Agent",
    description="Analyzes the prepared assessment data (recon, plan, results) using an LLM (Gemini) to generate an executive summary and overall risk score in JSON format.",
    model="gemini-1.5-flash-latest",
    instruction=summarizer_prompt_template, # Use the loaded prompt
    # Input comes from the previous tool implicitly via ADK sequence
    # The prompt expects the input under the key 'summary_input', 
    # but ADK passes the whole dict from the previous step. 
    # We might need to adjust the prompt or add input mapping if this causes issues.
    response_mime_type="application/json"
)

store_summary_tool = FunctionTool(
    func=store_report_summary,
    name="Store Summary Tool",
    description="Validates the JSON output from the Report Summarizer Agent and stores the validated summary/risk in state['report_summary']."
)

# --- Define Exploit Tools (as before) --- 

web_exploit_tool = FunctionTool(
    func=run_web_exploits, 
    name="Web Exploit Executor",
    description="Reads attack plan from state. Attempts web exploits. Appends results to state['exploit_results']. (Simulation)"
)
sql_exploit_tool = FunctionTool(
    func=run_sql_exploits, 
    name="SQL Exploit Executor",
    description="Reads attack plan from state. Attempts SQL exploits (Default Creds, Version Vulns, Sqlmap Direct). Appends results to state['exploit_results'].",
)

ssh_exploit_tool = FunctionTool(
    func=run_ssh_exploits,
    name="SSH Exploit Executor",
    description="Reads attack plan from state. Attempts SSH exploits (Weak Creds, Version Vulns, Config Audit). Appends results to state['exploit_results']."
)

# --- Define Exploit Router Agent --- 

exploit_router = RouterAgent(
    name="Exploit Router",
    description="Checks the attack plan and routes to the appropriate exploit tool (Web, SQL, SSH, etc.).",
    routing_func=decide_next_exploit,
    route_mapping={
        "Web Exploit Executor": web_exploit_tool,
        "SQL Exploit Executor": sql_exploit_tool,
        "SSH Exploit Executor": ssh_exploit_tool,
    },
)

# --- Define Report Tool (as before) --- 

report_tool = FunctionTool(
    func=generate_final_report, 
    name="Report Generator",
    description="Reads all data (recon, plan, exploits) from state and generates final markdown report file."
)

# --- Define the Main Workflow Agent (Previously Root) --- 

main_workflow_agent = Sequential(
    name="PhantomRecon Workflow",
    description="Performs the full security assessment workflow: Parallel Recon -> Web Analysis -> Aggregate -> LLM Plan -> Validate -> Route Exploits -> Report. Requires 'initial_target' to be set in session state before starting. Should only be run AFTER the user provides a target via the Interaction Agent.",
    agents=[
        recon_workflow, 
        web_analysis_tool, 
        aggregation_tool, 
        planning_agent,
        plan_validation_tool, 
        exploit_router,
        prepare_summary_input_tool,
        report_summarizer_agent,
        store_summary_tool,
        report_tool
    ],
)

# --- Define the NEW Root Agent for User Interaction --- 
root_agent = LlmAgent(
    name="PhantomRecon Interaction Agent",
    description="Acts as the main user interface for PhantomRecon. Greets the user, asks for the target IP/website, uses StoreTargetTool to save it, and then delegates the actual security assessment to the PhantomRecon Workflow agent.",
    model="gemini-1.5-flash-latest",
    instruction="""You are the friendly user-facing agent for the PhantomRecon security tool.
1. Greet the user warmly.
2. Ask the user for the target IP address or website name they want to assess.
3. Once the user provides a target, *confirm* it with them (e.g., "Okay, I will assess target X. Is that correct?").
4. If the user confirms, use the `StoreTargetTool` to save the confirmed target. You MUST provide the target string as the 'target' argument to the tool.
5. After the `StoreTargetTool` confirms the target is stored successfully (its return message will indicate this), inform the user that the assessment workflow is now starting.
6. VERY IMPORTANT: Do NOT attempt to perform any reconnaissance, planning, or exploitation yourself. Your ONLY job related to the assessment is to get the target and store it using the tool. Once stored, the separate 'PhantomRecon Workflow' agent (which is a sub-agent) will automatically take over. 
7. If the user asks about progress *after* you have started the workflow, politely explain that the automated assessment is in progress and the final report will be generated upon completion.""",
    tools=[store_target_tool],
    sub_agents=[main_workflow_agent]
)

logger.info("PhantomRecon ADK Agent initialized for interactive web UI.")

# Next Steps:
# 1. Update recon logic functions (perform_nmap_scan, etc.) to accept ToolContext and read state['initial_target']
# 2. Implement Real SQL/SSH Exploits.
# 3. Implement Real Web Search.
# 4. Refine LLM Planner & Error Handling.
# 5. Testing.
