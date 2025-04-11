#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from google.adk.agents import Agent, LlmAgent, Sequential, Parallel, RouterAgent
from google.adk.tools import FunctionTool
import logging
import json
from typing import Optional, Dict, Any

# Import the logic functions 
from agents.recon_logic import (
    perform_nmap_scan, 
    perform_dns_recon, 
    perform_web_search, 
    aggregate_recon_data
)
from agents.exploit_web_logic import run_web_exploits
from agents.exploit_sql_logic import run_sql_exploits
from agents.report_logic import generate_final_report
from agents.routing_logic import decide_next_exploit

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

# --- Define Recon Tools --- 

nmap_tool = FunctionTool(
    func=perform_nmap_scan, 
    name="Nmap Port Scanner",
    description="Performs Nmap scan. Reads initial target from state if needed. Writes results to state['nmap_results']."
)

dns_tool = FunctionTool(
    func=perform_dns_recon, 
    name="DNS/WHOIS Recon",
    description="Performs DNS/WHOIS lookups. Reads initial target from state if needed. Writes results to state['dns_results']. Requires dig/whois."
)

web_search_tool = FunctionTool(
    func=perform_web_search, 
    name="Web Search Simulator",
    description="Simulates web search. Reads initial target from state if needed. Writes results to state['web_search_results']."
)

aggregation_tool = FunctionTool(
    func=aggregate_recon_data, 
    name="Recon Data Aggregator",
    description="Receives results dict from parallel recon tools and aggregates them. Writes to state['aggregated_recon_data']."
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

# --- Define Exploit Tools (as before) --- 

web_exploit_tool = FunctionTool(
    func=run_web_exploits, 
    name="Web Exploit Executor",
    description="Reads attack plan from state. Attempts web exploits. Appends results to state['exploit_results']. (Simulation)"
)
sql_exploit_tool = FunctionTool(
    func=run_sql_exploits, 
    name="SQL Exploit Executor",
    description="Reads attack plan from state. Attempts SQL exploits. Appends results to state['exploit_results']. (Simulation)"
)

# --- Define Exploit Router Agent --- 

exploit_router = RouterAgent(
    name="Exploit Router",
    description="Checks the attack plan and routes to the appropriate exploit tool (Web, SQL, etc.).",
    routing_func=decide_next_exploit,
    route_mapping={
        "Web Exploit Executor": web_exploit_tool,
        "SQL Exploit Executor": sql_exploit_tool,
    },
)

# --- Define Report Tool (as before) --- 

report_tool = FunctionTool(
    func=generate_final_report, 
    name="Report Generator",
    description="Reads all data (recon, plan, exploits) from state and generates final markdown report file."
)

# --- Define the Main Orchestrator Agent --- 

root_agent = Sequential(
    name="PhantomRecon Orchestrator",
    description="Executes a simulated red team workflow using parallel recon, LLM planning, and routed exploitation.",
    agents=[
        recon_workflow, 
        aggregation_tool, 
        planning_agent,
        exploit_router,
        report_tool
    ],
)

logger.info("PhantomRecon ADK Agent with Routing Logic initialized.")

# Next Steps:
# 1. Implement real web analysis/exploit logic.
# 2. Refine LLM Planner: Improve prompt, handle potential JSON errors from LLM.
# 3. Add More Tools: Incorporate tools like Metasploit, Subfinder, httpx, nuclei.
# 4. Error Handling: Improve robustness throughout the workflow.
# 5. Testing: Thoroughly test the workflow with ADK CLI (`adk run phantomrecon -- --target <domain>`).
