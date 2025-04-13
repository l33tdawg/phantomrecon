#!/usr/bin/env python3
# Apply monkey patch for session persistence FIRST before other imports
from phantomrecon.session_fix import apply_monkey_patch
# Apply the patch immediately to ensure all agent runs have persistence
apply_monkey_patch()

# Now import the rest
import os
from dotenv import load_dotenv
from google.adk.agents import Agent, LlmAgent, SequentialAgent
from google.adk.tools import FunctionTool
import logging
import json
from typing import Optional, Dict, Any

# Import logic functions using absolute paths
from phantomrecon.agents.validation_logic import validate_attack_plan # Keep if needed later
# Import necessary recon functions
from phantomrecon.agents.recon_logic import (
    perform_nmap_scan, 
    perform_dns_recon, 
    perform_web_search, 
    perform_parallel_recon
)
# Import planning logic
from phantomrecon.agents.planner_logic import simple_create_attack_plan
# Import routing logic
from phantomrecon.agents.routing_logic import simple_decide_next_exploit
# Import exploit functions
from phantomrecon.agents.exploit_web_logic import simple_run_web_exploits
from phantomrecon.agents.exploit_sql_logic import simple_run_sql_exploits
from phantomrecon.agents.exploit_ssh_logic import simple_run_ssh_exploits
# Import reporting functions
from phantomrecon.agents.report_logic import simple_generate_final_report

# Load environment variables relative to project root
project_root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(dotenv_path=os.path.join(project_root_dir, '.env'))

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Prompt Loading ---
def load_prompt(filename: str) -> str:
    prompt_path = os.path.join(project_root_dir, 'prompts', filename)
    try:
        with open(prompt_path, 'r') as f: return f.read()
    except Exception as e:
        logger.error(f"Error loading prompt {prompt_path}: {e}")
        return f"ERROR: Could not load prompt - {e}"

# --- Recon Tools ---
# Individual tool definitions
perform_nmap_scan_tool = FunctionTool(func=perform_nmap_scan)
perform_dns_recon_tool = FunctionTool(func=perform_dns_recon)
perform_web_search_tool = FunctionTool(func=perform_web_search)
# New parallel recon tool that runs all recon methods at once
perform_parallel_recon_tool = FunctionTool(func=perform_parallel_recon)

# --- Planning Tools ---
simple_create_attack_plan_tool = FunctionTool(func=simple_create_attack_plan)

# --- Exploit Tools ---
simple_run_web_exploits_tool = FunctionTool(func=simple_run_web_exploits)
simple_run_sql_exploits_tool = FunctionTool(func=simple_run_sql_exploits)
simple_run_ssh_exploits_tool = FunctionTool(func=simple_run_ssh_exploits)

# --- Routing Tools ---
simple_decide_next_exploit_tool = FunctionTool(func=simple_decide_next_exploit)

# --- Reporting Tools ---
simple_generate_final_report_tool = FunctionTool(func=simple_generate_final_report)

# --- Agent Definitions ---

# 1. Validation Agent - LLM that directly stores the target in state
validation_agent = LlmAgent(
    name="ValidationAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are a target validation agent for a security reconnaissance system.
1. Ask the user for a target domain or IP address to analyze.
2. Once they provide a target, validate that it looks like a domain or IP address.
3. When the user provides a valid target, store it directly in session state using:
   context.session.state['initial_target'] = user_input
4. After storing the target, tell the user: "Target '[target]' confirmed and stored. Validation complete. Handing over to Reconnaissance Agent..."
5. If the user provides an invalid target, ask them to provide a proper domain or IP address.

Example conversation flow:
User: example.com
You: [Store example.com in session state]
You: "Target 'example.com' confirmed and stored. Validation complete. Handing over to Reconnaissance Agent..."
""",
    output_key="validation_result",
    description="Validates the target domain/IP and stores it in session state."
)

# 2. Reconnaissance Agent with updated instructions and parallel recon tool
recon_agent = LlmAgent(
    name="ReconAgent",
    model="gemini-1.5-flash-latest",
    instruction="""Your task is to perform reconnaissance on the target provided in the session state key 'initial_target'.
1. First, explicitly mention the target you found in the session state. For example: "Starting reconnaissance on target: example.com" 
2. IMPORTANT: If you can't find a target in the session state, look at the user's most recent message to infer the target.
   For example, if the user said "hitb.org", use that as the target directly.
3. Use the perform_parallel_recon tool to run all reconnaissance methods (nmap, dns, web search) concurrently.
   This tool automatically runs everything in parallel and combines the results.
4. When calling the tool, ALWAYS explicitly pass the target as a parameter to ensure it receives the correct value:
   perform_parallel_recon(direct_target_override="the_target")
5. After the tool completes, briefly summarize what was found from each method. Even if some methods failed, others may have succeeded.
6. **Do not perform planning or exploitation.** Your only job is reconnaissance.""",
    tools=[
        # Primary tool for parallel execution
        perform_parallel_recon_tool,
        # Keep individual tools as fallbacks
        perform_nmap_scan_tool,
        perform_dns_recon_tool,
        perform_web_search_tool,
    ],
    output_key="recon_results", # Store the final summary/status
    description="Performs parallel reconnaissance on the target from state['initial_target']."
)

# 3. Planner Agent
planner_agent = LlmAgent(
    name="PlannerAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an attack planner analyzing reconnaissance results. Your job is to:
1. Examine the reconnaissance data in the session state under the 'recon' key
2. Identify potential vulnerabilities and attack vectors based on the findings
3. Generate a prioritized attack plan
4. Use the simple_create_attack_plan tool to create a structured plan
5. Be thorough and methodical in your analysis

When calling the simple_create_attack_plan tool, you don't need to provide any parameters - it will automatically access the session state.""",
    tools=[simple_create_attack_plan_tool],
    output_key="planning_results",
    description="Analyzes recon data and generates an attack plan"
)

# 4. Exploit Router Agent
exploit_agent = LlmAgent(
    name="ExploitAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an exploitation agent that determines which exploits to run based on the attack plan.
1. Examine the attack plan generated by the planner
2. Use the simple_decide_next_exploit tool to determine which specific exploit modules to run
3. For each recommended exploit, run the appropriate exploit tool (simple_run_web_exploits, simple_run_sql_exploits, simple_run_ssh_exploits)
4. Report the results of each exploitation attempt
5. Be cautious and thorough in your exploitation approach

Remember that all exploits are simulated - no actual systems will be compromised.""",
    tools=[
        simple_decide_next_exploit_tool,
        simple_run_web_exploits_tool,
        simple_run_sql_exploits_tool,
        simple_run_ssh_exploits_tool
    ],
    output_key="exploit_results",
    description="Routes and executes appropriate exploit modules based on the attack plan"
)

# 5. Report Agent
report_agent = LlmAgent(
    name="ReportAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are a security report generator. Your job is to:
1. Examine all data from previous stages (reconnaissance, planning, exploitation)
2. Use the simple_generate_final_report tool to create a comprehensive security report
3. Ensure the report includes all findings, vulnerabilities, and recommendations
4. Be clear, concise, and professional in your reporting style

The report should be suitable for both technical and non-technical stakeholders.""",
    tools=[simple_generate_final_report_tool],
    output_key="final_report",
    description="Generates a comprehensive security report based on all findings"
)

# --- Sequential Agent Definition ---
sequential_pipeline = SequentialAgent(
    name="PhantomReconPipeline",
    sub_agents=[
        validation_agent,  # LlmAgent for validation
        recon_agent,       # Reconnaissance agent
        planner_agent,     # Planning agent
        exploit_agent,     # Exploitation agent
        report_agent       # Reporting agent
    ],
    description="Orchestrates the complete PhantomRecon workflow: Validate -> Recon -> Plan -> Exploit -> Report"
)

# --- Assign to 'agent' variable for adk run ---
agent = sequential_pipeline

logger.info("PhantomRecon Sequential Agent Pipeline initialized in __init__.py.")
