#!/usr/bin/env python3
# Direct import of ADK components
from google.adk.agents import Agent, LlmAgent, SequentialAgent, ParallelAgent, LoopAgent
from google.adk.planners import BuiltInPlanner
from google.genai import types as genai_types
from google.adk.tools import FunctionTool
from google.adk.tools.google_search_tool import GoogleSearchTool
from google.adk.tools.exit_loop_tool import exit_loop
import logging
import json
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Import logic functions using absolute paths
from phantomrecon.agents.validation_logic import validate_attack_plan # Keep if needed later
# Import necessary recon functions
from phantomrecon.agents.recon_logic import (
    perform_nmap_scan, 
    perform_dns_recon, 
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
# Import specialist agents
from phantomrecon.agents.specialist_agents import (
    web_security_agent,
    sql_injection_agent,
    ssh_network_agent,
    authentication_agent,
    api_security_agent,
    cloud_security_agent,
    cryptography_agent,
    cms_security_agent,
    container_security_agent,
    mobile_security_agent,
)
from phantomrecon.agents.audit_control_tools import aggregate_findings, should_continue_audit

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
   For example, if the user said "example.com", use that as the target directly.
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
        # Enable built-in Google Search within the model
        GoogleSearchTool(),
    ],
    output_key="recon_results", # Store the final summary/status
    description="Performs parallel reconnaissance on the target from state['initial_target']."
)

# 3. Planner Agent with comprehensive instructions
planner_agent = LlmAgent(
    name="PlannerAgent",
    model="gemini-1.5-flash-latest",
    instruction="""Your task is to analyze reconnaissance data and create an attack plan.
1. First, explicitly mention what you're doing: "PlannerAgent is analyzing reconnaissance data..."
2. **DO NOT ATTEMPT** to use Python functions like `locals()` or `print()` - these are not available to you.
3. Instead, look at the reconnaissance data and analyze it directly. You do not need to print or debug anything.
4. Create an attack plan by calling `simple_create_attack_plan()` - with NO parameters.
5. After the plan is created, briefly report that planning is complete.

IMPORTANT: DO NOT TRY TO DEBUG THE SYSTEM OR USE ANY PYTHON FUNCTIONS LIKE `locals()`, `print()`, etc. 
They will cause errors if attempted. Just analyze the data you have access to.
""",
    tools=[
        simple_create_attack_plan_tool,
    ],
    output_key="attack_plan", # Store the final plan
    description="Analyzes reconnaissance data and creates an attack plan."
)

# 4. Exploit Router Agent
exploit_agent = LlmAgent(
    name="ExploitAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an exploitation agent that executes specialized security testing modules to identify vulnerabilities.
    
    You have access to multiple specialized exploitation modules: web, ssh, and sql.
    
    Follow these steps:
    1. First, explicitly state: "ExploitAgent is starting exploitation phase."
    2. Get the target and attack plan from previous reconnaissance phase. The attack plan is created by analyzing the reconnaissance data.
    3. Use the simple_decide_next_exploit tool to determine which specific exploit modules to run.
       - The tool returns 'web' for web exploits, 'ssh' for SSH exploits, 'sql' for SQL exploits, or None if no exploits are recommended
       - When no exploits are recommended (None), inform the user that the exploitation phase is complete
    4. If specific exploits are recommended, call the corresponding run_X_exploits tool:
       - For 'web', call simple_run_web_exploits() with no parameters
       - For 'ssh', call simple_run_ssh_exploits() with no parameters
       - For 'sql', call simple_run_sql_exploits() with no parameters
    5. After each exploit run, call simple_decide_next_exploit again to determine if more exploits should be run
    6. Continue until no more exploits are recommended, then inform the user that exploitation is complete
    
    IMPORTANT NOTES:
    - If the attack plan was not properly formatted or no exploits are recommended, the router will return None
    - When the router returns None, report: "The attack plan does not contain any specific exploits to run. Therefore, no exploitation tools will be executed. Exploitation phase complete."
    - If any exploits are run successfully, report: "Exploitation phase is complete."
    
    Always call the exploit tool that matches exactly what the router returned. Do not try to guess or infer which exploit to run.
    """,
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

# --- Orchestrator (Agentic) setup ---
# Use ADK's BuiltInPlanner to dynamically select specialized sub-agents instead of fixed sequence
orchestrator_agent = LlmAgent(
    name="PhantomReconOrchestrator",
    model="gemini-1.5-pro-latest",  # Using Pro for better reasoning
    instruction="""You are a Senior Security Consultant and Red Team Lead conducting comprehensive security audits.

YOUR ROLE:
You are an autonomous penetration testing system. Given a target, you must conduct a FULL security audit 
by strategically coordinating specialized security agents.

AUTONOMOUS WORKFLOW:

1. INITIAL RECONNAISSANCE
   - First, ensure you have a valid target (invoke ValidationAgent if needed)
   - Invoke the ReconAgent to gather comprehensive intelligence
   - Analyze the attack surface: open ports, services, web technologies, etc.
   
2. STRATEGIC ANALYSIS
   - Based on recon findings, identify ALL potential vulnerability areas
   - Decide which specialist agents to invoke (you can invoke multiple in parallel)
   - Prioritize based on what's most likely to yield results
   
3. VULNERABILITY ASSESSMENT & EXPLOITATION
    - Invoke relevant specialist agents based on what was discovered:
     * Web application/HTTP services? → Invoke WebSecuritySpecialist
     * REST API or GraphQL detected? → Invoke APISecuritySpecialist
     * Database indicators detected? → Invoke SQLInjectionSpecialist  
     * SSH service open? → Invoke SSHNetworkSpecialist
     * Authentication mechanisms found? → Invoke AuthenticationSpecialist
     * Cloud-hosted (AWS/Azure/GCP)? → Invoke CloudSecuritySpecialist
     * HTTPS detected? → Invoke CryptographySpecialist
     * WordPress/Joomla/Drupal detected? → Invoke CMSSecuritySpecialist
     * Docker/Kubernetes detected? → Invoke ContainerSecuritySpecialist
     * Mobile app endpoints provided? → Invoke MobileSecuritySpecialist
   - You can invoke multiple specialists in parallel when appropriate
   - Analyze results from each agent
   - If vulnerabilities are found, document them and continue testing
   
4. ITERATION & DEEP DIVE
   - If you discover new attack vectors or entry points, DO NOT STOP
   - Gather additional intelligence if needed (invoke ReconAgent again)
   - Try alternative approaches if initial tests fail
   - Continue until you've thoroughly tested all discovered attack surfaces
   
5. COMPREHENSIVE REPORTING
   - Once audit is complete, invoke ReportAgent to generate findings
   - Ensure ALL vulnerabilities and attempts are documented

DECISION-MAKING PRINCIPLES:
- Think strategically like a real penetration tester
- Don't follow a rigid sequence - adapt based on what you find
- Invoke agents in parallel when possible for efficiency
- Be thorough: test every discovered service and endpoint
- Iterate: if new information is discovered, adjust your approach
- Document everything: successes and failures

IMPORTANT:
- You have FULL AUTONOMY to decide which agents to invoke and when
- There is NO fixed sequence - you decide the strategy
- You can invoke the same agent multiple times if needed
- Parallel invocation is encouraged when appropriate
- Stop only when you've completed a thorough security assessment""",
    global_instruction="""Maintain a professional, methodical approach.
- Always explain your strategic thinking before invoking agents
- Provide brief summaries after each agent completes
- Use clear, concise language
- Act decisively - don't ask for permission, take action""",
    sub_agents=[
        validation_agent,
        LoopAgent(
            name="AuditLoop",
            max_iterations=5,
            sub_agents=[
                recon_agent,
                ParallelAgent(
                    name="AssessmentParallel",
                    sub_agents=[
                        web_security_agent,
                        api_security_agent,
                        sql_injection_agent,
                        ssh_network_agent,
                        authentication_agent,
                        cloud_security_agent,
                        cryptography_agent,
                        cms_security_agent,
                        container_security_agent,
                        mobile_security_agent,
                    ],
                    description="Run specialist assessments in parallel"
                ),
                LlmAgent(
                    name="AggregateFindingsAgent",
                    model="gemini-1.5-flash-latest",
                    instruction="Use aggregate_findings to normalize and summarize results across specialists.",
                    tools=[FunctionTool(func=aggregate_findings)],
                    output_key="audit_aggregate"
                ),
                LlmAgent(
                    name="ContinueDecisionAgent",
                    model="gemini-1.5-flash-latest",
                    instruction=(
                        "First call should_continue_audit to decide if another iteration is needed. "
                        "If the tool returns continue=false, immediately call exit_loop() to stop this loop."
                    ),
                    tools=[FunctionTool(func=should_continue_audit), FunctionTool(func=exit_loop)],
                    output_key="audit_continue_decision"
                ),
            ],
            description="Iterate recon + parallel assessment until stop criteria"
        ),
        report_agent,
    ],
    planner=BuiltInPlanner(
        thinking_config=genai_types.ThinkingConfig(
            include_thoughts=True, 
            thinking_budget=-1  # Unlimited thinking for complex strategic decisions
        )
    ),
    description="Autonomous Senior Security Consultant that conducts comprehensive penetration tests"
)

# Export orchestrator as the primary ADK entrypoint
agent = orchestrator_agent

logger.info("PhantomRecon Orchestrator initialized with BuiltInPlanner.")
