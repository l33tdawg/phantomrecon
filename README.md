PhantomRecon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PhantomRecon** is a CLI-based, modular, agent-driven red team automation tool designed to demonstrate autonomous offensive security workflows powered by AI (Google's Gemini via Agent Development Kit - ADK).

Built as a proof-of-concept, it simulates identifying a target, performing broad reconnaissance (Nmap, DNS, Web Search), planning an attack strategy using an LLM, executing simulated exploits conditionally, and generating a report.

## Project Structure

```
phantomrecon/
├── phantomrecon/             # Main ADK agent module
│   ├── __init__.py
│   └── agent.py              # Defines the root Sequential agent, sub-agents (Parallel Recon, LLM Planner, Router), and tools.
├── agents/                   # Python modules containing agent/tool logic
│   ├── recon_logic.py        # Functions for Nmap, DNS (dig, whois), Web Search (simulated)
│   ├── routing_logic.py      # Logic for the Exploit Router agent
│   ├── exploit_web_logic.py  # Functions for web exploits (currently simulated)
│   ├── exploit_sql_logic.py  # Functions for SQL exploits (currently simulated)
│   └── report_logic.py       # Functions for report generation using session state
├── configs/
│   └── targets.json          # (Optional) Target configuration
├── data/
│   └── dummy_scan_output.json # Example Nmap data if no target specified
├── demos/
│   └── walkthrough.md        # Demo steps
├── prompts/                  # Prompt templates for LLM agents
├── reports/
│   └── sample_report.md      # Example output report
├── requirements.txt          # Python dependencies (includes google-adk)
├── .gitignore                # Files excluded from version control
└── LICENSE                   # MIT License
```

## Current Workflow

1.  **Parallel Reconnaissance (`recon_workflow` - Parallel Agent):**
    *   Runs Nmap Scan (`nmap_tool`)
    *   Runs DNS/WHOIS lookups (`dns_tool`)
    *   Simulates Web Search (`web_search_tool`)
    *   *State:* Each tool writes its results to the session state.
2.  **Aggregation (`aggregation_tool`):**
    *   Combines results from the parallel workflow.
    *   *State:* Writes `aggregated_recon_data` to session state.
3.  **LLM Planning (`planning_agent` - LlmAgent):**
    *   Receives aggregated data.
    *   Uses Gemini and `attack_planner_prompt.txt` to generate a JSON attack plan.
    *   *State:* Writes `attack_plan` to session state.
4.  **Exploit Routing (`exploit_router` - RouterAgent):**
    *   Reads `attack_plan` from state.
    *   Conditionally executes specific exploit tools (`web_exploit_tool`, `sql_exploit_tool`) based on the plan.
    *   *State:* Exploit tools append results to `exploit_results` list in session state.
5.  **Reporting (`report_tool`):**
    *   Reads all relevant data (recon, plan, results) from session state.
    *   Generates a final Markdown report file.

## Setup

1.  Clone the repository.
2.  Ensure prerequisites are installed: `python3`, `pip`, `nmap`, `dig`, `whois`, `sqlmap`, `wapiti`, `wpscan`, `searchsploit`.
3.  Create a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
4.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
5.  Configure API Keys:
    *   Copy `.env.example` to `.env` (if example exists) or edit `.env`.
    *   Add your Google API Key (from AI Studio or Vertex AI setup) for the `GOOGLE_API_KEY` variable.
    *   Set `GOOGLE_GENAI_USE_VERTEXAI` to `True` or `False` and configure related variables (`GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`) if using Vertex AI.
6.  Run the agent using the ADK CLI:
    *   For a specific target: `adk run phantomrecon -- --target <your_target_domain_or_ip>`
    *   Using dummy data (if no target in `.env`): `adk run phantomrecon`
    *   Using the web UI: `adk web` (then select `phantomrecon` agent)

## Security Notice

This tool is for authorized security testing and educational purposes **only**. Do not use against systems without explicit permission. The exploit modules are currently simulations but are intended to be replaced with real checks.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Prerequisites

*   Python 3.9+
*   pip (Python package installer)
*   Nmap (`sudo apt install nmap` or `brew install nmap`)
*   dig (`sudo apt install dnsutils` or `brew install bind`)
*   whois (`sudo apt install whois` or `brew install whois`)
*   sqlmap (`sudo apt install sqlmap` or `brew install sqlmap`)
*   wapiti (`sudo apt install wapiti` or `brew install wapiti`)
*   wpscan (`sudo apt install ruby-full` then `gem install wpscan` or `brew install wpscan`)
*   searchsploit (`sudo apt install exploitdb` or `brew install exploitdb`)
*   A Google Cloud Project with the Gemini API enabled.
*   An API Key for the Gemini API.
*   Python libraries listed in `requirements.txt` (install via `pip install -r requirements.txt`)

### Key Features

*   **Agent-Based Workflow:** Utilizes Google's Agent Development Kit (ADK) for a modular structure.
*   **Interactive Target Input:** Uses `adk web` interface to ask the user for the target IP/domain.
*   **Multi-Stage Assessment:**
    *   **Reconnaissance:**
        *   Nmap port scanning (Real)
        *   Enhanced DNS/WHOIS lookups (Real: `dig`, `nslookup`, `dig +trace`, AXFR attempt, `whois`)
        *   Web Search (Real, using Google Search)
        *   Enhanced Web Content Analysis (Real: links, forms, comments, scripts, headers, emails, basic tech detection)
        *   Data Aggregation
    *   **Planning:** LLM (Gemini) analyzes recon data to generate a prioritized attack plan (with validation).
    *   **Exploitation (Conditional Routing):** Executes tests based on the plan:
        *   **Web:** Default files, Misconfigurations (Dir Listing), SQL Injection (via `sqlmap` with refined options), Wapiti scan (parsed results), WPScan (parsed results, conditional), Basic Reflected XSS, Basic Command Injection - (Real Checks)
        *   **SQL:** Default Credentials (MySQL/PostgreSQL), Version Vulnerabilities (via `searchsploit` with refined query), Post-Auth Enumeration (via `sqlmap` direct connect) - (Real Checks)
        *   **SSH:** Weak Credentials, Version Vulnerabilities (via `searchsploit` with refined query), Configuration Audit (via `ssh-audit`, parsed results) - (Real Checks)
    *   **Reporting:** Generates a Markdown summary report.
*   **State Management:** Uses ADK's `ToolContext` to pass data between agents/tools.

## Session State Persistence Fix

This repo includes fixes for session state persistence issues in the Google ADK framework. The problem was that session state was not being properly carried over between agent runs in a sequential pipeline.

### Main Issues Fixed:

1. **Session State Persistence**: The `initial_target` value set by the ValidationAgent was not available in the ReconAgent, causing it to fail.
   - Solution: We created a `SessionStateWrapper` in `session_fix.py` that maintains a global state cache and intercepts all state operations.

2. **Command Execution**: The `UnsafeLocalCodeExecutor.execute()` method was missing, as the correct method is `execute_code()`.
   - Solution: We implemented a custom `CommandExecutor` in `executor_fix.py` that properly handles command execution using asyncio.

3. **Google Search Tool**: The GoogleSearchTool's API changed and needed to use `run_async()` instead of `run()`.
   - Solution: We updated the code to use the correct method.

4. **ADK Compatibility Fixes**: Fixed several incompatibilities with the latest ADK version:
   - Created simplified wrapper functions for all tools to address ADK's automatic function calling limitations
   - Enhanced the agent pipeline to include all stages: Validation, Recon, Planning, Exploitation, and Reporting
   - Fixed context variable initialization issues in the parallel recon function
   - SSH-audit tool now parses JSON output to extract structured findings (weak algorithms, recommendations) 
   - Better handling of tool outputs throughout the pipeline

5. **Refined Tool Output Parsing**: 
   - SSH-audit tool now parses JSON output to extract structured findings (weak algorithms, recommendations) 
   - Better handling of tool outputs throughout the pipeline

## How the Fix Works

1. We use monkey patching in `session_fix.py` to intercept all agent runs and wrap the session state.
2. The wrapper duplicates all state operations to a global cache, ensuring persistence.
3. For command execution, we use a custom implementation that doesn't rely on the UnsafeLocalCodeExecutor.
4. Better error handling for session state access across all agents was added.

## ADK Compatibility Fixes

The application encountered several issues with the latest version of Google's Agent Development Kit (ADK):

1. **Function Calling Changes**: ADK's function calling behavior changed, requiring adaptations to our tools:
   - Created simplified wrapper functions with consistent signatures
   - Added type annotations to all tool parameters
   - Implemented better error handling for tool execution

2. **Session Persistence**: ADK's session state management required several modifications:
   - Implemented global cache for session variables
   - Added state verification between agent transitions
   - Fixed session variable initialization in parallel workflows

3. **Agent Communication**: Enhanced inter-agent communication:
   - Standardized output formats from all tools
   - Improved parsing of structured data from external tool outputs
   - Added validation checks for data passed between agents

For more details, see the [README-ADK-FIXES.md](README-ADK-FIXES.md) file.

## Usage

Simply run the application as normal with:

```bash
adk run phantomrecon
```

The fix is applied automatically at startup in the `__init__.py` file.

## Testing the Fix

You can test just the session state functionality with:

```bash
adk run phantomrecon.session_test
```

This runs a test pipeline that sets and retrieves a value from session state. 