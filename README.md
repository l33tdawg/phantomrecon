# AI-RedTeam-Agent -> PhantomRecon

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
├── prompts/
│   └── attack_planner_prompt.txt # Prompt for the LLM planning agent
├── reports/
│   └── sample_report.md      # Example output report
├── requirements.txt          # Python dependencies (includes google-adk)
├── LICENSE                   # Project License
├── prd.md                    # Product Requirements Document
└── .env                      # Environment variables (ADK/Gemini API keys)
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

MIT License (Please add the actual license text to the LICENSE file)

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