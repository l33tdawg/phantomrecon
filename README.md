# PhantomRecon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PhantomRecon** is a CLI-based, modular, agent-driven red team automation tool designed to demonstrate autonomous offensive security workflows powered by AI (Google's Gemini via Agent Development Kit - ADK).

## Quick Start (CLI)

- Run interactive console (metasploit-style):
  ```bash
  python -m phantomrecon
  ```
- One-shot non-interactive run:
  ```bash
  python -m phantomrecon --target example.com --auto \
    --nmap-timeout 30 --nmap-top-ports 100 --nmap-args "-sV -Pn"
  ```

### CLI options
- `--target <domain|ip>`: Target to assess
- `--auto`: Run recon → plan → route → report
- `--nmap-timeout <seconds>`: Overrides `NMAP_TIMEOUT`
- `--nmap-top-ports <N>`: Overrides `NMAP_TOP_PORTS`
- `--nmap-args "..."`: Appends to Nmap args (`NMAP_ARGS`)
- `--nmap-disable`: Disable Nmap (sets `NMAP_DISABLE=1`)

Environment variables are also supported directly: `NMAP_TIMEOUT`, `NMAP_TOP_PORTS`, `NMAP_ARGS`, `NMAP_DISABLE`.

## Operational hygiene
- Reports are not versioned. `.gitignore` excludes `reports/*` except `reports/sample_report.md`.
- Generated HTML/MD reports live under `reports/` locally only.
- Remove or rotate reports as needed; they are never uploaded in commits.

Built as a proof-of-concept, it simulates identifying a target, performing broad reconnaissance (Nmap, DNS, Web Search), planning an attack strategy using an LLM, executing simulated exploits conditionally, and generating a report.

## Project Structure

```
phantomrecon/
├── phantomrecon/             # Main package (exported orchestrator agent)
│   ├── __init__.py
│   ├── __main__.py           # CLI entrypoint (interactive and non-interactive)
│   └── agent/                # Agent graph and tools
├── agents/                   # Python modules containing agent/tool logic
│   ├── recon_logic.py        # Nmap, DNS (dig), seeded web analysis; ADK search enabled
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
5.  Configure API Keys (env):
    *   Copy `.env.example` to `.env` (if example exists) or edit `.env`.
    *   Add your Google API Key (from AI Studio or Vertex AI setup) for the `GOOGLE_API_KEY` variable.
    *   Set `GOOGLE_GENAI_USE_VERTEXAI` to `True` or `False` and configure related variables (`GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`) if using Vertex AI.
6.  Run the tool:
    *   CLI interactive: `python -m phantomrecon`
    *   CLI one-shot: `python -m phantomrecon --target <target> --auto`
    *   ADK runner (optional): `adk run phantomrecon`

## Security Notice

This tool is for authorized security testing and educational purposes **only**. Do not use against systems without explicit permission.

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

## Architecture Notes (Current)

- Orchestrator agent (ADK `BuiltInPlanner`) selects specialized sub-agents: Validation → Recon → Planning → Exploitation → Reporting.
- State is read/written directly via `context.session.state` (no monkey patching or global cache wrappers).
- Recon improvements:
  - Env-configurable Nmap (`NMAP_TIMEOUT`, `NMAP_TOP_PORTS`, `NMAP_ARGS`, `NMAP_DISABLE`).
  - URL seeding for analysis when no search results; ADK `GoogleSearchTool` enabled for LLM-side search.
- Command execution uses `executor_fix.py` async helpers for robust timeouts and errors.

## Usage

Run via CLI (recommended):

```bash
python -m phantomrecon --target <domain|ip> --auto
```

Interactive console:

```bash
python -m phantomrecon
```

Optional ADK runner:

```bash
adk run phantomrecon -- --target <domain|ip> --auto
```