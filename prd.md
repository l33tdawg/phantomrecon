## 1. 📌 Overview

**PhantomRecon** is a CLI-based, modular, agent-driven red team automation tool designed to demonstrate the potential of autonomous offensive security workflows powered by AI. The tool simulates a real-world red team operation by autonomously:

- Identifying a target,
- Scanning it for open ports/services,
- Planning an attack strategy,
- Executing exploits on known vulnerabilities, and
- Generating a human-readable report.

The tool is being developed as a live keynote demo for Astana University and will be released as an open-source proof-of-concept to inspire research and future development in agentic offensive AI.

---

## 2. 🎯 Goals & Objectives

### 2.1 Goals

- Build a working proof-of-concept that realistically simulates a red team workflow.
- Showcase agentic reasoning, delegation, and coordination.
- Inspire students and researchers to explore offensive AI.
- Provide a modular foundation for future development.

### 2.2 Non-Goals

- Evade detection or bypass advanced defensive systems.
- Achieve zero-day or novel exploit development.
- Provide enterprise-grade red team automation (yet).

---

## 3. 🧩 Key Features

| Component        | Function                                                                 | ADK Implementation Idea |
|------------------|--------------------------------------------------------------------------|-------------------------|
| **Recon Workflow** | Performs Nmap, DNS/WHOIS, Web Search recon in parallel.                | `Parallel` Agent (`recon_workflow`) containing `FunctionTool`s (nmap, dns, web_search) |
| **Recon Aggregation**| Combines parallel recon results into a single structure.               | `FunctionTool` (`aggregation_tool`) |
| **Planning Agent** | Analyzes aggregated recon data using Gemini via ADK to propose attack plan (JSON). | `LlmAgent` (`planning_agent`) with custom prompt |
| **Exploit Router** | Reads plan from state and conditionally runs appropriate exploit tools. | `RouterAgent` (`exploit_router`) using custom routing logic |
| **Exploit Tools**  | Executes specific checks/exploits (Web, SQL) based on plan. (Simulated) | `FunctionTool`s (`web_exploit_tool`, `sql_exploit_tool`) using session state |
| **Report Tool**    | Generates Markdown report using all data from session state.             | `FunctionTool` (`report_tool`) using session state |
| **CLI Interface**  | Simple execution via ADK CLI.                                          | `adk run phantomrecon -- --target <host>`, `adk web` |

---

## 5. 🔐 Ethical Scope

This tool is intended strictly for **educational and research purposes**. It is designed to interact only with:

- Public demo targets (e.g., `scanme.nmap.org`)
- Self-hosted intentionally vulnerable applications (e.g., OWASP Juice Shop deployed on Vercel)

**Important:**
- No unauthorized scanning, exploitation, or intrusion of real-world assets is allowed.
- The tool will include:
  - A clear warning banner at runtime.
  - A license and README explicitly stating the ethical usage policy.

---

## 6. 🧱 Tech Stack

| Layer             | Tech                                                 | Notes |
|-------------------|------------------------------------------------------|-------|
| Language          | Python 3.x                                           |       |
| Agent Framework   | Google Agent Development Kit (ADK)                   | Core orchestration, state, LLM integration |
| CLI Interface     | ADK CLI (`adk run`, `adk web`)                       | Provided by ADK |
| LLM               | Google Gemini (via ADK `LlmAgent`)                    | For planning |
| Recon Tools       | `nmap` (via `python-nmap`), `dig`, `whois` (via `subprocess`) | Wrapped as ADK `FunctionTool`s |
| Exploitation      | `requests`, `mysql-connector-python` (logic simulated) | Wrapped as ADK `FunctionTool`s |
| Reporting         | Markdown output via `markdown2`                      | Wrapped as an ADK `FunctionTool` |
| State Management  | ADK Session State (`ToolContext.session.state`)       | For passing data between agents/tools |
| Hosting Target    | Vercel-hosted OWASP Juice Shop                       | Test target |

---

## 7. 🧪 Test Plan

The tool will be tested in the following ways:

- ✅ **Agent-Level Unit Testing**  
  Each agent (recon, planner, exploit, report) will be tested independently.

- ✅ **End-to-End Integration Testing**  
  Simulate full chain: scan → plan → exploit → report.

- ✅ **Demo Scenario Test**  
  Scan `scanme.nmap.org`, plan HTTP exploit, run SQLi against Juice Shop, confirm expected behavior.

- ✅ **CLI UX Testing**  
  Check invalid inputs, missing arguments, malformed configs.

- ✅ **Fail-Safe Testing**  
  Ensure no actual exploits or scans are run against unintended targets.

---

## 8. 📂 Deliverables

```plaintext
phantomrecon/
├── phantomrecon/             # Main ADK agent module
│   ├── __init__.py
│   └── agent.py              # Defines root agent, sub-agents (Parallel, LlmAgent, Router), tools
├── agents/                   # Python modules containing agent/tool logic
│   ├── recon_logic.py        # Nmap, DNS, Web Search functions
│   ├── routing_logic.py      # Exploit router function
│   ├── exploit_web_logic.py  # Web exploit functions (simulated)
│   ├── exploit_sql_logic.py  # SQL exploit functions (simulated)
│   └── report_logic.py       # Report generation function
├── configs/
│   └── targets.json
├── data/
│   └── dummy_scan_output.json
├── demos/
│   └── walkthrough.md
├── prompts/
│   └── attack_planner_prompt.txt # Prompt for LLM planner
├── reports/
│   └── sample_report.md
├── requirements.txt          # Includes google-adk
├── LICENSE
├── prd.md
└── .env                      # ADK/Gemini environment variables
``` 