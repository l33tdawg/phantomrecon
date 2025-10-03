# PhantomRecon Autonomous Architecture

## Vision
Transform PhantomRecon into a fully autonomous agentic red team system that mimics a senior security consultant/penetration tester. Given only a target, the system should:
- Autonomously decide what reconnaissance to perform
- Iteratively discover and analyze vulnerabilities
- Dynamically plan and execute attacks
- Adapt strategy based on findings
- Complete a comprehensive security audit

## Core Principles
1. **True Autonomy**: Orchestrator makes all decisions about which agents to invoke
2. **Specialization**: Each agent is an expert in a specific domain (SQLi, XSS, SSH, etc.)
3. **Iteration**: System can loop back to gather more intel or try different approaches
4. **ADK-Native**: Leverage ADK's agent capabilities fully, don't reinvent the wheel
5. **Adaptive**: Strategy changes based on what's discovered

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Senior Orchestrator Agent                  │
│  (Gemini 2.0 Flash Thinking / Pro - Full Autonomy)          │
│                                                              │
│  Role: Senior Security Consultant / Red Team Lead           │
│  - Receives target, plans full audit strategy               │
│  - Dynamically selects which agents to invoke               │
│  - Iterates based on findings                               │
│  - Coordinates specialized agents                           │
│  - Makes strategic decisions                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Delegates to specialized agents
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Specialized Agent Team                    │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Reconnaissance   │  │  Web Security    │  │  SQL Injection   │
│     Agent        │  │      Agent       │  │      Agent       │
│                  │  │                  │  │                  │
│ Tools:           │  │ Tools:           │  │ Tools:           │
│ - NMAP scan      │  │ - XSS detection  │  │ - SQLi detection │
│ - DNS recon      │  │ - CSRF check     │  │ - Blind SQLi     │
│ - Port analysis  │  │ - Path traversal │  │ - Union attacks  │
│ - Service enum   │  │ - Open redirect  │  │ - Time-based     │
│ - Web crawling   │  │ - SSRF detection │  │ - Error-based    │
└──────────────────┘  └──────────────────┘  └──────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  SSH/Network     │  │   Authentication │  │    Reporting     │
│     Agent        │  │      Agent       │  │      Agent       │
│                  │  │                  │  │                  │
│ Tools:           │  │ Tools:           │  │ Tools:           │
│ - SSH audit      │  │ - Weak passwords │  │ - Vuln summary   │
│ - Default creds  │  │ - Session hijack │  │ - Risk analysis  │
│ - Config checks  │  │ - Token analysis │  │ - Remediation    │
│ - Vuln scanning  │  │ - Auth bypass    │  │ - Timeline       │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

---

## Agent Specifications

### 1. Senior Orchestrator Agent
**Model**: `gemini-2.0-flash-thinking-exp` or `gemini-1.5-pro-latest`

**System Instruction**:
```
You are a Senior Security Consultant and Red Team Lead conducting a comprehensive 
security audit. Given a target, you must:

1. RECONNAISSANCE PHASE
   - Invoke the Reconnaissance Agent to gather initial intelligence
   - Analyze results to understand the attack surface
   - Decide if additional recon is needed

2. VULNERABILITY ASSESSMENT
   - Based on recon findings, identify potential vulnerability areas
   - Determine which specialist agents to invoke (Web, SQLi, SSH, Auth, etc.)
   - Invoke multiple agents in parallel when appropriate

3. EXPLOITATION PHASE
   - For each identified vulnerability, invoke the appropriate specialist agent
   - Analyze results to determine if exploitation was successful
   - Adapt strategy based on what's discovered

4. ITERATION
   - If new attack vectors are discovered, loop back to gather more intel
   - Try alternative approaches if initial attempts fail
   - Continue until a comprehensive audit is complete

5. REPORTING
   - Invoke the Reporting Agent to generate comprehensive findings
   - Ensure all vulnerabilities, attempts, and recommendations are documented

IMPORTANT: 
- You make ALL strategic decisions autonomously
- Invoke agents based on findings, not a fixed sequence
- Iterate and adapt your approach
- Think like a real penetration tester
- Be thorough but efficient
```

**Sub-Agents**: All specialist agents below
**Planner**: `BuiltInPlanner` with extended thinking

---

### 2. Reconnaissance Agent
**Model**: `gemini-1.5-flash-latest`

**Specialization**: Information gathering and attack surface mapping

**Tools**:
- `perform_nmap_scan` - Network port scanning
- `perform_dns_recon` - DNS enumeration and subdomain discovery  
- `analyze_web_content` - Web crawling and technology detection
- `enumerate_services` - Service version detection and fingerprinting
- `check_security_headers` - HTTP security header analysis
- `GoogleSearchTool` - OSINT gathering

**Output**: Comprehensive intelligence about target including:
- Open ports and services
- Web technologies used
- Potential entry points
- DNS records and subdomains
- Security posture indicators

---

### 3. Web Security Agent  
**Model**: `gemini-1.5-flash-latest`

**Specialization**: Web application vulnerabilities (XSS, CSRF, SSRF, etc.)

**Tools**:
- `test_xss_vulnerabilities` - Reflected, stored, DOM-based XSS
- `test_csrf_protection` - CSRF token validation
- `test_path_traversal` - Directory traversal attempts
- `test_open_redirect` - Open redirect detection
- `test_ssrf` - Server-side request forgery
- `test_file_upload` - File upload vulnerabilities
- `scan_sensitive_files` - Common sensitive file discovery

**Output**: Web vulnerability findings with:
- Vulnerability type and severity
- Affected endpoints
- Proof of concept
- Remediation recommendations

---

### 4. SQL Injection Agent
**Model**: `gemini-1.5-flash-latest`

**Specialization**: Database injection attacks

**Tools**:
- `test_sqli_basic` - Basic SQL injection detection
- `test_sqli_blind` - Boolean-based blind SQLi
- `test_sqli_time` - Time-based blind SQLi
- `test_sqli_union` - UNION-based injection
- `test_sqli_error` - Error-based injection
- `extract_database_info` - Database enumeration

**Output**: SQLi vulnerability findings with:
- Injection points
- Database type
- Exploitability assessment
- Data extraction possibilities

---

### 5. SSH/Network Agent
**Model**: `gemini-1.5-flash-latest`

**Specialization**: SSH and network service security

**Tools**:
- `audit_ssh_config` - SSH configuration analysis
- `test_default_credentials` - Default/weak credential testing
- `check_ssh_vulnerabilities` - Known SSH vulnerability scanning
- `test_network_services` - Network service enumeration and testing

**Output**: Network security findings

---

### 6. Authentication Agent
**Model**: `gemini-1.5-flash-latest`

**Specialization**: Authentication and session management

**Tools**:
- `test_weak_passwords` - Password strength testing
- `test_session_management` - Session handling analysis
- `test_auth_bypass` - Authentication bypass techniques
- `analyze_tokens` - JWT/token security analysis

**Output**: Authentication vulnerability findings

---

### 7. Reporting Agent
**Model**: `gemini-1.5-flash-latest`

**Specialization**: Comprehensive security report generation

**Tools**:
- `generate_vulnerability_report` - Full vulnerability documentation
- `calculate_risk_scores` - CVSS-based risk assessment
- `generate_timeline` - Attack timeline and sequence
- `generate_remediation_plan` - Prioritized remediation recommendations

**Output**: Professional security audit report

---

## Implementation Phases

### Phase 1: Orchestrator Enhancement ✓
- [x] Upgrade orchestrator instruction for true autonomy
- [x] Enable iterative decision-making
- [x] Add thinking/reasoning capabilities

### Phase 2: Specialist Agent Creation
- [ ] Convert existing exploit functions to full agents
- [ ] Create Web Security Agent with comprehensive tools
- [ ] Create SQL Injection Agent with advanced techniques
- [ ] Create SSH/Network Agent
- [ ] Create Authentication Agent

### Phase 3: Tool Enhancement
- [ ] Expand each tool with more comprehensive checks
- [ ] Add result validation and accuracy scoring
- [ ] Implement proper error handling and retries

### Phase 4: Iteration & Adaptation
- [ ] Enable orchestrator to loop back for more recon
- [ ] Add learning from failed attempts
- [ ] Implement alternative strategy selection

### Phase 5: CLI Simplification
- [ ] Single command: `phantomrecon --target example.com`
- [ ] Orchestrator handles everything autonomously
- [ ] Real-time progress visualization

---

## Key Improvements Over Current System

| Current | Enhanced |
|---------|----------|
| Fixed sequence (recon→plan→exploit→report) | Dynamic agent selection based on findings |
| Manual CLI commands for each phase | Single target input, full automation |
| Simple function tools | Full specialized agents with expertise |
| No iteration | Continuous discovery and adaptation |
| Basic exploitation checks | Comprehensive vulnerability testing |
| Generic planning | Strategic thinking and reasoning |

---

## Example Autonomous Flow

```
User: phantomrecon --target example.com

Orchestrator thinks:
├─ "This is a web domain. I should start with recon."
├─ Invokes: ReconAgent
│  └─ Finds: Ports 80, 443 open, Apache 2.4, PHP detected
│
├─ "Web server found. Check for web vulnerabilities and SQLi."
├─ Invokes (parallel): WebSecurityAgent, SQLiAgent  
│  ├─ WebSecurityAgent finds: XSS in search parameter
│  └─ SQLiAgent finds: Blind SQLi in login form
│
├─ "Found vulnerabilities. Let me validate and extract more info."
├─ Invokes: SQLiAgent again with targeted enumeration
│  └─ Extracts: Database version, table names
│
├─ "Also saw SSH on port 22. Check SSH security."
├─ Invokes: SSHAgent
│  └─ Finds: Weak SSH configuration
│
├─ "Comprehensive audit complete. Generate report."
└─ Invokes: ReportingAgent
   └─ Generates: Full vulnerability report with remediation

Total time: 2-5 minutes (depending on target)
Result: Professional security audit report
```

---

## Next Steps
1. Implement Phase 2: Create specialist agents
2. Enhance orchestrator with better strategic instructions
3. Test autonomous operation on multiple targets
4. Iterate based on performance

