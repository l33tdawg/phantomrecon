# PhantomRecon Walkthrough

This document explains how PhantomRecon works, with a focus on the sequential agent pipeline used to orchestrate the reconnaissance and vulnerability assessment process.

## Agent Architecture

PhantomRecon uses an ADK (Agent Development Kit) sequential agent pipeline that consists of the following agents:

1. **DirectValidationAgent**: Validates the target input and stores it in the session state
2. **ReconAgent**: Performs reconnaissance using Nmap, DNS, and web search tools
3. **PlannerAgent**: (Future) Analyzes recon data and creates an attack plan
4. **ExploitAgent**: (Future) Executes exploit checks based on the plan
5. **ReportAgent**: (Future) Generates a final vulnerability report

## How Sequential Agent Handoff Works

The key to the sequential agent pipeline is proper state management using the ADK session state. Here's how data flows through the system:

1. The **DirectValidationAgent**:
   - Takes the user input (target domain/IP)
   - Validates it for basic correctness
   - Stores it in `context.session.state['initial_target']`
   - Signals completion with a clear handoff message

2. The **ReconAgent**:
   - Reads the target from `context.session.state['initial_target']`
   - Executes three tools in sequence (Nmap, DNS recon, web search)
   - Each tool reads from the same state key and stores its results in specific state keys
   - Stores combined results in `context.session.state['recon_results']`

3. The **PlannerAgent** (Future):
   - Will read recon data from `context.session.state['recon_results']`
   - Will store the attack plan in `context.session.state['attack_plan']`

4. The **ExploitAgent** (Future):
   - Will read the attack plan from `context.session.state['attack_plan']`
   - Will store exploit results in `context.session.state['exploit_results']`

5. The **ReportAgent** (Future):
   - Will read all previous stages' data from session state
   - Will generate and return a final report

## Debugging Agent Handoff

If an agent isn't receiving data from a previous agent, check:

1. **State Key Names**: Ensure the producer agent stores data under the exact key name that the consumer agent expects
2. **State Validation**: Each function should check if required state keys exist before proceeding
3. **Error Handling**: Agents should handle missing state gracefully with clear error messages
4. **Agent Configuration**: Ensure each agent has the correct instruction prompt that explains how to use state

## Running PhantomRecon

To run PhantomRecon:

```
# Activate virtual environment (if applicable)
source venv/bin/activate

# Run with ADK web interface
adk web

# At the prompt, enter a target domain or IP address
# For example: example.com
```

The agents will execute in sequence, and you'll see the progress in the terminal.

## Key Implementation Details

1. The `DirectValidationAgent` is a custom Agent implementation that directly calls Python functions.
2. The `ReconAgent` is an LlmAgent that uses three primary tools for gathering data.
3. State management is the responsibility of each tool function, which both reads from and writes to the session state.
4. The session state preserves data between agent invocations, allowing the sequential flow.

## Common Issues

- **Agent Not Starting**: This could be due to an error in the previous agent.
- **Missing Data**: Check if the state keys are correctly set and validated.
- **Handoff Failure**: Ensure agents are explicitly signaling completion for better user feedback.

## Extending PhantomRecon

To add more agents to the sequential pipeline:

1. Define the agent in `phantomrecon/agent/__init__.py`
2. Add the agent to the `sub_agents` list in the `sequential_pipeline` definition
3. Ensure proper state read/write for seamless handoff 