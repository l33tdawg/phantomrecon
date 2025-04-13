#!/usr/bin/env python3
import logging
from google.adk.agents import Agent, LlmAgent, SequentialAgent
from google.adk.tools import ToolContext
import sys
import importlib

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# First agent: Sets a value in session state
set_agent = LlmAgent(
    name="SetAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an agent that sets a test value in the session state.
1. When the user messages you, store 'test_value' in session state using:
   context.session.state['test_key'] = 'test_value'
2. Tell the user you've stored the value and list the keys in the session state.
3. Print the type of the session state object for debugging.
""",
    output_key="set_result",
    description="Sets a test value in the session state"
)

# Second agent: Gets a value from session state
get_agent = LlmAgent(
    name="GetAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an agent that gets a test value from the session state.
1. When the user messages you, try to get 'test_key' from session state using:
   value = context.session.state.get('test_key', 'NOT_FOUND')
2. Tell the user the value you retrieved and list all keys in the session state.
3. Print the type of the session state object for debugging.
""",
    output_key="get_result",
    description="Gets a test value from the session state"
)

# Sequential agent that runs both
test_pipeline = SequentialAgent(
    name="TestPipeline",
    sub_agents=[set_agent, get_agent],
    description="Tests session state persistence between agents"
)

# Module inspection to understand session implementation
try:
    # Import session module
    session_module = importlib.import_module("google.adk.session")
    logger.info(f"Session module available. Contents: {dir(session_module)}")
except ImportError:
    logger.error("Cannot import google.adk.session")

# Look for the session object in submodules
modules_to_check = ["google.adk.tools", "google.adk.agents", "google.adk"]
for module_name in modules_to_check:
    try:
        module = importlib.import_module(module_name)
        logger.info(f"Module {module_name} contents: {[item for item in dir(module) if 'session' in item.lower()]}")
    except ImportError:
        logger.error(f"Cannot import {module_name}")

# For execution via 'python -m phantomrecon.session_test'
if __name__ == "__main__":
    logger.info("This is a test script to understand ADK session mechanism")
    logger.info("To run the agents, use: adk run phantomrecon.session_test")

# For import by ADK
agent = test_pipeline 