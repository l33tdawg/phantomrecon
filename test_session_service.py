#!/usr/bin/env python3
"""
Test the ADK's InMemorySessionService to verify that it correctly maintains state between agent runs.
"""
import logging
import asyncio
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.sessions.session import Session
from google.adk.runners import Runner
from google.genai import types

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set up a simple test agent that stores and retrieves values
setter_agent = LlmAgent(
    name="SetterAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an agent that sets values in the session state.
When the user says anything, do the following:
1. Store the value 'test_value' in the session state with the key 'test_key'
2. Tell the user you've done this and include the value in your response
3. Also list all available keys in the session state""",
    description="Sets values in the session state"
)

getter_agent = LlmAgent(
    name="GetterAgent",
    model="gemini-1.5-flash-latest",
    instruction="""You are an agent that retrieves values from the session state.
When the user says anything, do the following:
1. Try to retrieve the value with key 'test_key' from the session state
2. Tell the user what value you found (or report that you couldn't find any value)
3. List all available keys in the session state""",
    description="Gets values from the session state"
)

# Create a sequential agent
seq_agent = SequentialAgent(
    name="TestSequentialAgent",
    sub_agents=[setter_agent, getter_agent],
    description="Tests session state persistence"
)

async def test_session_persistence():
    """Test that the InMemorySessionService maintains state between agent runs."""
    logger.info("Setting up test with InMemorySessionService")
    
    # Create the services
    session_service = InMemorySessionService()
    
    # Create the runner
    runner = Runner(
        app_name="SessionPersistenceTest",
        agent=seq_agent,
        session_service=session_service
    )
    
    # Create a session
    user_id = "test_user"
    session_id = "test_session"
    
    logger.info("Creating new session")
    session = session_service.create_session(
        app_name="SessionPersistenceTest",
        user_id=user_id,
        session_id=session_id
    )
    
    # Create a test message
    test_message = types.Content(
        parts=[types.Part(text="Run the test")]
    )
    
    # Run the agent
    logger.info("Running the sequential agent")
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=test_message
    ):
        # Print non-partial events
        if not event.partial:
            # Use event.name instead of event.agent_name
            logger.info(f"Event from {event.name}: {event.text}")
    
    # Retrieve the session and check the state
    session = session_service.get_session(
        app_name="SessionPersistenceTest",
        user_id=user_id,
        session_id=session_id
    )
    
    logger.info(f"Session keys: {list(session.state.keys())}")
    
    # Check if our value is in the state
    if 'test_key' in session.state:
        logger.info(f"Success! Found test_key in session state with value: {session.state['test_key']}")
    else:
        logger.error("Failed! test_key not found in session state")
    
    return session.state.get('test_key') == 'test_value'

if __name__ == "__main__":
    logger.info("Starting session persistence test")
    result = asyncio.run(test_session_persistence())
    
    if result:
        logger.info("TEST PASSED: Session state was correctly persisted")
    else:
        logger.error("TEST FAILED: Session state was not correctly persisted") 