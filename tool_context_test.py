#!/usr/bin/env python3
"""
Test how context is passed from a LlmAgent to tools through FunctionTool.
"""
import asyncio
import logging
import os
from typing import Dict, Any
from google.adk.tools import FunctionTool
from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService

# Set DEBUG environment variable for verbose logging
os.environ['DEBUG'] = '1'

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define a simple tool that logs its context
async def debug_context(**kwargs) -> Dict[str, Any]:
    """A tool that logs details about its invocation context."""
    print(f"\n[DEBUG] debug_context called with {len(kwargs)} kwargs")
    print(f"[DEBUG] kwargs keys: {list(kwargs.keys())}")
    
    # Check for context
    context = kwargs.get('context')
    print(f"[DEBUG] context: {context} (type: {type(context)})")
    
    # Examine context if it exists
    if context:
        print(f"[DEBUG] context has session: {hasattr(context, 'session')}")
        if hasattr(context, 'session'):
            print(f"[DEBUG] session type: {type(context.session)}")
            print(f"[DEBUG] session has state: {hasattr(context.session, 'state')}")
            if hasattr(context.session, 'state'):
                print(f"[DEBUG] state type: {type(context.session.state)}")
                print(f"[DEBUG] state keys: {list(context.session.state.keys())}")
                
                # Add a test value to state
                context.session.state['debug_test'] = 'test_value'
                print(f"[DEBUG] Added 'debug_test': 'test_value' to session state")
    
    # Return something meaningful for the agent
    return {
        "status": "success", 
        "message": "Context debugging complete",
        "has_context": context is not None,
        "has_session": context is not None and hasattr(context, 'session'),
        "has_state": context is not None and hasattr(context, 'session') and hasattr(context.session, 'state'),
    }

# Define another tool that will check if the value is still in state
async def check_state(**kwargs) -> Dict[str, Any]:
    """A tool that checks if debug_test is still in the state."""
    print(f"\n[DEBUG] check_state called with {len(kwargs)} kwargs")
    
    # Check for context
    context = kwargs.get('context')
    print(f"[DEBUG] context: {context} (type: {type(context)})")
    
    # Examine context if it exists
    if context and hasattr(context, 'session') and hasattr(context.session, 'state'):
        state_keys = list(context.session.state.keys())
        print(f"[DEBUG] state keys: {state_keys}")
        
        # Check for debug_test value
        has_debug_test = 'debug_test' in context.session.state
        debug_test_value = context.session.state.get('debug_test', 'NOT FOUND')
        print(f"[DEBUG] debug_test in state: {has_debug_test}, value: {debug_test_value}")
        
        return {
            "status": "success",
            "debug_test_found": has_debug_test,
            "debug_test_value": debug_test_value,
            "state_keys": state_keys
        }
    else:
        return {
            "status": "error",
            "message": "No context, session, or state available",
            "has_context": context is not None,
            "has_session": context is not None and hasattr(context, 'session'),
            "has_state": context is not None and hasattr(context, 'session') and hasattr(context.session, 'state'),
        }

class ContextTestRunner:
    """Test runner for context passing between agents and tools."""
    
    def __init__(self):
        # Create the session service with debug mode
        self.session_service = InMemorySessionService(debug_mode=True)
        logger.info("Created InMemorySessionService instance with debug mode")
        
        # Create tools
        debug_context_tool = FunctionTool(func=debug_context)
        check_state_tool = FunctionTool(func=check_state)
        
        # Create the test agents
        self.first_agent = LlmAgent(
            name="FirstAgent",
            model="gemini-1.5-flash-latest",
            instruction="""You are the first agent in a test of context passing.
1. First, tell the user you're the first agent and you'll be checking context.
2. Call the debug_context tool to check and log details about your context.
3. After the tool returns, thank the user and tell them you're done.""",
            tools=[debug_context_tool],
            output_key="first_agent_output",
            description="First agent that tests context"
        )
        
        self.second_agent = LlmAgent(
            name="SecondAgent",
            model="gemini-1.5-flash-latest",
            instruction="""You are the second agent in a test of context passing.
1. First, tell the user you're the second agent and you'll be checking if state from the first agent persisted.
2. Call the check_state tool to verify if the debug_test value is still in the state.
3. Report whether or not the value was found, and what the value was if found.
4. Thank the user and tell them the test is complete.""",
            tools=[check_state_tool],
            output_key="second_agent_output",
            description="Second agent that tests state persistence"
        )
        
        # Create the sequential agent
        self.sequential_agent = SequentialAgent(
            name="TestSequentialAgent",
            sub_agents=[self.first_agent, self.second_agent],
            description="Tests context passing between agents and tools"
        )
        
        # Create the runner
        self.runner = Runner(
            app_name="ContextTest",
            agent=self.sequential_agent,
            session_service=self.session_service
        )
        logger.info("Created test runner with sequential agent")

    async def run_test(self):
        """Run the test and return results."""
        # Create fixed user and session IDs for consistency
        user_id = "test_user"
        session_id = "test_session"
        
        # Create session explicitly before running the test
        self.session_service.create_session(
            app_name="ContextTest",
            user_id=user_id,
            session_id=session_id
        )
        logger.info(f"Created session {session_id} for user {user_id}")
        
        # Start the runner with a simple input
        input_text = "Start the context test"
        print(f"\nRunning context test with input: {input_text}\n")
        
        # Generate the results
        from google.genai import types
        content = types.Content(parts=[types.Part(text=input_text)])
        
        # Process the runner output
        result = []
        async for event in self.runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content
        ):
            result.append(event)
            print(f"\nAgent [{event.author}]: {event.content}\n")
        
        # Get final session state
        final_session = self.session_service.get_session(
            app_name="ContextTest",
            user_id=user_id,
            session_id=session_id
        )
        
        final_state_keys = list(final_session.state.keys()) if final_session.state else []
        print(f"\nFinal session state keys: {final_state_keys}")
        
        for key in final_state_keys:
            print(f"  - {key}: {final_session.state.get(key)}")
        
        return result

async def main():
    test = ContextTestRunner()
    await test.run_test()
    
    print("\n✅ Context test complete!")

if __name__ == "__main__":
    asyncio.run(main()) 