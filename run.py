#!/usr/bin/env python3
"""
Run script for the PhantomRecon agent using the Google ADK Runner.
"""

import asyncio
import logging
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from phantomrecon.agent import agent

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def main():
    """Run the PhantomRecon agent interactively"""
    # Initialize the session service
    session_service = InMemorySessionService()
    
    # Initialize the runner
    runner = Runner(
        app_name="PhantomRecon",
        agent=agent,
        session_service=session_service
    )
    
    # Create a unique session ID
    user_id = "user"
    session_id = "session"
    
    # Create a session
    session_service.create_session(
        app_name="PhantomRecon",
        user_id=user_id,
        session_id=session_id
    )
    
    print("PhantomRecon agent initialized. Type 'exit' to quit.")
    
    # Interactive loop
    while True:
        # Get user input
        user_input = input("\nYou: ")
        
        # Check for exit command
        if user_input.lower() in ("exit", "quit"):
            break
        
        # Create a message from the user input
        message = types.Content(
            parts=[types.Part(text=user_input)]
        )
        
        # Run the agent
        print("\nAgent: ", end="", flush=True)
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=message
        ):
            # Print non-partial events
            if not event.partial:
                # Print the event content - this may need to be adjusted
                # based on the actual structure of the event object
                if hasattr(event, 'content'):
                    if hasattr(event.content, 'parts') and event.content.parts:
                        # If content has parts, print the text from the first part
                        print(event.content.parts[0].text)
                    else:
                        # If content doesn't have parts, print the content itself
                        print(str(event.content))
                else:
                    # If no content attribute, print the event object itself
                    print(str(event))
                
if __name__ == "__main__":
    asyncio.run(main()) 