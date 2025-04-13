#!/usr/bin/env python3
# PhantomRecon Google Search Example
import logging
import asyncio
import sys
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import the phantomrecon web search function
try:
    from phantomrecon.agents.recon_logic import perform_web_search
except ImportError:
    logger.error("Failed to import perform_web_search from phantomrecon. Make sure it's installed correctly.")
    sys.exit(1)

# Setup necessary context for ADK
try:
    from google.adk.toolkit import ToolContext
    from google.adk import sessions
except ImportError:
    logger.error("Failed to import ADK modules. Make sure google-adk is installed.")
    sys.exit(1)

class SimpleSessionState:
    """Simple state object to mimic the ADK session state"""
    def __init__(self):
        self.state = {}

class SimpleSession:
    """Simple session object to mimic the ADK session"""
    def __init__(self, target):
        self.state = {"initial_target": target}

class SimpleContext:
    """Simple context object to mimic the ADK context"""
    def __init__(self, target):
        self.session = SimpleSession(target)

async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_domain>")
        print(f"Example: {sys.argv[0]} example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    logger.info(f"Starting web search for target: {target}")
    
    # Create a simple context to pass to the function
    # Setup context for the function to use
    context = SimpleContext(target)
    
    # Mock the get_current_context function
    def mock_get_current_context():
        return context
    
    # Import and patch the get_current_context module
    import google.adk.toolkit
    google.adk.toolkit.get_current_context = mock_get_current_context
    
    # Perform the web search
    try:
        search_results = await perform_web_search()
        
        # Display results
        print("\n--- SEARCH RESULTS ---")
        if "error" in search_results:
            print(f"Error: {search_results['error']}")
        else:
            print(f"Target: {search_results['target']}")
            print(f"Query: {search_results['search_query']}")
            print(f"Status: {search_results['status']}")
            print(f"Found {len(search_results['results'])} results:")
            
            # Print the results
            for i, url in enumerate(search_results['results'], 1):
                print(f"{i}. {url}")
    
    except Exception as e:
        logger.error(f"Error running web search: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main()) 