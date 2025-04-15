#!/usr/bin/env python3
"""
Test the session persistence fixes in InMemorySessionService.
This script directly tests the session service without using agents.
"""
import logging
import os

# Set DEBUG environment variable for verbose logging
os.environ['DEBUG'] = '1'

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import the session service
from google.adk.sessions.in_memory_session_service import InMemorySessionService

def main():
    """Run tests on the InMemorySessionService to verify state persistence."""
    
    # Create service with debug mode
    service = InMemorySessionService(debug_mode=True)
    logger.info("Created InMemorySessionService instance")
    
    # App and user info
    app_name = "TestApp"
    user_id = "test_user"
    session_id = "test_session"
    
    # Step 1: Create a session
    session = service.create_session(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id
    )
    logger.info(f"Created session {session_id} with initial state keys: {list(session.state.keys())}")
    
    # Step 2: Update state using update_state method
    service.update_state(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        key="test_key",
        value="test_value"
    )
    logger.info("Updated state with test_key=test_value")
    
    # Step 3: Verify state was updated using get_state method
    key_value = service.get_state(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        key="test_key"
    )
    logger.info(f"Retrieved value for test_key: {key_value}")
    
    if key_value == "test_value":
        print("✅ Step 1 PASSED: State was correctly updated and retrieved")
    else:
        print(f"❌ Step 1 FAILED: Retrieved value {key_value} != expected 'test_value'")
    
    # Step 4: Access global cache directly
    global_value = service.get_from_global_cache("test_key")
    logger.info(f"Retrieved value from global cache: {global_value}")
    
    if global_value == "test_value":
        print("✅ Step 2 PASSED: Value was correctly stored in global cache")
    else:
        print(f"❌ Step 2 FAILED: Global cache value {global_value} != expected 'test_value'")
    
    # Step 5: Update global cache directly
    service.set_in_global_cache("global_key", "global_value")
    logger.info("Set global_key=global_value in global cache")
    
    # Step 6: Create a new session to check if it gets the global state
    new_session_id = "new_test_session"
    new_session = service.create_session(
        app_name=app_name,
        user_id=user_id,
        session_id=new_session_id
    )
    logger.info(f"Created new session {new_session_id} with initial state keys: {list(new_session.state.keys())}")
    
    # Step 7: Check if the new session has values from global cache
    new_key_value = service.get_state(
        app_name=app_name,
        user_id=user_id,
        session_id=new_session_id,
        key="test_key"
    )
    logger.info(f"Retrieved value for test_key in new session: {new_key_value}")
    
    new_global_value = service.get_state(
        app_name=app_name,
        user_id=user_id,
        session_id=new_session_id,
        key="global_key"
    )
    logger.info(f"Retrieved value for global_key in new session: {new_global_value}")
    
    if new_key_value == "test_value" and new_global_value == "global_value":
        print("✅ Step 3 PASSED: New session correctly inherited global state")
    else:
        print(f"❌ Step 3 FAILED: New session did not inherit all global state")
        print(f"  test_key: {new_key_value}")
        print(f"  global_key: {new_global_value}")
    
    # Step 8: Print the global cache contents
    service.print_global_cache()
    
    # Summary
    print("\nTest Summary:")
    if (key_value == "test_value" and 
        global_value == "test_value" and 
        new_key_value == "test_value" and 
        new_global_value == "global_value"):
        print("✅ ALL TESTS PASSED: Session state persistence is working correctly!")
    else:
        print("❌ SOME TESTS FAILED: Session state persistence has issues.")
        

if __name__ == "__main__":
    main() 