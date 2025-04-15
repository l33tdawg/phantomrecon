#!/usr/bin/env python3
"""
Simple test for EnhancedStateDict in InMemorySessionService
"""
from google.adk.sessions.in_memory_session_service import InMemorySessionService, EnhancedStateDict
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def main():
    # Initialize the session service
    session_service = InMemorySessionService(debug_mode=True)
    
    # Create a session
    session = session_service.create_session(
        app_name="TestApp",
        user_id="test_user",
        session_id="test_session"
    )
    
    # Verify the session state is an EnhancedStateDict
    assert isinstance(session.state, EnhancedStateDict), f"State should be EnhancedStateDict, got {type(session.state)}"
    print(f"✅ Session state is correctly using EnhancedStateDict")
    
    # Set some values in the state
    session.state["test_key"] = "test_value"
    session.state["user_input"] = "test message"
    
    # Get the session again (simulating a different agent getting the same session)
    another_session = session_service.get_session(
        app_name="TestApp",
        user_id="test_user",
        session_id="test_session"
    )
    
    # Verify the state values are preserved
    assert "test_key" in another_session.state, f"test_key should be in state, got keys: {list(another_session.state.keys())}"
    assert "user_input" in another_session.state, f"user_input should be in state, got keys: {list(another_session.state.keys())}"
    assert another_session.state["test_key"] == "test_value", f"test_key value should be 'test_value', got '{another_session.state['test_key']}'"
    assert another_session.state["user_input"] == "test message", f"user_input value should be 'test message', got '{another_session.state['user_input']}'"
    
    print(f"✅ Session state values correctly persisted between sessions")
    print(f"✅ TEST PASSED: Session state persistence is working correctly")
    
if __name__ == "__main__":
    main() 