#!/usr/bin/env python3
"""
Helper functions to fix session state persistence issues in PhantomRecon.
"""
import logging
from typing import Dict, Any, Optional
import importlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global cache to store state between agent runs
# This is a simple in-memory solution
_GLOBAL_STATE_CACHE: Dict[str, Any] = {}

def get_from_global_cache(key: str, default: Any = None) -> Any:
    """
    Get a value from the global state cache.
    
    Args:
        key: The key to retrieve
        default: Default value if key doesn't exist
        
    Returns:
        The value from the cache or default
    """
    return _GLOBAL_STATE_CACHE.get(key, default)

def set_in_global_cache(key: str, value: Any) -> None:
    """
    Set a value in the global state cache.
    
    Args:
        key: The key to set
        value: The value to store
    """
    _GLOBAL_STATE_CACHE[key] = value
    logger.debug(f"Set in global cache: {key}={value}")

def print_global_cache() -> None:
    """Print the current contents of the global cache"""
    logger.info(f"Global state cache contents: {_GLOBAL_STATE_CACHE}")

class SessionStateWrapper:
    """
    Wrapper around ADK's session state to ensure persistence.
    This intercepts state operations and duplicates them to our global cache.
    """
    
    def __init__(self, original_state: Dict[str, Any]):
        """
        Initialize with the original state dictionary.
        
        Args:
            original_state: The original state object from ADK
        """
        self._original_state = original_state
        
        # Initialize from global cache if available
        for key, value in _GLOBAL_STATE_CACHE.items():
            if key not in self._original_state:
                self._original_state[key] = value
                logger.debug(f"Restored {key} from global cache to session state")
    
    def __getitem__(self, key: str) -> Any:
        """Get an item from state, checking global cache as fallback"""
        # First try the original state
        if key in self._original_state:
            return self._original_state[key]
        
        # Fall back to global cache
        if key in _GLOBAL_STATE_CACHE:
            value = _GLOBAL_STATE_CACHE[key]
            # Update original state for future access
            self._original_state[key] = value
            logger.debug(f"Retrieved {key} from global cache and updated session state")
            return value
            
        # Not found anywhere
        return None
    
    def __setitem__(self, key: str, value: Any) -> None:
        """Set an item in both state and global cache"""
        # Update original state
        self._original_state[key] = value
        # Also update global cache
        _GLOBAL_STATE_CACHE[key] = value
        logger.debug(f"Set {key} in both session state and global cache")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get with default value, checking global cache as fallback"""
        # First try the original state
        if key in self._original_state:
            return self._original_state[key]
        
        # Fall back to global cache
        if key in _GLOBAL_STATE_CACHE:
            value = _GLOBAL_STATE_CACHE[key]
            # Update original state for future access
            self._original_state[key] = value
            logger.debug(f"Retrieved {key} from global cache and updated session state")
            return value
            
        # Not found anywhere, return default
        return default
    
    def setdefault(self, key: str, default: Any = None) -> Any:
        """Set default value if key doesn't exist, checking global cache first"""
        # Check original state first
        if key in self._original_state:
            return self._original_state[key]
        
        # Check global cache
        if key in _GLOBAL_STATE_CACHE:
            value = _GLOBAL_STATE_CACHE[key]
            self._original_state[key] = value
            logger.debug(f"Retrieved {key} from global cache for setdefault")
            return value
            
        # Not found anywhere, set default in both places
        self._original_state[key] = default
        _GLOBAL_STATE_CACHE[key] = default
        logger.debug(f"Set default for {key} in both session state and global cache")
        return default
    
    def update(self, other_dict: Dict[str, Any]) -> None:
        """Update the state dictionary with key/value pairs from another dictionary"""
        if not other_dict:
            return
            
        # Update both original state and global cache
        for key, value in other_dict.items():
            self._original_state[key] = value
            _GLOBAL_STATE_CACHE[key] = value
            
        logger.debug(f"Updated session state with {len(other_dict)} items")
    
    def keys(self):
        """Return keys from the union of state and global cache"""
        all_keys = set(self._original_state.keys()).union(_GLOBAL_STATE_CACHE.keys())
        return all_keys
    
    def items(self):
        """Return items from the combined state"""
        combined = dict(_GLOBAL_STATE_CACHE)  # Start with global cache
        combined.update(self._original_state)  # Original state takes precedence
        return combined.items()
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists in either state or global cache"""
        return key in self._original_state or key in _GLOBAL_STATE_CACHE

def patch_session_state(context):
    """
    Patch the session state of a context object to use our wrapper.
    
    Args:
        context: The context object from ADK
    
    Returns:
        True if patching was successful, False otherwise
    """
    if not context or not hasattr(context, 'session'):
        logger.warning("Context object missing or has no session attribute")
        return False
    
    if not hasattr(context.session, 'state'):
        logger.warning("Session object has no state attribute")
        return False
    
    # Check if already patched
    if isinstance(context.session.state, SessionStateWrapper):
        logger.debug("Session state already patched")
        return True
    
    # Patch the state
    try:
        original_state = context.session.state
        context.session.state = SessionStateWrapper(original_state)
        logger.info("Successfully patched session state")
        return True
    except Exception as e:
        logger.error(f"Error patching session state: {e}")
        return False

# Monkey patch to the main agent module
def apply_monkey_patch():
    """
    Apply monkey patching to ensure session state persistence.
    This should be called at application startup.
    """
    try:
        # Import the agent classes directly from ADK instead of our module
        from google.adk.agents import LlmAgent, SequentialAgent
        
        # Store original LlmAgent._run_async_impl method
        original_llm_run = LlmAgent._run_async_impl
        
        # Create patched method
        def patched_llm_run(self, context):
            # Apply our state wrapper
            patch_session_state(context)
            # Call original method
            return original_llm_run(self, context)
        
        # Apply the patch
        LlmAgent._run_async_impl = patched_llm_run
        logger.info("Successfully applied LlmAgent._run_async_impl monkey patch")
        
        # Similar patch for SequentialAgent if needed
        try:
            original_seq_run = SequentialAgent._run_async_impl
            
            def patched_seq_run(self, context):
                # Apply our state wrapper 
                patch_session_state(context)
                # Call original method
                return original_seq_run(self, context)
            
            SequentialAgent._run_async_impl = patched_seq_run
            logger.info("Successfully applied SequentialAgent._run_async_impl monkey patch")
        except Exception as e:
            logger.error(f"Error monkey patching SequentialAgent: {e}")
        
        return True
    except Exception as e:
        logger.error(f"Error applying monkey patch: {e}")
        return False

# Can be run directly to test the patching
if __name__ == "__main__":
    logger.info("Running session fix module directly")
    result = apply_monkey_patch()
    logger.info(f"Monkey patching result: {result}")
    print_global_cache() 