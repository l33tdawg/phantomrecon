from typing import Any

class EnhancedStateDict:
    def __getitem__(self, key: str) -> Any:
        """Get item with fallback to global cache."""
        # First try local state
        if key in super():
            value = super().__getitem__(key)
            # Ensure consistency with global cache
            if key not in _GLOBAL_STATE_CACHE or _GLOBAL_STATE_CACHE[key] != value:
                _set_in_global_cache(key, value)
            return value
        
        # Try global cache
        if key in _GLOBAL_STATE_CACHE:
            value = _get_from_global_cache(key)
            # Update local state
            super().__setitem__(key, value)
            return value
        
        # Not found anywhere
        raise KeyError(key) 