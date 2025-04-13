from .agent import sequential_pipeline as agent

# Apply session state persistence fix
from .session_fix import apply_monkey_patch, print_global_cache

# For debugging/logging
print_global_cache()

# Apply monkey patch for session state 
apply_monkey_patch()
