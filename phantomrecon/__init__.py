# Compatibility shim: ensure google.genai.types has HttpRetryOptions expected by ADK
try:
    import google.genai.types as _genai_types
    if not hasattr(_genai_types, 'HttpRetryOptions') and hasattr(_genai_types, 'HttpOptions'):
        # Alias HttpRetryOptions -> HttpOptions for compatibility
        setattr(_genai_types, 'HttpRetryOptions', getattr(_genai_types, 'HttpOptions'))
except Exception:
    # Best-effort; ADK import may still succeed if not needed
    pass

import os as _os

# Import the main agent for ADK runner to find (allow disabling for smoke tests)
agent = None
if not _os.environ.get('PHANTOMRECON_NO_IMPORT_AGENT'):
    from .agent import orchestrator_agent as agent
    # Provide `root_agent` alias for ADK runner discovery as well
    from .agent import orchestrator_agent as root_agent

import logging
logger = logging.getLogger(__name__)
logger.info("PhantomRecon package initialized (Orchestrator agent exported)")
