# Import the main agent for ADK runner to find
from .agent import sequential_pipeline as agent

import logging
logger = logging.getLogger(__name__)
logger.info("PhantomRecon package initialized (using ADK's native EnhancedStateDict for state persistence)")
