"""
Simple test agent to understand the ADK context structure.
"""
import logging
from google.adk.agents import Agent
from google.adk import events

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleTestAgent(Agent):
    """A simple agent for testing ADK structure."""
    
    def __init__(self):
        super().__init__(name="SimpleTestAgent", description="Tests ADK structure")
        
    async def _run_async_impl(self, ctx):
        # Log information about the context
        logger.info(f"Context type: {type(ctx)}")
        logger.info(f"Context dir: {dir(ctx)}")
        
        # Try to extract the user message
        try:
            # Try to access different potential ways to get the message
            if hasattr(ctx, 'get_last_message_text'):
                user_input = ctx.get_last_message_text()
                logger.info(f"Got message via get_last_message_text: {user_input}")
                
            if hasattr(ctx, 'messages'):
                logger.info(f"Messages: {ctx.messages}")
                
            if hasattr(ctx, 'conversation'):
                logger.info(f"Conversation: {dir(ctx.conversation)}")
                if hasattr(ctx.conversation, 'messages'):
                    logger.info(f"Conversation messages: {ctx.conversation.messages}")
                    
            if hasattr(ctx, 'message'):
                logger.info(f"Message: {ctx.message}")
                
            # Check if it has a session
            if hasattr(ctx, 'session'):
                logger.info(f"Session: {dir(ctx.session)}")

            # Try to get the new_message
            if hasattr(ctx, 'new_message'):
                logger.info(f"New message: {ctx.new_message}")
                if hasattr(ctx.new_message, 'content'):
                    logger.info(f"Content: {ctx.new_message.content}")
                    if hasattr(ctx.new_message.content, 'parts'):
                        logger.info(f"Parts: {ctx.new_message.content.parts}")
                        if len(ctx.new_message.content.parts) > 0:
                            logger.info(f"Text: {ctx.new_message.content.parts[0].text}")
                            user_input = ctx.new_message.content.parts[0].text
                            
            # Fallback to using the app_data
            if hasattr(ctx, 'app_data'):
                logger.info(f"App data: {ctx.app_data}")
            
        except Exception as e:
            logger.error(f"Error accessing context: {e}")
            user_input = "Unknown input"
        
        # Return a response
        response = f"I received your message: '{user_input}'"
        yield events.AgentEvent.from_text(self.name, response)

# Create agent instance
agent = SimpleTestAgent() 