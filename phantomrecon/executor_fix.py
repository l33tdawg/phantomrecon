#!/usr/bin/env python3
"""
Helper functions to fix command execution issues in PhantomRecon.
"""
import logging
import asyncio
import subprocess
from typing import List, Tuple, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CommandExecutor:
    """
    Custom executor to handle shell commands properly.
    """
    
    @staticmethod
    async def execute(command: List[str], timeout: int = 60) -> Tuple[str, str, int]:
        """
        Execute a command using asyncio subprocess.
        
        Args:
            command: The command to execute as a list of strings
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, returncode)
        """
        try:
            logger.debug(f"Running command: {' '.join(command)}")
            
            # Use asyncio.subprocess directly
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Wait for the process with timeout
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                return stdout.decode().strip(), stderr.decode().strip(), process.returncode
            except asyncio.TimeoutError:
                # Try to terminate the process on timeout
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    process.kill()  # Force kill if terminate doesn't work
                    await process.wait()
                
                err_msg = f"Error: Command timed out after {timeout}s: {' '.join(command)}"
                logger.warning(err_msg)
                return "", err_msg, -2  # Indicate timeout with -2
            
        except FileNotFoundError:
            cmd_name = command[0]
            err_msg = f"Error: Command '{cmd_name}' not found. Is it installed and in PATH?"
            logger.error(err_msg)
            return "", err_msg, -1  # Indicate file not found with -1
        except Exception as e:
            err_msg = f"Unexpected error running command {' '.join(command)}: {e}"
            logger.error(err_msg, exc_info=True)
            return "", err_msg, -3  # Indicate other error with -3
    
    @staticmethod
    async def execute_detailed(command: str, timeout: int = 15) -> Tuple[str, str, int]:
        """
        More detailed command runner with proper escaping & better error messages.
        Takes a command string instead of list.
        
        Args:
            command: The command as a string
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, returncode)
        """
        import shlex
        try:
            # Split the command string using shlex to handle quoted arguments properly
            cmd_parts = shlex.split(command)
            return await CommandExecutor.execute(cmd_parts, timeout)
        except Exception as e:
            logger.error(f"Error parsing or running detailed command '{command}': {e}")
            return "", f"Command parsing/execution error: {e}", -3

    @staticmethod
    async def execute_with_adk(command: str, timeout: int = 60) -> Tuple[str, str, int]:
        """
        Alternative execution method through subprocess.
        
        Args:
            command: The command as a string
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, returncode)
        """
        try:
            # Use a simple approach with asyncio.subprocess via a shell
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            
            try:
                # Wait for the process with timeout
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                return stdout.decode().strip(), stderr.decode().strip(), process.returncode
            except asyncio.TimeoutError:
                process.terminate()
                await process.wait()
                return "", f"Command timed out after {timeout}s", -2
                
        except Exception as e:
            logger.error(f"Error executing command with shell: {e}")
            return "", f"Error executing command: {e}", -3

# For direct usage
async def run_command(command: List[str], timeout: int = 60) -> Tuple[str, str, int]:
    """
    Shorthand function to run a command.
    
    Args:
        command: The command to execute as a list of strings
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (stdout, stderr, returncode)
    """
    return await CommandExecutor.execute(command, timeout)

async def run_command_detailed(command: str, timeout: int = 15) -> Tuple[str, str, int]:
    """
    Shorthand function to run a detailed command.
    
    Args:
        command: The command as a string
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (stdout, stderr, returncode)
    """
    return await CommandExecutor.execute_detailed(command, timeout)

# Example usage
if __name__ == "__main__":
    async def test():
        stdout, stderr, returncode = await run_command(["ls", "-la"])
        print(f"Return code: {returncode}")
        print(f"Output: {stdout}")
        if stderr:
            print(f"Error: {stderr}")
    
    asyncio.run(test()) 