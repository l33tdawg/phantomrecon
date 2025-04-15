#!/usr/bin/env python3
"""
Custom command executor for PhantomRecon to address issues with ADK's UnsafeLocalCodeExecutor.

This module provides safer, more reliable command execution functionality with proper
error handling, timeouts, and asyncio support. It replaces direct use of ADK's
UnsafeLocalCodeExecutor which had compatibility issues.
"""

import asyncio
import logging
import shlex
import subprocess
from typing import List, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def run_command(command: Union[List[str], str], timeout: int = 60) -> Tuple[str, str, int]:
    """
    Run a shell command asynchronously with timeout.
    
    Args:
        command: Command to run as list of strings or a single string
        timeout: Maximum execution time in seconds
        
    Returns:
        Tuple containing (stdout, stderr, return_code)
    """
    if isinstance(command, str):
        command = shlex.split(command)
        
    logger.debug(f"Running command: {' '.join(command)}")
    
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return_code = process.returncode
        except asyncio.TimeoutError:
            logger.warning(f"Command timed out after {timeout} seconds: {' '.join(command)}")
            try:
                process.kill()
            except Exception:
                pass
            return "", f"Command timed out after {timeout} seconds", 124
            
        stdout_str = stdout.decode('utf-8', errors='replace').strip()
        stderr_str = stderr.decode('utf-8', errors='replace').strip()
        
        logger.debug(f"Command returned code {return_code}")
        if return_code != 0:
            logger.warning(f"Command returned non-zero exit code {return_code}: {stderr_str}")
            
        return stdout_str, stderr_str, return_code
    
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return "", f"Error executing command: {e}", 1

async def run_command_detailed(command: str, timeout: int = 60) -> Tuple[str, str, int]:
    """
    Run a shell command with more detailed output formatting and improved error handling.
    This version is used for more complex tools that need better error reporting.
    
    Args:
        command: Command to run as string
        timeout: Maximum execution time in seconds
        
    Returns:
        Tuple containing (stdout, stderr, return_code)
    """
    logger.info(f"Running detailed command: {command}")
    
    try:
        # For complex commands that might include pipes, shell=True is needed
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            shell=True
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return_code = process.returncode
        except asyncio.TimeoutError:
            logger.warning(f"Command timed out after {timeout} seconds: {command}")
            try:
                process.kill()
            except Exception:
                pass
            return "", f"Command timed out after {timeout} seconds", 124
            
        stdout_str = stdout.decode('utf-8', errors='replace').strip()
        stderr_str = stderr.decode('utf-8', errors='replace').strip()
        
        logger.debug(f"Command returned code {return_code}")
        if return_code != 0:
            logger.warning(f"Command returned non-zero exit code {return_code}")
            logger.warning(f"STDERR: {stderr_str}")
            
        return stdout_str, stderr_str, return_code
    
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return "", f"Error executing command: {e}", 1

# Synchronous versions for non-async contexts

def run_command_sync(command: Union[List[str], str], timeout: int = 60) -> Tuple[str, str, int]:
    """Synchronous version of run_command for use in non-async contexts"""
    return asyncio.run(run_command(command, timeout))

def run_command_detailed_sync(command: str, timeout: int = 60) -> Tuple[str, str, int]:
    """Synchronous version of run_command_detailed for use in non-async contexts"""
    return asyncio.run(run_command_detailed(command, timeout)) 