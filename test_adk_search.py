#!/usr/bin/env python3
import unittest
import asyncio
from unittest.mock import patch, MagicMock
import sys
import os

# Add the project root to the path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Import the functions to test
from phantomrecon.agents.recon_logic import perform_web_search_with_adk, perform_web_search

class MockToolContext:
    """Mock ToolContext for testing"""
    def __init__(self):
        self.session = MagicMock()
        self.session.state = {'initial_target': 'example.com'}

class TestADKGoogleSearch(unittest.TestCase):
    """Test cases for the ADK Google Search integration"""

    def setUp(self):
        """Set up the test environment"""
        self.context = MockToolContext()
        self.kwargs = {'context': self.context}

    @patch('phantomrecon.agents.recon_logic.google_search_tool.google_search')
    def test_perform_web_search_with_adk_success(self, mock_google_search):
        """Test the ADK search function works when Google Search succeeds"""
        # Mock successful search results
        mock_google_search.return_value = [
            {'title': 'Example.com', 'link': 'https://example.com'},
            {'title': 'Example About', 'link': 'https://example.com/about'},
        ]
        
        # Run the function (need to use asyncio.run to call async function)
        results = asyncio.run(perform_web_search_with_adk(**self.kwargs))
        
        # Verify the correct search queries were made
        self.assertEqual(mock_google_search.call_count, 4)  # 4 different queries should be made
        
        # Check that we got the expected results
        self.assertEqual(results['status'], 'completed')
        self.assertEqual(len(results['results']), 2)
        self.assertIn('https://example.com', results['results'])
        self.assertIn('https://example.com/about', results['results'])
        
    @patch('phantomrecon.agents.recon_logic.google_search_tool.google_search')
    def test_perform_web_search_with_adk_failure(self, mock_google_search):
        """Test the ADK search function gracefully handles failures"""
        # Mock Google Search raising an exception
        mock_google_search.side_effect = Exception("API error")
        
        # Run the function
        results = asyncio.run(perform_web_search_with_adk(**self.kwargs))
        
        # Check that we got fallback results
        self.assertEqual(results['status'], 'completed')
        self.assertTrue(len(results['results']) > 0)
        # Should have fallback pattern-based URLs
        self.assertIn('https://example.com', results['results'])
        
    def test_perform_web_search_patterns(self):
        """Test the pattern-based search function"""
        # Run the pattern-based function
        results = asyncio.run(perform_web_search(**self.kwargs))
        
        # Check that we got the expected pattern-based URLs
        self.assertEqual(results['status'], 'completed')
        self.assertTrue(len(results['results']) >= 5)  # Should have multiple pattern URLs
        self.assertIn('https://example.com', results['results'])
        self.assertIn('https://www.example.com', results['results'])

if __name__ == '__main__':
    unittest.main() 