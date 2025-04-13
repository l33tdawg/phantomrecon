#!/usr/bin/env python3
import asyncio
import json
import logging

# Configure logging for testing
logging.basicConfig(level=logging.INFO)

async def main():
    # Import the module
    import phantomrecon.agents.recon_logic as recon_logic
    
    # Create a test version of the function
    async def test_analyze_web_content():
        # Create a simplified version for testing that doesn't rely on context
        search_results = {
            'results': [
                'https://example.com',
                'https://wikipedia.org', 
                'https://python.org'
            ]
        }
        
        # Initialize with empty result structure
        analysis_results = {
            "status": "error",
            "urls_analyzed": 0,
            "failed_urls": 0,
            "results": []
        }
        
        # Skip state check logic since this is a test
        
        # Set up the HTTP session with appropriate headers
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Limit the number of URLs to check to prevent excessive requests
        max_urls = 5
        urls_to_check = search_results['results'][:max_urls]
        
        logging.info(f"Analyzing content from {len(urls_to_check)} URLs")
        
        async with recon_logic.aiohttp.ClientSession(headers=headers) as session:
            # Create an analysis task for each URL
            tasks = []
            for url in urls_to_check:
                tasks.append(recon_logic._analyze_single_url(session, url))
            
            # Run all tasks concurrently
            url_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process the results
            for result in url_results:
                if isinstance(result, Exception):
                    # Handle any exceptions during analysis
                    logging.error(f"Error analyzing URL: {result}")
                    analysis_results["failed_urls"] += 1
                else:
                    # Add successful result to our list
                    if result:  # Only add if we got a valid result
                        analysis_results["results"].append(result)
                        analysis_results["urls_analyzed"] += 1
        
        # Update status if we successfully analyzed anything
        if analysis_results["urls_analyzed"] > 0:
            analysis_results["status"] = "completed"
        
        return analysis_results
    
    # Run our test function
    results = await test_analyze_web_content()
    
    # Print the results
    print("Analysis Results:")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main()) 