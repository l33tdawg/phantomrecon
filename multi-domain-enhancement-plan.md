# PhantomRecon Enhancement Plan: Multi-Domain Scanning & Improved Search

## Current Limitations

1. **Single Target Focus**: PhantomRecon currently treats a domain (e.g., hitb.org) as a single target, missing the opportunity to discover and assess subdomains that could reveal additional attack surfaces.

2. **Limited Search Capabilities**: While we use `googlesearch-python` for web searches, we're not leveraging ADK's built-in LLM-powered `google_search` function, which could provide more contextually relevant results.

## Proposed Enhancements

### 1. Multi-Domain Discovery & Assessment

#### Implementation Plan:

1. **Initial DNS Reconnaissance Phase**
   - Create a new function `perform_subdomain_enumeration(target_domain)` that executes before the main reconnaissance phase
   - Implement multiple subdomain discovery techniques:
     - DNS zone transfers (dig axfr)
     - Certificate transparency logs (using certspotter or similar API)
     - Subdomain brute forcing with common subdomain wordlists
     - Passive DNS data sources
   - Store results in a new state variable: `subdomains`

2. **Reconnaissance Loop Architecture**
   - Modify `perform_parallel_recon` to iterate through the main domain and all discovered subdomains
   - Create a queue system to process domains in batches to prevent overwhelming resources
   - Implement a tracking mechanism to avoid duplicate scans
   - Create progress indicators for multi-domain scanning

3. **Domain Prioritization Logic**
   - Implement scoring for discovered subdomains based on:
     - Technology fingerprinting results
     - Open ports
     - Public-facing services
     - Known vulnerabilities in discovered services
   - Allow focusing on high-value targets first when time/resources are limited

4. **Resource Management**
   - Add configuration options for controlling scan depth per subdomain
   - Implement intelligent rate limiting to prevent target server overload
   - Add support for distributing scans across multiple threads/processes
   - Implement caching of results for efficiency

5. **Unified Reporting**
   - Enhance report generation to organize findings by subdomain
   - Create summary sections that aggregate vulnerabilities across all subdomains
   - Generate subdomain relationship maps
   - Provide risk scoring at both individual subdomain and overall domain levels

### 2. Enhanced Search with ADK's google_search

#### Implementation Plan:

1. **Integration Strategy**
   - Replace current `googlesearch-python` implementation with ADK's `google_search` function
   - Create a wrapper function that ensures backward compatibility with existing code
   - Add fallback to current implementation if ADK search fails

2. **LLM-Guided Search Queries**
   - Implement a function to generate targeted search queries based on discovered information
   - Create a tiered search approach:
     - Basic domain information gathering
     - Technology-specific vulnerability searches
     - Contextual searches based on discovered services and versions

3. **Search Result Analysis**
   - Develop an LLM-powered parser to extract relevant technical information from search results
   - Implement clustering of search results by topic/relevance
   - Create a feedback loop where initial search results inform subsequent search queries

4. **Integration with Exploitation Planning**
   - Use search results to enhance attack plan generation
   - Incorporate discovered CVEs and known vulnerabilities into targeted exploit selection
   - Correlate public vulnerability reports with target's infrastructure

## Technical Implementation Details

### Subdomain Discovery Implementation

```python
def perform_subdomain_enumeration(context: ToolContext, target_domain: str) -> List[str]:
    """
    Discover subdomains for a given target domain using multiple techniques.
    
    Args:
        context: The ADK ToolContext
        target_domain: The base domain to enumerate subdomains for
        
    Returns:
        List of discovered subdomains
    """
    discovered_subdomains = set()
    
    # Method 1: DNS Zone Transfer attempt
    try:
        nameservers = _get_nameservers(target_domain)
        for ns in nameservers:
            zone_transfer_results = _attempt_zone_transfer(target_domain, ns)
            discovered_subdomains.update(zone_transfer_results)
    except Exception as e:
        print(f"[SUBDOMAIN] Zone transfer error: {e}")
    
    # Method 2: Certificate Transparency logs
    ct_subdomains = _query_certificate_transparency(target_domain)
    discovered_subdomains.update(ct_subdomains)
    
    # Method 3: Common subdomain brute forcing (limited set)
    wordlist = _get_common_subdomains()
    brute_force_results = _brute_force_subdomains(target_domain, wordlist)
    discovered_subdomains.update(brute_force_results)
    
    # Validate discovered subdomains with DNS resolution
    validated_subdomains = _validate_subdomains(discovered_subdomains)
    
    # Store in context state
    if not context.session.state.get('subdomains'):
        context.session.state['subdomains'] = []
    context.session.state['subdomains'].extend(validated_subdomains)
    
    # Store in global cache for persistence
    from google.adk.sessions.in_memory_session_service import _set_in_global_cache
    _set_in_global_cache('subdomains', validated_subdomains)
    
    return validated_subdomains
```

### Enhanced Search Implementation

```python
def perform_intelligent_search(context: ToolContext, target_domain: str, 
                               discovered_services: List[Dict] = None) -> Dict:
    """
    Perform intelligent web searches using ADK's google_search with LLM guidance.
    
    Args:
        context: The ADK ToolContext
        target_domain: The domain to research
        discovered_services: Optional list of services discovered during recon
        
    Returns:
        Dictionary of search results by category
    """
    from google.adk.tools.search import google_search
    
    results_by_category = {
        "general_domain_info": [],
        "technology_specific": [],
        "vulnerability_reports": [],
        "security_discussions": []
    }
    
    # Generate basic domain search queries
    base_queries = [
        f"security issues {target_domain}",
        f"vulnerability {target_domain}",
        f"{target_domain} data breach",
        f"{target_domain} security report",
        f"{target_domain} bug bounty"
    ]
    
    # Execute basic searches
    for query in base_queries:
        try:
            search_results = google_search(query)
            results_by_category["general_domain_info"].extend(search_results)
        except Exception as e:
            print(f"[SEARCH] Error searching for '{query}': {e}")
            # Fallback to previous implementation
            fallback_results = _fallback_search(query)
            results_by_category["general_domain_info"].extend(fallback_results)
    
    # If we have discovered services, perform targeted searches
    if discovered_services:
        for service in discovered_services:
            service_name = service.get('name', '')
            version = service.get('version', '')
            if service_name and version:
                tech_query = f"{service_name} {version} vulnerability exploit"
                try:
                    tech_results = google_search(tech_query)
                    results_by_category["technology_specific"].extend(tech_results)
                except Exception as e:
                    print(f"[SEARCH] Error searching for '{tech_query}': {e}")
    
    # Store results in context state
    context.session.state['search_results'] = results_by_category
    
    # Store in global cache for persistence
    from google.adk.sessions.in_memory_session_service import _set_in_global_cache
    _set_in_global_cache('search_results', results_by_category)
    
    return results_by_category
```

### Multi-Domain Reconnaissance Loop

```python
def perform_multi_domain_recon(context: ToolContext, initial_target: str) -> Dict:
    """
    Orchestrates reconnaissance across multiple subdomains.
    
    Args:
        context: The ADK ToolContext
        initial_target: The initial domain target
        
    Returns:
        Aggregated reconnaissance data
    """
    # Step 1: Discover subdomains
    print(f"[RECON] Starting subdomain discovery for {initial_target}")
    subdomains = perform_subdomain_enumeration(context, initial_target)
    all_targets = [initial_target] + subdomains
    print(f"[RECON] Discovered {len(subdomains)} subdomains")
    
    # Step 2: Set up aggregated results container
    aggregated_results = {
        "domains": {},
        "summary": {
            "total_domains": len(all_targets),
            "total_open_ports": 0,
            "total_vulnerabilities": 0,
            "high_value_targets": []
        }
    }
    
    # Step 3: Process each domain with rate limiting
    for domain in all_targets:
        print(f"[RECON] Processing domain: {domain}")
        
        # Create a temporary context for this domain's recon
        domain_context = ToolContext()
        domain_context.session.state = {'initial_target': domain}
        
        # Perform reconnaissance for this specific domain
        domain_results = perform_parallel_recon(domain_context, domain)
        
        # Store results in the aggregated container
        aggregated_results["domains"][domain] = domain_results
        
        # Update summary statistics
        if 'nmap_scan' in domain_results:
            open_ports = _count_open_ports(domain_results['nmap_scan'])
            aggregated_results["summary"]["total_open_ports"] += open_ports
            
        # Apply target scoring and identify high-value targets
        target_score = _score_target_domain(domain_results)
        if target_score > 70:  # Threshold for high-value
            aggregated_results["summary"]["high_value_targets"].append({
                "domain": domain,
                "score": target_score,
                "reason": _get_high_score_reason(domain_results)
            })
            
        # Implement rate limiting to be considerate to target servers
        time.sleep(2)  # Basic rate limiting
    
    # Step 4: Store the complete results
    context.session.state['recon'] = aggregated_results
    
    # Store in global cache for persistence
    from google.adk.sessions.in_memory_session_service import _set_in_global_cache
    _set_in_global_cache('recon', aggregated_results)
    
    return aggregated_results
```

## Required Changes to Existing Components

1. **Agent Pipeline Modification**
   - Update `main_workflow_agent` to include subdomain discovery step
   - Modify planner to process multi-domain data
   - Update exploit router to handle multiple targets

2. **User Interface Enhancements**
   - Add progress indicators for multi-domain scanning
   - Provide options to limit scope (e.g., max number of subdomains)
   - Allow selective targeting of specific subdomains

3. **Data Model Updates**
   - Extend attack plan structure to accommodate multiple domains
   - Modify report templates to display subdomain hierarchies
   - Update state persistence to handle increased data volume

4. **Performance Considerations**
   - Implement caching of common data between subdomains
   - Add configuration options for scan depth per subdomain
   - Consider distributed scanning options for large domains

## Implementation Roadmap

### Phase 1: Core Infrastructure (Week 1-2)
- Implement subdomain enumeration function
- Create multi-domain reconnaissance loop
- Update data models to support multiple domains

### Phase 2: LLM-Enhanced Search (Week 2-3)
- Replace current search with ADK's google_search
- Implement intelligent query generation
- Create result parser and categorizer

### Phase 3: Integration & Testing (Week 3-4)
- Connect subdomain discovery with existing reconnaissance
- Update planning and exploitation phases
- Enhance reporting for multi-domain results

### Phase 4: Optimization & Refinement (Week 4-5)
- Performance tuning for large domain sets
- Implement advanced targeting and prioritization
- Add user-configurable scan parameters

## Success Metrics

1. Increased coverage: >80% of discoverable subdomains identified
2. Performance: Complete scans of medium-sized domains (<50 subdomains) within reasonable timeframe
3. Actionable results: High-value targets correctly identified for focused assessment
4. Resource efficiency: Intelligent prioritization reduces unnecessary scanning

## Future Considerations

1. **Advanced Subdomain Techniques**
   - Implement more sophisticated permutation techniques
   - Integrate with passive DNS databases (if available)
   - Add support for custom wordlists

2. **Enhanced Reporting**
   - Create visual domain maps showing relationships
   - Implement risk heat maps across subdomain structure
   - Enable custom report filtering by subdomain patterns

3. **Scan Distribution**
   - Add support for distributed scanning across multiple agents
   - Implement scan resumption for interrupted operations
   - Consider cloud-based scanning options for massive domains 