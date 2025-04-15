#!/usr/bin/env python3
import os
import json
from typing import Dict, List
from datetime import datetime
import markdown2
from rich.console import Console
from google.adk.tools import ToolContext
import logging

console = Console()

class ReportAgent:
    def __init__(self, output_dir: str = "reports"):
        """Initialize the reporting agent."""
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate(self, recon_data: Dict, attack_plan: Dict, exploit_results: List[Dict]):
        """
        Generate a report based on the collected data.
        
        Args:
            recon_data (Dict): Reconnaissance scan results
            attack_plan (Dict): Planned attack vectors
            exploit_results (List[Dict]): Results from executed exploits
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"report_{timestamp}.md"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # Build Markdown report content
        md_content = self._build_markdown_report(recon_data, attack_plan, exploit_results)
        
        # Save Markdown report
        try:
            with open(report_path, 'w') as f:
                f.write(md_content)
            console.print(f"[green]Report saved to: {report_path}[/green]")
            
            # Optional: Convert to HTML
            # self._generate_html_report(md_content, report_path.replace(".md", ".html"))
            
        except IOError as e:
            console.print(f"[red]Error saving report: {str(e)}[/red]")
            
    def _build_markdown_report(self, recon_data: Dict, attack_plan: Dict, 
                             exploit_results: List[Dict]) -> str:
        """
        Construct the Markdown report content.
        
        Args:
            recon_data (Dict): Reconnaissance data
            attack_plan (Dict): Attack plan
            exploit_results (List[Dict]): Exploit results
            
        Returns:
            str: Report content in Markdown format
        """
        report = []
        report.append("# PhantomRecon Security Assessment Report")
        report.append(f"*Generated on: {datetime.now().isoformat()}*")
        report.append("\n---\n")
        
        # Reconnaissance Summary
        report.append("## 1. Reconnaissance Summary")
        report.append("### Targets Scanned:")
        for host, data in recon_data.get("scan", {}).items():
            report.append(f"- **{host}** ({data.get('hostnames', [{}])[0].get('name', 'N/A')})")
            report.append("  - **Open Ports & Services:**")
            for port in data.get("ports", []):
                service = port.get("service", {})
                report.append(f"    - Port {port['port']}/{port.get('protocol', 'tcp')}")
                report.append(f"      - State: {port['state']}")
                report.append(f"      - Service: {service.get('name', 'N/A')}")
                report.append(f"      - Product: {service.get('product', 'N/A')}")
                report.append(f"      - Version: {service.get('version', 'N/A')}")
        report.append("\n---\n")
        
        # Attack Plan
        report.append("## 2. Attack Plan")
        report.append("### Identified Target Services:")
        for service_name, info in attack_plan.items():
            report.append(f"- **{service_name.capitalize()}** (Version: {info['version']}, Port: {info['port']})")
            report.append("  - **Planned Tests:**")
            for test in info['tests']:
                report.append(f"    - `{test}`")
        report.append("\n---\n")
        
        # Exploitation Results
        report.append("## 3. Exploitation Results")
        if exploit_results:
            report.append("### Test Outcomes:")
            for result in exploit_results:
                test_name = result.get('test', 'N/A')
                target_id = result.get('target', 'N/A')
                base_url = result.get('url') # Get base URL if available (added in scanners)
                target_display = f"`{target_id}`" + (f" ({base_url})" if base_url else "")
                
                report.append(f"- **Test:** `{test_name}` on Target {target_display}")
                report.append(f"  - Status: **{result.get('status', 'N/A').upper()}**")
                
                findings = result.get('findings')
                if findings:
                    report.append("  - Findings:")
                    findings_list = findings if isinstance(findings, list) else [findings]
                    
                    # --- Specific Formatting for Scanners ---
                    if test_name == 'wapiti_scan':
                        for finding in findings_list:
                             if isinstance(finding, dict):
                                  report.append(f"    - **Category:** `{finding.get('category', 'N/A')}` (Level: `{finding.get('level', 'N/A')}`)")
                                  report.append(f"      - Message: {finding.get('message', 'N/A')}")
                                  if finding.get('parameter'):
                                       report.append(f"      - Parameter: `{finding.get('parameter')}` (Method: `{finding.get('method', 'N/A')}`)")
                                       # Optionally add curl command or details if needed
                                       # report.append(f"        - Details: `{finding.get('detail', {})}`") 
                             else:
                                  report.append(f"    - (Non-dict finding: {finding})")
                                  
                    elif test_name == 'wpscan_scan':
                        for finding in findings_list:
                             if isinstance(finding, dict):
                                 finding_type = finding.get('type', 'N/A')
                                 if finding_type == 'info':
                                      report.append(f"    - **Info:** {finding.get('message', 'N/A')}")
                                 elif finding_type == 'wpscan_vulnerability':
                                      report.append(f"    - **Vulnerability:** `{finding.get('title', 'N/A')}`")
                                      report.append(f"      - Source: `{finding.get('source_type', 'N/A')}` (`{finding.get('source_name', 'N/A')}`)")
                                      if finding.get('fixed_in'):
                                           report.append(f"      - Fixed In: `{finding.get('fixed_in')}`")
                                      # Optionally add references
                                      refs = finding.get('references', {})
                                      if refs:
                                           report.append("      - References:")
                                           for ref_type, ref_list in refs.items():
                                               if isinstance(ref_list, list):
                                                   for ref_item in ref_list:
                                                        report.append(f"        - {ref_type.upper()}: {ref_item}")
                                               elif isinstance(ref_list, str): # Handle single string ref
                                                    report.append(f"        - {ref_type.upper()}: {ref_list}")
                                 elif finding_type == 'wpscan_interesting':
                                      report.append(f"    - **Interesting Finding:** {finding.get('message', 'N/A')}")
                                      report.append(f"      - Confidence: {finding.get('confidence', 'N/A')}%")
                                 else:
                                      # Generic fallback for other WPScan finding types
                                      report.append(f"    - Type: `{finding_type}`")
                                      report.append(f"      - Message: {finding.get('message', finding.get('to_s', 'N/A'))}")
                             else:
                                 report.append(f"    - (Non-dict finding: {finding})")
                                 
                    # --- Generic Formatting for Other Tests ---    
                    else:
                        for finding in findings_list:
                            if isinstance(finding, dict):
                                 # Specific formatting for SQL version vulns (searchsploit)
                                 if test_name == 'version_vulnerabilities' and finding.get('type') == 'exploitdb_finding':
                                      report.append(f"    - **ExploitDB:** `{finding.get('title', 'N/A')}`")
                                      report.append(f"      - EDB-ID: `{finding.get('edb_id', 'N/A')}` (Path: `{finding.get('path', 'N/A')}`")
                                      report.append(f"      - Platform: `{finding.get('platform', 'N/A')}` (Type: `{finding.get('exploit_type', 'N/A')}`")
                                  
                                 # Specific formatting for SQL default creds
                                 elif test_name == 'default_credentials' and finding.get('user') is not None:
                                      report.append(f"    - **Successful Login:** User=`{finding.get('user')}` Password=`{finding.get('password')}`")
                                  
                                 # Specific formatting for SQL sqlmap direct exploit
                                 elif test_name == 'sqlmap_direct_exploit' and isinstance(finding, dict):
                                      report.append(f"    - **Sqlmap Direct Connect Results:** (User: `{result.get('auth_used',{}).get('user')}`)\") # Fixed quotes and parenthesis")
                                      if finding.get('current_user'):
                                           report.append(f"      - Current User: `{finding.get('current_user')}`\") # Fixed quotes")
                                      if finding.get('current_db'):
                                           report.append(f"      - Current DB: `{finding.get('current_db')}`\") # Fixed quotes")
                                      if finding.get('is_dba') is not None:
                                           report.append(f"      - Is DBA: `{finding.get('is_dba')}`\") # Fixed quotes")
                                      if finding.get('databases'): # Note: sqlmap stdout parsing might only get count now
                                           report.append(f"      - Databases Found: `{finding.get('databases')}` (or count: `{finding.get('databases_count')}`)\") # Fixed quotes and parenthesis")
                                      if finding.get('errors'):
                                           # Properly format the f-string expression for joining the list
                                           errors_str = ", ".join(finding.get('errors', []))
                                           report.append(f"    - **Enumeration Errors:** `{errors_str}`")
                                  
                                 # Default generic format
                                 else:
                                     # Specific formatting for SSH weak creds
                                     if test_name == 'weak_credentials' and finding.get('user') is not None:
                                          report.append(f"    - **Successful Login:** User=`{finding.get('user')}` Password=`{finding.get('password')}`")
                                     # Specific formatting for SSH Audit (extract key info)
                                     elif test_name == 'ssh_config_audit' and isinstance(finding, dict):
                                          report.append(f"    - **SSH Audit Findings:**")
                                          if finding.get('banner'):
                                               report.append(f"      - Banner: `{finding.get('banner')}`")
                                          
                                          # Report weak algorithms
                                          if finding.get('weak_algorithms'):
                                              report.append(f"      - **Weak Algorithms Detected:**")
                                              for algo in finding['weak_algorithms']:
                                                   report.append(f"        - **Category:** `{algo.get('category').upper()}` Name: `{algo.get('name')}` ({algo.get('classification')})")
                                                   if algo.get('recommendations'):
                                                       report.append(f"          - Recommendation: {'; '.join(algo['recommendations'])}")
                                          else:
                                               report.append(f"      - Weak Algorithms: None found.")
                                          
                                          # Report recommendations (warnings/failures)
                                          if finding.get('recommendations'):
                                              report.append(f"      - **Security Recommendations:**")
                                              for rec in finding['recommendations']:
                                                   report.append(f"        - **Severity:** `{rec.get('severity').upper()}` Message: {rec.get('message')}")
                                          else:
                                               report.append(f"      - Security Recommendations: None found.")

                                          # Report allowed authentication methods
                                          auth_methods = finding.get('auth_methods')
                                          if isinstance(auth_methods, list):
                                              report.append(f"      - **Allowed Auth Methods:** `{', '.join(auth_methods)}`")
                                              # Highlight if password auth seems disabled
                                              if auth_methods and "password" not in auth_methods and "keyboard-interactive" not in auth_methods:
                                                  report.append(f"        - **Note:** Password/Keyboard-Interactive auth likely disabled.")
                                          elif auth_methods:
                                               report.append(f"      - Auth Methods: (Could not parse list: {auth_methods})")

                                          # Optionally report fingerprints
                                          # if finding.get('fingerprints'):
                                          #      report.append(f"      - Fingerprints:")
                                          #      for fp_type, fp_value in finding['fingerprints'].items():
                                          #           report.append(f"        - {fp_type.upper()}: {fp_value}")
                                     
                                     # Fallback to generic for other dict findings
                                     else:
                                          report.append(f"    - Type: `{finding.get('type', 'N/A')}`")
                                          report.append(f"    - Message: {finding.get('message', 'N/A')}")
                                     # Add other common fields if needed (e.g., path for default_files)
                                     if 'path' in finding:
                                         report.append(f"      - Path: `{finding.get('path')}`")
                                     if 'url' in finding:
                                         report.append(f"      - URL: `{finding.get('url')}`")
                            else:
                                 # Handle cases where findings might be simple strings
                                 report.append(f"    - {finding}")
                                
                elif result.get('message'): # Display message if no findings but message exists (e.g., skipped)
                     report.append(f"  - Message: {result['message']}")
                    
                report.append("") # Add spacing between test results
        else:
            report.append("*No exploits were executed or results available.*")
        report.append("\n---\n")
        
        # Conclusion
        report.append("## 4. Conclusion")
        report.append("This report summarizes the automated assessment conducted by PhantomRecon.")
        report.append("Further manual investigation may be required.")
        
        return "\n".join(report)
        
    def _generate_html_report(self, md_content: str, html_path: str):
        """
        Convert Markdown content to HTML report.
        
        Args:
            md_content (str): Markdown report content
            html_path (str): Path to save the HTML file
        """
        try:
            html_content = markdown2.markdown(md_content, extras=["tables", "fenced-code-blocks"])
            
            # Optional: Add basic styling
            html_full = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>PhantomRecon Report</title>
                <style>
                    body {{ font-family: sans-serif; line-height: 1.6; padding: 20px; }}
                    h1, h2, h3 {{ color: #333; }}
                    code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 4px; }}
                    pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                {html_content}
            </body>
            </html>
            """
            
            with open(html_path, 'w') as f:
                f.write(html_full)
            console.print(f"[green]HTML report saved to: {html_path}[/green]")
        except Exception as e:
            console.print(f"[red]Error generating HTML report: {str(e)}[/red]")

def _build_markdown_report(recon_data: Dict, attack_plan: Dict, exploit_results: List[Dict], summary_text: str) -> str:
    """
    Construct the Markdown report content using provided data structures.
    
    Args:
        recon_data (Dict): Aggregated reconnaissance data.
        attack_plan (Dict): Generated attack plan.
        exploit_results (List[Dict]): List of results from exploit checks.
        summary_text (str): Pre-generated summary text.
            
    Returns:
        str: Report content in Markdown format.
    """
    # --- Data Extraction (No longer needed, data is passed in) ---
    # Get data from state
    # recon_data = context.session.state.get('aggregated_recon_data', {})
    # attack_plan = context.session.state.get('attack_plan', {})
    # exploit_results = context.session.state.get('exploit_results', [])
    # report_summary = context.session.state.get('report_summary', {}) # Get LLM summary
    target = recon_data.get('target', 'Unknown Target') # Use passed recon_data
    
    report = []
    report.append("# PhantomRecon Security Assessment Report")
    report.append(f"*Target: {target}*") # Add target here
    report.append(f"*Generated on: {datetime.now().isoformat()}*")
    report.append("\n---\n")

    # --- Executive Summary (from passed argument) --- 
    report.append("## 1. Executive Summary")
    # Check if summary_text is the default placeholder or an actual summary
    if summary_text and summary_text != "No summary generated.":
        # Simple inclusion for now, assuming summary_text is ready markdown
        report.append(summary_text) 
    else:
         report.append("_(No summary was generated.)_")
    report.append("\n---\n")

    # --- Detailed Report Sections (Re-numbered) --- 
    # (Remove the previous manual summary/risk calculation logic)
    
    # Reconnaissance Summary
    report.append("## 2. Reconnaissance Summary") # Renumbered
    # Access nmap data within the passed recon_data structure
    nmap_scan_data = recon_data.get("nmap_scan", {})
    scan_results = nmap_scan_data.get("scan", {})
    if scan_results:
        report.append("### Targets Scanned:")
        for host, data in scan_results.items():
            # Extract hostname if available
            hostname = "N/A"
            if data.get('hostnames') and isinstance(data['hostnames'], list) and data['hostnames']:
                 hostname = data['hostnames'][0].get('name', 'N/A')
            report.append(f"- **{host}** ({hostname})")
            # Extract open ports (assuming structure from nmap scan parser)
            open_ports = []
            if data.get('tcp') and isinstance(data['tcp'], dict):
                 for port_num, port_info in data['tcp'].items():
                      if isinstance(port_info, dict) and port_info.get('state') == 'open':
                           port_info_copy = port_info.copy() # Avoid modifying original state
                           port_info_copy['port'] = port_num # Add port number back for reporting
                           port_info_copy['protocol'] = 'tcp'
                           open_ports.append(port_info_copy)
            # Add UDP ports if needed
            
            if open_ports:
                report.append("  - **Open Ports & Services:**")
                for port in open_ports:
                    service = port.get("service", {})
                    report.append(f"    - Port {port.get('port', 'N/A')}/{port.get('protocol', 'tcp')}")
                    report.append(f"      - State: {port.get('state', 'N/A')}")
                    report.append(f"      - Service: {port.get('name', 'N/A')}")
                    report.append(f"      - Product: {port.get('product', 'N/A')}")
                    report.append(f"      - Version: {port.get('version', 'N/A')}")
            else:
                 report.append("  - *No open TCP ports found in scan results.*")
    else:
         report.append("_(Nmap scan data not available or scan failed)_ ")
         # Add error/warning message if present in nmap_scan_data
         if nmap_scan_data.get("error"):
             report.append(f"  - Error: {nmap_scan_data['error']}")
         if nmap_scan_data.get("warning"):
             report.append(f"  - Warning: {nmap_scan_data['warning']}")
             
    report.append("\n---\n")
    
    # Include DNS/WHOIS info if available (simplified)
    dns_info = recon_data.get('dns_recon', {}) # Use passed recon_data
    if dns_info and not dns_info.get("error"):
         report.append("### DNS/WHOIS Info:")
         # Access dig results within dns_info -> dns -> dig
         dig_results = dns_info.get('dns', {}).get('dig', {})
         report.append(f"- A Records: {dig_results.get('A',[])}")
         report.append(f"- MX Records: {dig_results.get('MX',[])}")
         report.append(f"- NS Records: {dig_results.get('NS',[])}")
         report.append(f"- TXT Records: {dig_results.get('TXT',[])}")
         # Add others as needed
         whois_data = dns_info.get('whois')
         whois_status = 'N/A'
         if isinstance(whois_data, str):
              if whois_data.startswith("Failed") or whois_data.startswith("Skipped"):
                   whois_status = whois_data
              elif len(whois_data) > 10: # Basic check for actual content
                   whois_status = "Available (details omitted)" # Avoid dumping full WHOIS
         report.append(f"- WHOIS Status: {whois_status}")
         # Add AXFR attempt summary if present
         axfr_attempt = dns_info.get('dns', {}).get('axfr_attempt')
         if isinstance(axfr_attempt, dict) and 'status' not in axfr_attempt: # Check if it has server results
              successful_axfr = [ns for ns, res in axfr_attempt.items() if res.get('status') == 'success']
              if successful_axfr:
                   report.append(f"- **Potential Zone Transfer (AXFR): Succeeded from {successful_axfr}**")
              else:
                   report.append("- Zone Transfer (AXFR): Attempted, failed from all checked name servers.")
         elif isinstance(axfr_attempt, dict):
              report.append(f"- Zone Transfer (AXFR): {axfr_attempt.get('message', 'Status unavailable')}")
         # Add DNS errors if any occurred
         if dns_info.get("errors"):
             report.append("- DNS Errors:")
             for err in dns_info["errors"]:
                  report.append(f"  - `{err}`")
              
    elif dns_info and dns_info.get("error"):
        report.append(f"### DNS/WHOIS Info:\n Error: {dns_info['error']}")
    else:
        report.append("### DNS/WHOIS Info:\n_(Not available)_")
        
    report.append("\n---\n")
    
    # Attack Plan
    report.append("## 3. Attack Plan Generated by LLM")
    if isinstance(attack_plan, dict) and not attack_plan.get("error"):
        report.append("### Identified Target Services & Planned Tests:")
        # Iterate through plan items (which might be web_targets, sql_targets etc)
        plan_items_count = 0
        for target_key, info in attack_plan.items():
             # Skip internal error/details fields if they exist at top level
             if target_key in ['error', 'details']: continue 
             
             plan_items_count += 1
             if isinstance(info, dict):
                  report.append(f"- **Target Key:** `{target_key}`") # Use the key from the plan dict
                  report.append(f"  - Host: {info.get('target_host', 'N/A')}:{info.get('port', 'N/A')}")
                  report.append(f"  - Service: {info.get('service_name', 'N/A')} ({info.get('product', 'N/A')} {info.get('version', 'N/A')})")
                  report.append("  - Planned Tests:")
                  for test in info.get('tests', []):
                      report.append(f"    - `{test}`")
                  report.append("") # Add spacing
             elif isinstance(info, list): # Handle cases like web_targets which might be a list
                  report.append(f"- **Target Group:** `{target_key}` ({len(info)} targets)")
                  for sub_info in info:
                      if isinstance(sub_info, dict):
                          report.append(f"  - Host: {sub_info.get('target_host', 'N/A')}:{sub_info.get('port', 'N/A')}")
                          report.append(f"    - Service: {sub_info.get('service_name', 'N/A')} ({sub_info.get('product', 'N/A')} {sub_info.get('version', 'N/A')})")
                          report.append("    - Planned Tests:")
                          for test in sub_info.get('tests', []):
                              report.append(f"      - `{test}`")
                          report.append("") # Add spacing
        if plan_items_count == 0: # Check if we actually iterated through any valid plan items
            report.append("*Attack plan structure invalid or empty.*")
    elif isinstance(attack_plan, dict) and attack_plan.get("error"):
         report.append(f"*Error during planning phase: {attack_plan['error']}*")
         if attack_plan.get('details'):
              report.append(f"```\n{attack_plan.get('details')}\n```")
    else:
        report.append("*No valid attack plan was generated or available.*")
        
    report.append("\n---\n")
    
    # Exploitation Results
    report.append("## 4. Exploitation Results") # Removed simulation note
    if exploit_results:
        report.append("### Test Outcomes:")
        for result in exploit_results:
            # Use the structure from the original _build_markdown_report in ReportAgent class
            test_name = result.get('test', 'N/A')
            target_id = result.get('target', 'N/A')
            base_url = result.get('url') # Get base URL if available (added in scanners)
            target_display = f"`{target_id}`" + (f" ({base_url})" if base_url else "")
            
            report.append(f"- **Test:** `{test_name}` on Target {target_display}")
            report.append(f"  - Status: **{result.get('status', 'N/A').upper()}**")
            
            findings = result.get('findings')
            if findings:
                report.append("  - Findings:")
                findings_list = findings if isinstance(findings, list) else [findings]
                
                # --- Specific Formatting Logic (copied from ReportAgent._build_markdown_report) ---
                if test_name == 'wapiti_scan':
                    for finding in findings_list:
                        if isinstance(finding, dict):
                                report.append(f"    - **Category:** `{finding.get('category', 'N/A')}` (Level: `{finding.get('level', 'N/A')}`)")
                                report.append(f"      - Description: {finding.get('description', 'N/A')}") # Use description
                                if finding.get('parameter'):
                                    report.append(f"      - Parameter: `{finding.get('parameter')}` (Method: `{finding.get('method', 'N/A')}`)")
                                    report.append(f"      - Reference: {finding.get('reference')}")
                                # Optionally add curl command or details if needed
                                # report.append(f"        - Details: `{finding.get('detail', {})}`") 
                        else:
                                report.append(f"    - (Non-dict finding: {finding})")
                                
                elif test_name == 'wpscan_scan':
                    for finding in findings_list:
                        if isinstance(finding, dict):
                            finding_type = finding.get('type', 'N/A')
                            if finding_type == 'info':
                                    report.append(f"    - **Info:** {finding.get('message', 'N/A')}")
                            elif finding_type == 'wpscan_vulnerability':
                                    report.append(f"    - **Vulnerability:** `{finding.get('title', 'N/A')}`")
                                    report.append(f"      - Source: `{finding.get('source_type', 'N/A')}` (`{finding.get('source_name', 'N/A')}`)")
                                    if finding.get('fixed_in'):
                                        report.append(f"      - Fixed In: `{finding.get('fixed_in')}`")
                                    # Add structured references
                                    refs = finding.get('references', {})
                                    if refs:
                                        report.append("      - References:")
                                        for ref_type, ref_list in refs.items():
                                            if isinstance(ref_list, list):
                                                for ref_item in ref_list:
                                                    report.append(f"        - {ref_type.upper()}: {ref_item}")
                                            elif isinstance(ref_list, str): # Handle single string ref
                                                 report.append(f"        - {ref_type.upper()}: {ref_list}")
                            elif finding_type == 'wpscan_interesting':
                                    report.append(f"    - **Interesting Finding:** {finding.get('message', 'N/A')}")
                                    report.append(f"      - Confidence: {finding.get('confidence', 'N/A')}%")
                            else:
                                    # Generic fallback for other WPScan finding types
                                    report.append(f"    - Type: `{finding_type}`")
                                    report.append(f"      - Message: {finding.get('message', finding.get('to_s', 'N/A'))}")
                        else:
                            report.append(f"    - (Non-dict finding: {finding})")
                            
                # --- Generic Formatting for Other Tests ---    
                else:
                    for finding in findings_list:
                        if isinstance(finding, dict):
                                # Specific formatting for SQL/SSH version vulns (searchsploit)
                                if test_name == 'version_vulnerabilities' and finding.get('type') == 'exploitdb_finding':
                                    report.append(f"    - **ExploitDB:** `{finding.get('title', 'N/A')}`")
                                    report.append(f"      - EDB-ID: `{finding.get('edb_id', 'N/A')}` (Path: `{finding.get('path', 'N/A')}`)")
                                    report.append(f"      - Platform: `{finding.get('platform', 'N/A')}` (Type: `{finding.get('exploit_type', 'N/A')}`)")
                                
                                # Specific formatting for SQL/SSH default creds
                                elif test_name in ['default_credentials', 'weak_credentials'] and finding.get('user') is not None:
                                    report.append(f"    - **Successful Login:** User=`{finding.get('user')}` Password=`{finding.get('password')}`")
                                
                                # Specific formatting for SQL sqlmap direct exploit
                                elif test_name == 'sqlmap_direct_exploit' and isinstance(finding, dict):
                                    report.append(f"    - **Sqlmap Direct Connect Results:** (User: `{result.get('auth_used',{}).get('user')}`)")
                                    if finding.get('current_user'):
                                        report.append(f"      - Current User: `{finding.get('current_user')}`")
                                    if finding.get('current_db'):
                                        report.append(f"      - Current DB: `{finding.get('current_db')}`")
                                    if finding.get('is_dba') is not None:
                                        report.append(f"      - Is DBA: `{finding.get('is_dba')}`")
                                    if finding.get('databases_count') is not None:
                                        report.append(f"      - Databases Count: `{finding.get('databases_count')}`")
                                    if finding.get('errors'):
                                        # Properly format the f-string expression for joining the list
                                        errors_str = ", ".join(finding.get('errors', []))
                                        report.append(f"    - **Enumeration Errors:** `{errors_str}`")
                                        
                                # Specific formatting for SQL config audit
                                elif test_name == 'sql_config_audit' and isinstance(findings_list, list): # Findings is a list of check results
                                     # Avoid repeating the header for each finding in the list
                                     if finding == findings_list[0]: # Only print header once
                                         report.append(f"    - **SQL Configuration Audit Results:** (User: `{result.get('auth_used',{}).get('user')}`)")
                                         
                                     # Now process the actual finding (which is a check result dict)
                                     check_name = finding.get('check')
                                     check_status = finding.get('status')
                                     check_message = finding.get('message')
                                     check_results = finding.get('results')
                                     
                                     report.append(f"      - **Check:** `{check_name}`")
                                     if check_status == 'error':
                                            report.append(f"        - Status: ERROR - {check_message}")
                                     elif check_status == 'permission_denied':
                                            report.append(f"        - Status: Permission Denied - {check_message}")
                                     elif check_name == 'user_privileges':
                                            # Format MySQL/Postgres grants
                                            report.append(f"        - Privileges: (details omitted, check logs)") # Too verbose
                                     elif check_name == 'list_users':
                                            if isinstance(check_results, list):
                                                user_count = len(check_results)
                                                # Handle different result structures (list of tuples vs list of dicts)
                                                users_str = ", ".join(f'`{row[0]}`' if isinstance(row, tuple) and len(row)>0 else f'`{row.get("user") or row.get("rolname")}`' if isinstance(row, dict) else '?' for row in check_results[:5]) # Show first 5
                                                report.append(f"        - Users Found ({user_count}): {users_str}{'...' if user_count > 5 else ''}")
                                            else:
                                                report.append(f"        - Users: (Could not parse results)")
                                     elif check_name == 'empty_mysql_passwords':
                                            report.append(f"        - **Warning:** Empty MySQL Passwords for: `{', '.join(finding.get('users',[]))}`")
                                     elif check_name == 'mysql_secure_file_priv':
                                            if isinstance(check_results, dict):
                                                report.append(f"        - secure_file_priv: `{check_results.get('Value', 'N/A')}`")
                                            else:
                                                report.append(f"        - secure_file_priv: (Could not parse results)")
                                     elif check_name == 'postgres_file_access_potential':
                                            report.append(f"        - Potential File Access: Superuser status `{finding.get('is_superuser')}` ({finding.get('message')})")
                                     else: # Fallback for other config checks
                                            report.append(f"        - Results: (Details omitted)")
                                
                                # Specific formatting for SSH Audit (extract key info)
                                elif test_name == 'ssh_config_audit' and isinstance(finding, dict):
                                    # Avoid repeating header if findings is the dict itself (not list)
                                    if findings_list == [findings]: # Check if it's the only item
                                         report.append(f"    - **SSH Audit Findings:**")
                                    
                                    if finding.get('banner'):
                                            report.append(f"      - Banner: `{finding.get('banner')}`")
                                    
                                    # Report weak algorithms
                                    if finding.get('weak_algorithms'):
                                        report.append(f"      - **Weak Algorithms Detected:**")
                                        for algo in finding['weak_algorithms']:
                                            report.append(f"        - **Category:** `{algo.get('category').upper()}` Name: `{algo.get('name')}` ({algo.get('classification')})")
                                            if algo.get('recommendations'):
                                                report.append(f"          - Recommendation: {'; '.join(algo['recommendations'])}")
                                    else:
                                        # Only report if not already printed
                                        if findings_list == [findings]:
                                             report.append(f"      - Weak Algorithms: None found.")
                                    
                                    # Report recommendations (warnings/failures)
                                    if finding.get('recommendations'):
                                        report.append(f"      - **Security Recommendations:**")
                                        for rec in finding['recommendations']:
                                            report.append(f"        - **Severity:** `{rec.get('severity').upper()}` Message: {rec.get('message')}")
                                    else:
                                         # Only report if not already printed
                                        if findings_list == [findings]:
                                             report.append(f"      - Security Recommendations: None found.")

                                    # Report allowed authentication methods
                                    auth_methods = finding.get('auth_methods')
                                    if isinstance(auth_methods, list):
                                        report.append(f"      - **Allowed Auth Methods:** `{', '.join(auth_methods)}`")
                                        # Highlight if password auth seems disabled
                                        if auth_methods and "password" not in auth_methods and "keyboard-interactive" not in auth_methods:
                                            report.append(f"        - **Note:** Password/Keyboard-Interactive auth likely disabled.")
                                    elif auth_methods:
                                         report.append(f"      - Auth Methods: (Could not parse list: {auth_methods})")
                                    
                                # Specific formatting for Basic SQLi (sqlmap web)
                                elif test_name == 'sql_injection_basic' and finding.get('type') == 'potential_sqli':
                                     report.append(f"    - **Potential SQLi:** {finding.get('message')}")
                                     report.append(f"      - URL: `{finding.get('url')}`")
                                     if finding.get('identified_points'):
                                          report.append(f"      - Identified Point(s):")
                                          for point in finding['identified_points']:
                                               report.append(f"        - `{point}`")
                                     # Optionally include sqlmap output snippet
                                     # if finding.get('sqlmap_output_snippet'):
                                     #      report.append(f"      - Sqlmap Output Snippet:\n```\n{finding['sqlmap_output_snippet']}\n```")

                                # Specific formatting for Basic Reflected XSS
                                elif test_name == 'xss_reflected_basic' and finding.get('type') == 'potential_reflected_xss':
                                     report.append(f"    - **Potential Reflected XSS:** {finding.get('message')}")
                                     report.append(f"      - URL: `{finding.get('url')}`")
                                     report.append(f"      - Parameter: `{finding.get('parameter')}`")
                                     report.append(f"      - Payload Used: `{finding.get('payload')}`")

                                # Specific formatting for Basic Command Injection
                                elif test_name == 'command_injection_basic' and finding.get('type') == 'potential_command_injection':
                                     report.append(f"    - **Potential Command Injection:** {finding.get('message')}")
                                     report.append(f"      - URL: `{finding.get('url')}`")
                                     report.append(f"      - Parameter: `{finding.get('parameter')}`")
                                     report.append(f"      - Payload Suffix Used: `{finding.get('payload_suffix')}`")
                                     report.append(f"      - Indicator Found: `{finding.get('indicator_found')}`")
                                
                                # Specific formatting for default files check
                                elif test_name == 'default_files' and finding.get('type') == 'potential_info_leak':
                                     report.append(f"    - **Accessible Default Path:** `{finding.get('path')}` (Status: {finding.get('status_code')})")
                                     report.append(f"      - URL: `{finding.get('url')}`")
                                     
                                # Specific formatting for misconfigurations check (dir listing)
                                elif test_name == 'misconfigurations' and finding.get('type') == 'misconfiguration':
                                     report.append(f"    - **Misconfiguration ({finding.get('subtype','N/A')}):** {finding.get('message')}")
                                     report.append(f"      - URL: `{finding.get('url')}`")

                                # Default generic format for other dict findings
                                else:
                                    # Avoid duplicating message if already shown
                                    if 'message' in finding and 'type' in finding:
                                         report.append(f"    - Type: `{finding.get('type', 'N/A')}` - Message: {finding.get('message', 'N/A')}")
                                    elif 'message' in finding:
                                         report.append(f"    - Message: {finding.get('message', 'N/A')}")
                                    else: # Just dump key-value pairs if structure unknown
                                         for k, v in finding.items():
                                              report.append(f"    - {k}: {v}")
                                             
                                    # Add other common fields if needed (e.g., path, url if not already covered)
                                    # if 'path' in finding: report.append(f"      - Path: `{finding.get('path')}`")
                                    # if 'url' in finding: report.append(f"      - URL: `{finding.get('url')}`")
                        else:
                                # Handle cases where findings might be simple strings
                                report.append(f"    - {finding}")
                                
            elif result.get('message'): # Display message if no findings but message exists (e.g., skipped, error)
                 report.append(f"  - Message: {result['message']}")
                
            report.append("") # Add spacing between test results
    else:
        report.append("*No exploits were executed or results available.*")
        
    report.append("\n---\n")
    
    # Conclusion
    report.append("## 5. Conclusion") # Renumbered
    report.append("This report summarizes the automated assessment conducted by PhantomRecon.")
    report.append("Further manual investigation may be required, especially for findings marked as 'potential' or where tools indicated vulnerabilities.")
    
    return "\n".join(report)

def generate_final_report(context: ToolContext) -> str:
    """
    Generate a final report based on all collected data in the session state.
    
    Args:
        context: Tool context for accessing session state
        
    Returns:
        A Markdown report as a string
    """
    logging.info("Generating final report...")
    
    # Initialize empty data
    recon_data = {}
    attack_plan = {}
    exploit_results = []
    
    # First, try to get data from context
    if hasattr(context, 'session') and hasattr(context.session, 'state'):
        state = context.session.state
        
        # Extract reconnaissance data
        if 'recon' in state:
            recon_data = state['recon']
        else:
            # Try to get individual recon pieces
            nmap_scan = state.get('nmap_scan_results', {})
            dns_recon = state.get('dns_recon_results', {})
            web_search = state.get('web_search_results', {})
            web_analysis = state.get('web_content_analysis', {})
            
            if any([nmap_scan, dns_recon, web_search, web_analysis]):
                recon_data = {
                    "nmap_scan": nmap_scan,
                    "dns_recon": dns_recon,
                    "web_search": web_search,
                    "web_analysis": web_analysis,
                    "target": state.get('initial_target', "unknown")
                }
        
        # Extract attack plan
        if 'attack_plan' in state:
            attack_plan = state['attack_plan']
            
        # Extract exploit results
        if 'exploit_results' in state:
            exploit_results = state['exploit_results']
            if not isinstance(exploit_results, list):
                exploit_results = [exploit_results]
    
    # If data is still missing, try global cache
    if not recon_data or not attack_plan:
        try:
            from google.adk.sessions.in_memory_session_service import _get_from_global_cache
            if not recon_data:
                recon_data = _get_from_global_cache('recon')
            if not attack_plan:
                attack_plan = _get_from_global_cache('attack_plan')
            logging.info("Retrieved data from global cache")
        except (ImportError, Exception) as e:
            logging.warning(f"Could not access global cache: {e}")
    
    # If still missing data, try emergency cache files
    if not recon_data:
        try:
            import pickle
            import os
            cache_file = 'recon_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    recon_data = pickle.load(f)
                logging.info("Loaded recon data from emergency cache file")
        except Exception as e:
            logging.warning(f"Could not load recon data from cache file: {e}")
            
    if not attack_plan:
        try:
            import pickle
            import os
            cache_file = 'plan_cache.pkl'
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    attack_plan = pickle.load(f)
                logging.info("Loaded attack plan from emergency cache file")
        except Exception as e:
            logging.warning(f"Could not load attack plan from cache file: {e}")
    
    # Ensure we have minimal required data
    if not recon_data:
        recon_data = {
            "target": getattr(context.session.state, 'initial_target', "unknown"),
            "error": "No reconnaissance data available"
        }
    
    if not attack_plan:
        attack_plan = {
            "error": "No attack plan available"
        }
    
    # Generate the summary
    target = recon_data.get('target', 'unknown')
    summary_text = f"Security assessment for {target}"
    
    # Build the markdown report
    report_content = _build_markdown_report(recon_data, attack_plan, exploit_results, summary_text)
    
    # Save the report to a file in reports/ directory
    try:
        import os
        import time
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate timestamped filename
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        target_name = recon_data.get('target', 'unknown').replace('.', '-')
        report_filename = f"{reports_dir}/security-report-{target_name}-{timestamp}.md"
        
        with open(report_filename, 'w') as f:
            f.write(report_content)
        
        logging.info(f"Report saved to {report_filename}")
        
        # Try to generate HTML version
        html_path = report_filename.replace('.md', '.html')
        _generate_html_report(report_content, html_path)
    except Exception as e:
        logging.error(f"Failed to save report: {e}")
    
    # If context has session state, store the final report
    if hasattr(context, 'session') and hasattr(context.session, 'state'):
        context.session.state['final_report'] = report_content
    
    return report_content

def simple_generate_final_report(**kwargs):
    """
    A simplified wrapper for generate_final_report that helps ADK's automatic function calling.
    
    Returns:
        A report string or dictionary
    """
    print("[REPORT] Using simplified report generation function")
    context = kwargs.get('context')
    
    if not context:
        print("[REPORT] Context not provided, using emergency cache mechanism")
        # Create a minimal context-like object with required attributes
        class MinimalContext:
            pass
            
        minimal_context = MinimalContext()
        minimal_context.session = MinimalContext()
        minimal_context.session.state = {}
        
        return generate_final_report(minimal_context)
        
    return generate_final_report(context) 