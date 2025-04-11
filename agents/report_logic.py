#!/usr/bin/env python3
import os
import json
from typing import Dict, List
from datetime import datetime
import markdown2
from rich.console import Console
from google.adk.tools import ToolContext

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
                                           report.append(f"    - **Enumeration Errors:** `{', '.join(finding.get('errors'))}`\") # Fixed quotes")
                                  
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

def _build_markdown_report(context: ToolContext) -> str:
    """
    Construct the Markdown report content by reading data from session state.
    
    Args:
        context (ToolContext): ADK ToolContext containing session state.
            
    Returns:
        str: Report content in Markdown format.
    """
    # --- Data Extraction ---
    # Get data from state
    recon_data = context.session.state.get('aggregated_recon_data', {})
    attack_plan = context.session.state.get('attack_plan', {})
    exploit_results = context.session.state.get('exploit_results', [])
    report_summary = context.session.state.get('report_summary', {}) # Get LLM summary
    target = recon_data.get('recon_summary',{}).get('nmap_hosts',['Unknown Target'])[0]
    
    report = []
    report.append("# PhantomRecon Security Assessment Report")
    report.append(f"*Target: {target}*\") # Add target here
    report.append(f"*Generated on: {datetime.now().isoformat()}*\")
    report.append("\n---\n")

    # --- Executive Summary (from LLM) --- 
    report.append("## 1. Executive Summary")
    if report_summary and not report_summary.get("error"):
        report.append(f"**Overall Assessed Risk:** {report_summary.get('overall_risk', 'Error: Risk not found')}\")
        report.append("\n" + report_summary.get('executive_summary_md', 'Error: Summary not found.'))
    elif report_summary and report_summary.get("error"):
        report.append("**Error generating summary:**")
        report.append(f"```\n{report_summary.get('error')}\n```")
        report.append("_(Proceeding with detailed results only.)_")
    else:
         report.append("_(No summary was generated.)_")
    report.append("\n---\n")

    # --- Detailed Report Sections (Re-numbered) --- 
    # (Remove the previous manual summary/risk calculation logic)
    
    # Reconnaissance Summary
    report.append("## 2. Reconnaissance Summary") # Renumbered
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
    
    # Detailed Nmap Results (Optional - can be verbose)
    nmap_scan = recon_data.get('nmap_scan_results', {}).get('scan', {})
    if nmap_scan:
         report.append("### Nmap Scan Details:")
         for host, data in nmap_scan.items():
             report.append(f"#### Host: {host}")
             # Display open TCP ports
             tcp_ports = data.get('tcp', {})
             if tcp_ports:
                  report.append("  - **Open TCP Ports:**")
                  for port_num, port_data in tcp_ports.items():
                       if port_data.get('state') == 'open':
                            service = port_data.get("service", "unknown")
                            product = port_data.get("product", "N/A")
                            version = port_data.get("version", "N/A")
                            report.append(f"    - **Port {port_num}/tcp:** {service} ({product} {version})")
             # Could add UDP, OS info etc. here
    else:
         report.append("_(Nmap scan data not available or scan failed)_ ")

    # Include DNS/WHOIS info if available (simplified)
    dns_info = recon_data.get('dns_recon_results', {})
    if dns_info and not dns_info.get("error"):
         report.append("### DNS/WHOIS Info:")
         report.append(f"- A Records: {dns_info.get('dns',{}).get('A',[])}")
         report.append(f"- MX Records: {dns_info.get('dns',{}).get('MX',[])}")
         # Add others as needed
         report.append(f"- WHOIS Status: {'Available' if dns_info.get('whois') not in [None, 'Failed or unavailable', 'Skipped (Private IP range)'] else dns_info.get('whois', 'N/A')}")

    report.append("\n---\n")
    
    # Attack Plan
    report.append("## 3. Attack Plan Generated by LLM")
    if isinstance(attack_plan, dict) and not attack_plan.get("error"):
        report.append("### Identified Target Services & Planned Tests:")
        for service_key, info in attack_plan.items():
            report.append(f"- **Target Key:** `{service_key}`")
            report.append(f"  - Host: {info.get('target_host', 'N/A')}:{info.get('port', 'N/A')}")
            report.append(f"  - Service: {info.get('service_name', 'N/A')} ({info.get('product', 'N/A')} {info.get('version', 'N/A')})")
            report.append("  - Planned Tests:")
            for test in info.get('tests', []):
                report.append(f"    - `{test}`")
            report.append("") # Add spacing
    elif isinstance(attack_plan, dict) and attack_plan.get("error"):
         report.append(f"*Error during planning phase: {attack_plan['error']}*")
    else:
        report.append("*No valid attack plan was generated or available.*")
        
    report.append("\n---\n")
    
    # Exploitation Results
    report.append("## 4. Exploitation Results (Simulation)")
    if exploit_results:
        report.append("### Test Outcomes:")
        for result in exploit_results:
            report.append(f"- **Test:** `{result.get('test', 'N/A')}` on Target `{result.get('target', 'N/A')}`")
            report.append(f"  - Status: **{result.get('status', 'N/A').upper()}**")
            if result.get('findings'):
                report.append("  - Findings:")
                # Ensure findings is a list before iterating
                findings_list = result['findings'] if isinstance(result['findings'], list) else [result['findings']]
                for finding in findings_list:
                    if isinstance(finding, dict):
                         report.append(f"    - Type: {finding.get('type', 'N/A')}")
                         report.append(f"    - Message: {finding.get('message', 'N/A')}")
                    else:
                         report.append(f"    - {finding}") # Handle non-dict findings
            elif result.get('message'): # For errors or skipped tests
                 report.append(f"  - Message: {result['message']}")
            report.append("") # Add spacing
    else:
        report.append("*No exploits were executed or results available in state.*")
        
    report.append("\n---\n")
    
    # Conclusion
    report.append("## 5. Conclusion") # Renumbered
    report.append("This report summarizes the automated assessment conducted by PhantomRecon.")
    report.append("Further manual investigation may be required, especially for findings marked as \'potential\'.")
    
    return "\n".join(report)
        
def generate_final_report(context: ToolContext) -> str:
    """
    Generates a final Markdown report by reading all data from session state.
    Saves the report to a file.

    Args:
        context (ToolContext): ADK ToolContext containing session state.

    Returns:
        str: Confirmation message including the path to the saved report.
    """
    output_dir = "reports"
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create report directory '{output_dir}': {e}")
        return f"Error: Failed to create report directory '{output_dir}'."
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"phantomrecon_report_{timestamp}.md"
    report_path = os.path.join(output_dir, report_filename)
    
    logger.info("Generating final report from session state...")
    # Build Markdown report content using data from state
    md_content = _build_markdown_report(context)
    
    # Save Markdown report
    try:
        with open(report_path, 'w') as f:
            f.write(md_content)
        msg = f"Report saved successfully to: {report_path}"
        logger.info(msg)
        console.print(f"[green]{msg}[/green]")
        # Store path in state for potential future use?
        context.session.state['final_report_path'] = report_path
        
        # Generate HTML report
        try:
            html_report_path = report_path.replace(".md", ".html")
            _generate_html_report(md_content, html_report_path)
        except Exception as html_err:
            # Log error but don't fail the overall reporting process
            logger.error(f"Failed to generate HTML report: {html_err}", exc_info=True)
            console.print(f"[yellow]Warning: Failed to generate HTML report: {html_err}[/yellow]")
            
        return msg # Return success message for Markdown report
        
    except IOError as e:
        error_msg = f"Error saving report to {report_path}: {e}"
        logger.error(error_msg)
        console.print(f"[red]{error_msg}[/red]")
        return f"Error: Failed to save report - {e}"
    except Exception as e:
        error_msg = f"Unexpected error during report generation: {e}"
        logger.error(error_msg, exc_info=True)
        console.print(f"[red]{error_msg}[/red]")
        return f"Error: Unexpected error generating report - {e}"

# _generate_html_report helper function (ensure it exists and is correct)
# It seems it was defined within the ReportAgent class previously, let's ensure it's available here
def _generate_html_report(md_content: str, html_path: str):
    """
    Convert Markdown content to HTML report using markdown2 library.
    
    Args:
        md_content (str): Markdown report content
        html_path (str): Path to save the HTML file
    """
    try:
        html_content = markdown2.markdown(md_content, extras=["tables", "fenced-code-blocks", "code-friendly"])
        
        # Basic HTML structure and styling
        html_full = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhantomRecon Report</title>
            <style>
                body {{ font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 1000px; margin: auto; }}
                h1, h2, h3 {{ color: #333; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
                h1 {{ font-size: 2em; }}
                h2 {{ font-size: 1.5em; }}
                h3 {{ font-size: 1.2em; }}
                code {{ background-color: #f4f4f4; padding: 2px 4px; border-radius: 4px; font-family: monospace; }}
                pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 1em; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                li {{ margin-bottom: 0.5em; }}
            </style>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """
        
        with open(html_path, 'w') as f:
            f.write(html_full)
        logger.info(f"HTML report saved to: {html_path}")
        console.print(f"[blue]HTML report saved to: {html_path}[/blue]")
    except Exception as e:
        # Re-raise or handle more gracefully if needed, here we just log
        logger.error(f"Error in _generate_html_report: {str(e)}", exc_info=True)
        raise # Re-raise to be caught by the caller

# _generate_html_report helper can remain the same if needed, but call it from generate_final_report
# def _generate_html_report(md_content: str, html_path: str):
#    ... 