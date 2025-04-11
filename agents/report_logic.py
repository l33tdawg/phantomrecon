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
                report.append(f"- **Test:** `{result['test']}`")
                report.append(f"  - Status: {result['status']}")
                if result.get('findings'):
                    report.append("  - Findings:")
                    for finding in result['findings']:
                        report.append(f"    - Type: {finding['type']}")
                        report.append(f"    - Message: {finding['message']}")
                report.append("\n")
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
    # Read data from state
    recon_data = context.session.state.get('aggregated_recon_data', {})
    attack_plan = context.session.state.get('attack_plan', {})
    exploit_results = context.session.state.get('exploit_results', [])
    
    report = []
    report.append("# PhantomRecon Security Assessment Report")
    report.append(f"*Generated on: {datetime.now().isoformat()}*")
    report.append("\n---\n")
    
    # Target Info from Recon Summary
    target = recon_data.get('recon_summary',{}).get('nmap_hosts',['Unknown Target'])[0]
    report.append(f"## Target: {target}")
    report.append("\n---\n")

    # Reconnaissance Summary (using aggregated data)
    report.append("## 1. Reconnaissance Summary")
    summary = recon_data.get('recon_summary', {})
    report.append(f"- Nmap Hosts Found: {summary.get('nmap_hosts', 'N/A')}")
    report.append(f"- Discovered Subdomains: {summary.get('discovered_subdomains', 'N/A')}")
    report.append(f"- Discovered URLs: {summary.get('discovered_urls', 'N/A')}")
    report.append(f"- Analyzed URLs Count: {summary.get('analyzed_urls_count', 'N/A')}")
    
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
    report.append("## 2. Attack Plan Generated by LLM")
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
    report.append("## 3. Exploitation Results (Simulation)")
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
    report.append("## 4. Conclusion")
    report.append("This report summarizes the automated assessment conducted by PhantomRecon.")
    report.append("All exploitation steps were simulated. Further manual investigation is recommended.")
    
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
        return msg # Return success message
        
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

# _generate_html_report helper can remain the same if needed, but call it from generate_final_report
# def _generate_html_report(md_content: str, html_path: str):
#    ... 