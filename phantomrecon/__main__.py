#!/usr/bin/env python3
import os
import sys
import json
import argparse
import asyncio
from typing import Any, Dict

# Import orchestrator and stage functions
from phantomrecon.agent import orchestrator_agent
from phantomrecon.agents.recon_logic import perform_parallel_recon
from phantomrecon.agents.planner_logic import simple_create_attack_plan
from phantomrecon.agents.routing_logic import simple_decide_next_exploit
from phantomrecon.agents.report_logic import simple_generate_final_report


class CliSession:
    def __init__(self):
        self.state: Dict[str, Any] = {}


class CliContext:
    def __init__(self, session: CliSession):
        self.session = session


async def run_recon(ctx: CliContext, target: str | None = None) -> Dict[str, Any]:
    if target:
        ctx.session.state['initial_target'] = target
    return await perform_parallel_recon(context=ctx)


async def run_plan(ctx: CliContext, recon_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if recon_data is None:
        recon_data = ctx.session.state.get('aggregated_recon_data') or ctx.session.state.get('recon') or {}
    return await simple_create_attack_plan(context=ctx, recon_data=recon_data)


def run_route(ctx: CliContext) -> str | None:
    return simple_decide_next_exploit(context=ctx)


def run_report(ctx: CliContext) -> Dict[str, Any] | str:
    return simple_generate_final_report(context=ctx)


async def run_auto(ctx: CliContext, target: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        'orchestrator': orchestrator_agent.name,
        'target': target,
    }
    # Recon
    recon = await run_recon(ctx, target=target)
    ctx.session.state['aggregated_recon_data'] = recon
    results['recon'] = recon.get('status') if isinstance(recon, dict) else 'unknown'
    # Plan
    plan = await run_plan(ctx, recon)
    ctx.session.state['attack_plan'] = plan
    results['plan_keys'] = list(plan.keys()) if isinstance(plan, dict) else []
    # Route
    next_step = run_route(ctx)
    results['router_next'] = next_step
    # Report
    report = run_report(ctx)
    results['report_ok'] = isinstance(report, (dict, str))
    return results


def interactive_console():
    print(f"PhantomRecon Console - Orchestrator: {orchestrator_agent.name}")
    print("Type 'help' for commands. 'exit' to quit.")
    session = CliSession()
    ctx = CliContext(session)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    target = None
    while True:
        try:
            cmd = input('pr> ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExiting.')
            break
        if not cmd:
            continue
        if cmd in ('exit', 'quit'): break
        if cmd == 'help':
            print("""
Commands:
  set target <value>     - Set target domain/IP
  show target            - Show current target
  show state             - Show session state keys
  recon                  - Run parallel recon
  plan                   - Generate attack plan
  route                  - Decide next exploit
  report                 - Generate final report
  auto                   - Run recon->plan->route->report
  exit                   - Quit
""")
            continue
        if cmd.startswith('set target '):
            target = cmd.split(' ', 2)[2].strip()
            session.state['initial_target'] = target
            print(f"Target set: {target}")
            continue
        if cmd == 'show target':
            print(f"Target: {session.state.get('initial_target')}")
            continue
        if cmd == 'show state':
            print(json.dumps({k: type(v).__name__ for k, v in session.state.items()}, indent=2))
            continue
        if cmd == 'recon':
            if not session.state.get('initial_target'):
                print("Set target first: set target <value>")
                continue
            res = loop.run_until_complete(run_recon(ctx))
            session.state['aggregated_recon_data'] = res
            print(f"Recon status: {res.get('status')}")
            continue
        if cmd == 'plan':
            res = loop.run_until_complete(run_plan(ctx))
            session.state['attack_plan'] = res
            print(f"Plan keys: {list(res.keys()) if isinstance(res, dict) else []}")
            continue
        if cmd == 'route':
            res = run_route(ctx)
            print(f"Next: {res}")
            continue
        if cmd == 'report':
            res = run_report(ctx)
            print("Report generated.")
            continue
        if cmd == 'auto':
            if not session.state.get('initial_target'):
                print("Set target first: set target <value>")
                continue
            res = loop.run_until_complete(run_auto(ctx, session.state['initial_target']))
            print(json.dumps(res, indent=2))
            continue
        print("Unknown command. Type 'help'.")


def main():
    parser = argparse.ArgumentParser(prog='phantomrecon', description='PhantomRecon CLI')
    parser.add_argument('--target', help='Target domain or IP')
    parser.add_argument('--auto', action='store_true', help='Run recon->plan->route->report')
    parser.add_argument('--nmap-timeout', type=int, help='Set NMAP_TIMEOUT env')
    parser.add_argument('--nmap-top-ports', type=str, help='Set NMAP_TOP_PORTS env')
    parser.add_argument('--nmap-args', type=str, help='Set NMAP_ARGS env')
    parser.add_argument('--nmap-disable', action='store_true', help='Disable Nmap (env)')
    args = parser.parse_args()

    # Apply env config for Nmap
    if args.nmap_timeout is not None:
        os.environ['NMAP_TIMEOUT'] = str(args.nmap_timeout)
    if args.nmap_top_ports is not None:
        os.environ['NMAP_TOP_PORTS'] = str(args.nmap_top_ports)
    if args.nmap_args is not None:
        os.environ['NMAP_ARGS'] = str(args.nmap_args)
    if args.nmap_disable:
        os.environ['NMAP_DISABLE'] = '1'

    if args.auto:
        if not args.target:
            print('--auto requires --target', file=sys.stderr)
            sys.exit(2)
        session = CliSession()
        ctx = CliContext(session)
        session.state['initial_target'] = args.target
        results = asyncio.run(run_auto(ctx, args.target))
        print(json.dumps(results))
        return

    # Default to interactive console if no actionable flags
    interactive_console()


if __name__ == '__main__':
    main()


