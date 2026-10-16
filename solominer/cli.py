"""Command-line interface shared by repository scripts and installed service."""
import argparse
import json
import sys
import subprocess
from pathlib import Path
from . import __version__, admin, runtime
from .config import DEFAULT_CONFIG

def parser():
    result = argparse.ArgumentParser(description="Fedora SoloMiner secure service controls")
    result.add_argument("--version", action="version", version=__version__)
    subs = result.add_subparsers(dest="command", required=True)
    for name in ("run", "status", "doctor", "health"):
        sub = subs.add_parser(name)
        sub.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
        if name in ("status", "doctor"):
            sub.add_argument("--json", action="store_true", help="Print machine-readable diagnostics")
    for name in ("install", "update"):
        sub = subs.add_parser(name)
        sub.add_argument("--install-deps", action="store_true", help="Install Fedora build prerequisites")
        sub.add_argument("--update-packages", action="store_true", help="Explicitly upgrade Fedora packages")
        group = sub.add_mutually_exclusive_group()
        group.add_argument("--no-restart", action="store_true", help="Build and stage without activating")
        group.add_argument("--activate-staged", action="store_true", help="Activate the previously staged build")
        sub.add_argument("--check", action="store_true", help="Compare this checkout with installed provenance")
        if name == "install":
            sub.add_argument("--migrate", action="store_true", help="Require and preserve existing configuration")
    subs.add_parser("rollback", help="Restore the previous executable, control plane, and unit")
    subs.add_parser("apply-config", help="Validate and apply settings without rebuilding the miner")
    return result

def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in ("install", "update"):
            if args.check:
                print(json.dumps(admin.check_update(), indent=2))
            else:
                admin.install_or_update(args)
        elif args.command == "rollback":
            admin.rollback()
        elif args.command == "apply-config":
            admin.apply_config()
        elif args.command == "run":
            runtime.run_miner(config_path=args.config)
        elif args.command == "health":
            result = runtime.health_check(config_path=args.config)
            if result.get("changed"):
                print(json.dumps(result, sort_keys=True))
            # Conditions are logged on change; a failing oneshot would spam journald.
        else:
            result = runtime.report(config_path=args.config)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"SoloMiner {__version__}")
                service = result.get("service", {})
                print(f"Service: {service.get('ActiveState', 'unknown')}/{service.get('SubState', 'unknown')}  PID: {service.get('MainPID', 'unknown')}")
                config = result.get("configuration", {})
                if config:
                    print(f"Pool: {config.get('pool')}  Worker: {config.get('worker')}  Threads: {config.get('threads')}")
                    if config.get("fallback_pools"):
                        print("Configured fallbacks: " + ", ".join(config["fallback_pools"]))
                    print(f"CPU budget: {config.get('cpu_quota')}  Memory ceiling: {config.get('memory_max')}  Temperature limit: {config.get('max_temp')}C")
                print(f"Current memory: {service.get('MemoryCurrent', 'unknown')} bytes  Tasks: {service.get('TasksCurrent', 'unknown')}")
                print(f"Miner: {result.get('version', 'unknown')}")
                readings = result.get("temperatures", [])
                if readings:
                    print(f"Hottest CPU sensor: {max(item['celsius'] for item in readings):.1f}C")
                for check in result.get("checks", []):
                    label = "OK" if check.get("ok") else check.get("severity", "error").upper()
                    print(f"[{label}] {check.get('name')}: {check.get('message')}")
            return 0 if result.get("ok") else 1
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"SoloMiner: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("SoloMiner: interrupted; existing installation retained or restored.", file=sys.stderr)
        return 130

