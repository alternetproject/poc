import argparse
import http.client
import json
import logging
import sqlite3
import sys
import time

from .client import fetch
from .config import Config
from .node import RelayServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Alternet: minimal direct-first HTTPS routing experiment")
    commands = parser.add_subparsers(dest="command", required=True)
    node = commands.add_parser("node", help="run a relay listener")
    node.add_argument("--config", required=True)
    node.add_argument("--ready-file", help=argparse.SUPPRESS)
    client = commands.add_parser("fetch", help="fetch an HTTPS URL directly or through peers")
    client.add_argument("--config", required=True)
    client.add_argument("--ca", help="explicit PEM CA file (otherwise use the system trust store)")
    client.add_argument("url")
    commands.add_parser("demo", help="run all three local routing scenarios")
    commands.add_parser("demo-discovery", help="demonstrate automatic discovery and recovery under partial blocking")
    commands.add_parser("demo-peers", help="demonstrate open joining, peer exchange, and bootstrap-independent recovery")
    peers = commands.add_parser("discover", help="refresh and list reachable peers",
                                description="Discover peers using configured bootstrap addresses and cached contacts.")
    peers.add_argument("--config", required=True)
    shared = commands.add_parser("demo-shared", help="measure shared-endpoint blocking and a selective-blocking counterexample")
    shared.add_argument("--json", action="store_true")
    commands.add_parser("demo-carrier", help="test the browser-free libcurl carrier against previous TLS filters")
    resilience = commands.add_parser("demo-resilience", help="test entry replacement against rescanning and ciphertext filtering")
    resilience.add_argument("--json", action="store_true")
    resilience.add_argument("--output", help="save the complete measured JSON report")
    resilience.add_argument("--trials", type=int, default=2)
    recovery = commands.add_parser("demo-recovery", help="measure continuous recovery versus ongoing IP enumeration")
    recovery.add_argument("--json", action="store_true")
    recovery.add_argument("--output", help="save measured timelines and per-client results as JSON")
    recovery.add_argument("--modes", nargs="+", choices=("unfiltered", "frozen", "continuous_slow", "continuous_fast"),
                          default=("unfiltered", "frozen", "continuous_slow", "continuous_fast"))
    recovery.add_argument("--step-seconds", type=float, default=2)
    recovery.add_argument("--rounds", type=int, default=6)
    recovery.add_argument("--tail-seconds", type=float, default=5)
    recovery.add_argument("--peer-count", type=int, default=4, help="finite relay-capable population, 4 to 16")
    recovery.add_argument("--client-policy", choices=("supplied", "advertised"), default="supplied",
                          help="try supplied contact hints on failure, or wait for positive public advertisements")
    discovery = commands.add_parser("discovery", help="run an HTTPS discovery service and optional gateway")
    discovery.add_argument("--config", required=True)
    discovery.add_argument("--ready-file", help=argparse.SUPPRESS)
    origin = commands.add_parser("_origin", help="internal demo HTTPS fixture")
    for option in ("cert", "key", "body", "ready-file"):
        origin.add_argument("--" + option, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    if args.command.startswith("demo"):
        logging.getLogger("alternet").setLevel(logging.WARNING)
    try:
        if args.command == "node":
            from .lab import write_ready
            config = Config.load(args.config)
            with RelayServer(config) as server:
                logging.info("[%s] listening on %s:%s; relay=%s", config.name,
                             server.server_address[0], server.server_address[1], config.relay)
                write_ready(args.ready_file, server.server_address)
                server.serve_forever(poll_interval=0.1)
        elif args.command == "fetch":
            result = fetch(Config.load(args.config), args.url, ca_file=args.ca)
            sys.stdout.buffer.write(result.body)
            sys.stdout.buffer.flush()
            return 0 if result.status < 400 else 1
        elif args.command == "demo":
            from .demo import run
            run()
        elif args.command == "demo-discovery":
            from .discovery_demo import run
            run()
        elif args.command == "demo-peers":
            from .peer_demo import run
            run()
        elif args.command == "discover":
            from .peer_discovery import PeerDiscovery
            config = Config.load(args.config)
            if config.gateway_only:
                raise ValueError("ordinary peer discovery is disabled in gateway_only mode")
            manager = PeerDiscovery(config)
            try:
                manager.refresh(time.monotonic() + 10, force=True)
                contacts = manager.book.live()
                print(json.dumps({"peers": contacts}, indent=2))
                if not contacts:
                    raise RuntimeError("no reachable contacts; configure a reachable ordinary node in bootstrap "
                                       "or reuse a populated peer_cache")
            finally:
                manager.close()
        elif args.command == "demo-shared":
            from experiments.shared_endpoint import run
            run(as_json=args.json)
        elif args.command == "demo-carrier":
            from experiments.transport_carrier import run
            run()
        elif args.command == "demo-resilience":
            from experiments.entry_resilience import run
            run(as_json=args.json, output=args.output, trials=args.trials)
        elif args.command == "demo-recovery":
            from experiments.recovery_race import run
            run(as_json=args.json, output=args.output, modes=args.modes,
                step_seconds=args.step_seconds, rounds=args.rounds, tail_seconds=args.tail_seconds,
                peer_count=args.peer_count, client_policy=args.client_policy)
        elif args.command == "discovery":
            from .discovery import DiscoveryServer, ServiceConfig
            from .lab import write_ready
            config = ServiceConfig.load(args.config)
            with DiscoveryServer(config) as server:
                logging.info("[%s] HTTPS discovery listening on %s:%s; gateway=%s", config.node.name,
                             server.server_address[0], server.server_address[1], config.node.relay)
                write_ready(args.ready_file, server.server_address)
                server.serve_forever(poll_interval=0.1)
        else:
            from .lab import serve_origin
            serve_origin(args.cert, args.key, args.body, args.ready_file)
    except KeyboardInterrupt:
        logging.info("Stopped.")
        return 130
    except (OSError, ValueError, RuntimeError, sqlite3.Error, http.client.HTTPException) as exc:
        logging.error("ERROR: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
