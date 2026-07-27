from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from .bundles import Bundle, BundleError, BundleRegistry, default_root
from .execution import ExecutionError, run_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="access",
        description="Inspect trusted development-access bundle configuration.",
    )
    parser.add_argument(
        "--config-root",
        type=Path,
        default=default_root(),
        help="trusted registry root (default: ~/.config/access)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="include diagnostic details such as the trusted-root path",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list configured bundles")
    subparsers.add_parser("status", help="validate bootstrap configuration")
    run_parser = subparsers.add_parser(
        "run", help="run an exact argv under a development/build bundle"
    )
    run_parser.add_argument("bundle", help="trusted bundle name")
    run_parser.add_argument(
        "command_argv",
        nargs=argparse.REMAINDER,
        help="-- COMMAND [ARG ...]",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_arguments)
    if args.command == "run":
        args.has_command_separator = any(
            raw_arguments[index : index + 3] == ["run", args.bundle, "--"]
            for index in range(max(0, len(raw_arguments) - 2))
        )
    try:
        registry = BundleRegistry(args.config_root)
        if args.command == "list":
            return _list_bundles(registry)
        if args.command == "status":
            return _status(registry, verbose=args.verbose)
        return _run(registry, args)
    except (BundleError, ExecutionError) as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return 2


def _validated_bundles(registry: BundleRegistry) -> list[Bundle]:
    if not registry.root.is_dir():
        raise BundleError("trusted root does not exist or is not a directory")
    return [registry.load(name) for name in registry.names()]


def _list_bundles(registry: BundleRegistry) -> int:
    bundles = _validated_bundles(registry)
    if not bundles:
        print("No bundles configured.")
        return 0
    print("NAME\tPROVIDERS\tCAPABILITIES\tRISK\tDESCRIPTION")
    for bundle in bundles:
        print(
            f"{bundle.name}\t{','.join(bundle.providers)}\t"
            f"{','.join(bundle.capabilities)}\t{bundle.risk}\t{bundle.description}"
        )
    return 0


def _status(registry: BundleRegistry, *, verbose: bool = False) -> int:
    bundles = _validated_bundles(registry)
    print("configuration: ready")
    if verbose:
        print(f"trusted root: {registry.root}")
    print(f"bundles: {len(bundles)} valid")
    print("credential resolution: not implemented")
    return 0


def _run(registry: BundleRegistry, args: argparse.Namespace) -> int:
    command = args.command_argv
    if not args.has_command_separator or not command:
        raise ExecutionError("access run requires BUNDLE -- COMMAND")
    bundle = registry.load(args.bundle)
    token_file = registry.root / "bootstrap-token"
    runtime_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_value:
        raise ExecutionError("validated XDG_RUNTIME_DIR is required")
    try:
        return_code = run_bundle(
            bundle,
            command,
            op_executable="/usr/bin/op",
            bootstrap_token_file=token_file,
            inherited_env=os.environ,
            xdg_runtime_dir=Path(runtime_value),
        )
    except KeyboardInterrupt:
        return 130
    return 128 + (-return_code) if return_code < 0 else return_code


if __name__ == "__main__":
    raise SystemExit(main())
