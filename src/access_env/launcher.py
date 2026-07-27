from __future__ import annotations

import os
import sys


REMOVED_BEFORE_FINAL_COMMAND = {
    "OP_SERVICE_ACCOUNT_TOKEN",
    "OP_RUN_NO_MASKING",
    "DBUS_SESSION_BUS_ADDRESS",
    "NOTIFY_SOCKET",
    "JOURNAL_STREAM",
    "SYSTEMD_EXEC_PID",
    "INVOCATION_ID",
}


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] != "--" or len(arguments) == 1:
        print("internal launcher requires -- COMMAND", file=sys.stderr)
        return 2
    command = arguments[1:]
    environment = os.environ.copy()
    private_runtime = environment.pop("ACCESS_PRIVATE_RUNTIME", None)
    for variable in REMOVED_BEFORE_FINAL_COMMAND:
        environment.pop(variable, None)
    environment.pop("XDG_RUNTIME_DIR", None)
    if not private_runtime or not os.path.isabs(private_runtime):
        print("access: private runtime is unavailable", file=sys.stderr)
        return 126
    environment["XDG_RUNTIME_DIR"] = private_runtime
    try:
        os.execvpe(command[0], command, environment)
    except OSError:
        print("access: command could not be executed", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
