"""One entry point: hazmat <command> [flags].

Each command keeps its own module, so `python3 -m hazmat.scan` still works; this
only routes. Flags belong to the command, so argv is handed over untouched.
"""
import sys

from . import anchor, batch, confirm, derive, match, schema_check, selfcheck, serve, verify, watch

COMMANDS = {
    'scan': (match, 'match one target (address, bytecode or file)'),
    'batch': (batch, 'match many targets from a file'),
    'derive': (derive, 'derive selectors from source and check them against code'),
    'confirm': (confirm, 'fetch, rebuild, compare and probe a placard'),
    'verify': (verify, 're-derive a sheet digest, or re-check a record'),
    'selfcheck': (selfcheck, 'every placard fires on its target and stays quiet elsewhere'),
    'serve': (serve, 'serve the paste-a-target page, sheets and the JSON API'),
    'watch': (watch, 'watch new verifications and upgrades, and alert'),
    'anchor': (anchor, 'merkle-root the register, prove a placard, verify a proof'),
    'validate': (schema_check, 'validate every placard against the schema, without dependencies'),
}


def usage():
    width = max(len(name) for name in COMMANDS)
    lines = ['usage: hazmat <command> [flags]', '']
    lines += ['  %-*s  %s' % (width, name, helptext) for name, (_, helptext) in sorted(COMMANDS.items())]
    lines += ['', 'run `hazmat <command> --help` for a command\'s flags']
    return '\n'.join(lines)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(usage())
        return 0
    command, rest = argv[0], argv[1:]
    if command not in COMMANDS:
        sys.stderr.write('unknown command: %s\n\n%s\n' % (command, usage()))
        return 2
    module = COMMANDS[command][0]
    try:
        return module.main(rest)
    except SystemExit as exc:
        return exc.code or 0
    except Exception as exc:  # a failure must still exit non-zero and say why
        sys.stderr.write('%s: %s\n' % (type(exc).__name__, exc))
        return 1


if __name__ == '__main__':
    sys.exit(main())
