#!/usr/bin/env python3
"""log_redactor.py — #9 on the top-50 profit builds.

Strips credential-looking values from log text before it is
shared, so a log file can be sent to support, a client, or a
public issue without leaking secrets.

  python3 log_redactor.py <input.log> <output.log>
  python3 log_redactor.py -            (stdin -> stdout)

Redaction rules (by field NAME, applied per line):
  - JSON / assignment fields named password, passwd, secret,
    api_key, token, private_key, auth_token, session_token:
    the value after : or = becomes [REDACTED] (quotes kept
    when the original value was quoted).
  - "Bearer <token>" becomes "Bearer [REDACTED]".

The tool never overwrites its input: if output equals input
it refuses. Counts lines processed and values redacted on
stderr. Exit 0 on success, 2 on usage error.

Honest limit: redaction by field name only catches values
that sit next to a sensitive name. A bare secret on a line
with no field name will NOT be caught — review the output
before sharing anything that ever held real credentials.
"""
import re
import sys

FIELD = re.compile(
    r"(?i)([\"']?)(password|passwd|secret|api[_-]?key|token|private[_-]?key"
    r"|auth_token|session_token)([\"']?)(\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|\S+)")
BEARER = re.compile(r"(?i)(Bearer\s+)\S+")


def redact_value(match):
    q1, name, q2, sep, value = match.groups()
    if value[:1] in ("\"", "'"):
        new_value = f"{value[0]}[REDACTED]{value[0]}"
    else:
        new_value = "[REDACTED]"
    return f"{q1}{name}{q2}{sep}{new_value}"


def redact_line(line):
    before = line
    line = FIELD.sub(redact_value, line)
    line = BEARER.sub(r"\1[REDACTED]", line)
    return line, line != before


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: log_redactor.py <input.log|-> [<output.log>]")
        return 2
    src, dst = sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None
    if src != "-" and dst is not None and src == dst:
        print("error: refusing to overwrite the input file")
        return 2
    if src == "-":
        lines = sys.stdin.read().splitlines(keepends=True)
    else:
        try:
            with open(src, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            print(f"error: cannot read {src}: {exc}")
            return 2
    out_lines = []
    redacted = 0
    for line in lines:
        new, changed = redact_line(line)
        out_lines.append(new)
        if changed:
            redacted += 1
    text = "".join(out_lines)
    if dst is None:
        sys.stdout.write(text)
    else:
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(f"lines: {len(lines)}, values redacted: {redacted}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
