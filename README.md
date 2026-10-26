# Log Redactor — strip credential-looking values from logs

Redacts secrets from log text by field NAME before a log is
shared with support, a client, or a public issue, so the log
can leave the machine without the credentials leaving with it.

## Rules (per line)

- Fields named `password`, `passwd`, `secret`, `api_key`,
  `token`, `private_key`, `auth_token`, `session_token`:
  the value after `:` or `=` becomes `[REDACTED]`
  (quotes preserved when the original value was quoted,
  including JSON `"password": "value"`).
- `Bearer <token>` becomes `Bearer [REDACTED]`.

## Usage

```
python3 log_redactor.py <input.log> <output.log>
python3 log_redactor.py -            # stdin -> stdout
```

Exit `0` on success, `2` on usage error. Counts of lines
processed and values redacted go to stderr.

The tool never overwrites its input: if the output path
equals the input path, it refuses with exit 2.

## Proof (this package, re-run on the copies)

- 5-line test log (password assignment, JSON `api_key`,
  Bearer token, secret assignment, one clean line):
  4 redactions, 0 leaks of the planted fake values, exit 0
- In-place run (input path = output path): refused, exit 2

## Honest limit

Redaction by field name only catches values that sit next to
a sensitive name. A bare secret on a line with no field name
will NOT be caught. Review the output before sharing anything
that ever held real credentials.

## License

No license file ships with this repo, so all rights reserved
by default.
