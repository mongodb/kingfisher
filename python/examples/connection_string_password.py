"""Use built-in connection-string rules, scan offline, and print redacted findings.

From a source checkout or unpacked sdist:
  python python/examples/connection_string_password.py
"""
from kingfisher_sdk import Rules, Scanner


def main():
    # Built-in rules cover connection strings; broad generic rules remain excluded.
    # Compile once and reuse. Scanning does not contact the database.
    scanner = Scanner(Rules())
    for finding in scanner.scan("Host=db.internal;Username=app;Password=opensaysme;"):
        if finding.visible:
            print(finding.to_dict())  # Secrets and captures are redacted by default.


if __name__ == "__main__":
    main()
