"""Execution-profile guard — enforces the non-destructive profile in code.

Defence in depth on top of per-tool ``forbidden_flags``: a *global* denylist of
destructive tokens (data dump, OS/SQL shell, file write, blind/OOB exploitation,
persistence) that is rejected on **every** command regardless of which tool
proposed it or what the LLM asked for. The destructive class is not loadable;
this guard ensures even a permitted tool cannot be pushed into destructive
behaviour by flag.

``non_destructive`` is the only profile that enables execution. Any other
profile fails closed (nothing runs) until an explicit, reviewed profile is added.
"""

from __future__ import annotations

from safeguard.safety.exceptions import ProfileViolation

# Destructive / data-exfiltrating / persistence-enabling tokens. Matched against
# each command token's flag head (``--flag`` from ``--flag=value``) and whole
# tokens. Curated, deny-by-default.
DESTRUCTIVE_TOKENS = frozenset({
    # data extraction
    "--dump", "--dump-all", "--dumps", "--passwords", "--file-read",
    # write / code exec / shells
    "--file-write", "--file-dest", "--os-shell", "--os-cmd", "--os-pwn",
    "--sql-shell", "--sql-query", "--exploit", "--shell", "--reverse",
    # blind / out-of-band exploitation
    "--blind", "--oob", "--interactsh-server",
    # destructive HTTP methods driven explicitly
    "--method=delete", "--method=put",
    # persistence / registry / crontab
    "--reg-add", "--reg-write", "--crontab",
})


class ProfileGuard:
    def __init__(self, profile: str = "non_destructive") -> None:
        self.profile = profile

    def check(self, command: list[str]) -> None:
        if self.profile != "non_destructive":
            # Fail closed: no other profile is enabled for execution.
            raise ProfileViolation(
                f"profile '{self.profile}' is not enabled for execution")
        for token in command:
            head = token.split("=", 1)[0].lower()
            whole = token.lower()
            if whole in DESTRUCTIVE_TOKENS or head in DESTRUCTIVE_TOKENS:
                raise ProfileViolation(
                    f"token {token!r} is destructive and forbidden by the "
                    "non_destructive profile")
