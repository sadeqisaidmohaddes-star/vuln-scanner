# Custom plugins

Drop a `.py` file in this directory that defines a subclass of `ScannerModule`,
and it will be discovered and run automatically — no registration required.

```python
# vulnscan/plugins/my_check.py
from vulnscan import ScannerModule, Severity


class RobotsExposure(ScannerModule):
    name = "robots_check"
    description = "Reports whether /robots.txt is present and what it discloses."
    category = "web"
    default_severity = Severity.INFO
    intrusive = False          # set True for active probing (skipped under --passive)
    order = 50                 # lower runs earlier; >50 runs after discovery modules

    def applicable(self, target, ctx) -> bool:
        return target.is_web

    async def run(self, target, ctx):
        findings = []
        url = target.base_url().rstrip("/") + "/robots.txt"
        try:
            resp = await ctx.http_get(url)
        except Exception:
            return findings
        if resp.status_code == 200:
            findings.append(self.finding(
                title="robots.txt present",
                severity=Severity.INFO,
                description="A robots.txt file is reachable and may disclose paths.",
                target=target,
                evidence={"url": url, "status": resp.status_code},
                remediation="Ensure robots.txt does not reference sensitive paths.",
            ))
        return findings
```

## Rules of the interface

- Set a unique `name` (used by `--modules` and as `Finding.module`).
- Implement `async def run(self, target, ctx) -> list[Finding]`.
- Build findings with `self.finding(...)` (it fills in the module name).
- Use `ctx.http_get / ctx.http_request / ctx.open_connection` so the global
  rate limit and concurrency cap are honoured.
- Catch your own expected errors and return `[]`; the engine isolates crashes
  but well-behaved modules degrade gracefully.
- Honour the detection-only contract: **never** exfiltrate data, run destructive
  payloads, or perform actions beyond what is needed to *detect and report*.

You can also keep plugins outside the package and load them with
`--plugins-dir /path/to/dir`.
