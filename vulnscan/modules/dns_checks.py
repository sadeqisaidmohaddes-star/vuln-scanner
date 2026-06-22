"""DNS hygiene checks, a scoped zone-transfer (AXFR) attempt, and wordlist
subdomain enumeration.

This module is a *detection-and-reporting* check only. It inspects published DNS
records for common email/authentication hygiene gaps (SPF, DMARC, CAA), attempts
an authorized zone transfer to detect misconfigured nameservers, and probes a
small bundled wordlist of subdomain labels to surface attack surface. It never
exploits anything, never dumps a whole zone, and degrades to an empty result on
any expected DNS failure.

All record/misconfiguration checks run unconditionally (they are passive lookups).
The AXFR attempt and the subdomain wordlist sweep are *intrusive* in spirit — they
fan out additional active queries — so they are skipped under ``--passive``.

dnspython is imported lazily inside :meth:`DnsChecksModule.run` so importing this
module stays cheap and free of third-party side effects.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING, Any, Optional

from ..core.datafiles import load_lines
from ..core.models import Finding, Severity
from ..core.module_base import ScannerModule

if TYPE_CHECKING:  # imported only for type-checking; avoids runtime import cost
    from ..core.context import ScanContext
    from ..core.models import Target


# How many sample record names to include from a successful zone transfer. We
# deliberately never dump the whole zone — only enough to evidence the finding.
_AXFR_SAMPLE_LIMIT = 5

# Cap on how many discovered subdomains we enumerate into a finding's evidence.
_SUBDOMAIN_EVIDENCE_LIMIT = 50


class DnsChecksModule(ScannerModule):
    """Check DNS hygiene records, attempt AXFR, and enumerate subdomains."""

    name = "dns_checks"
    description = "DNS hygiene (SPF/DMARC/CAA), zone-transfer attempt, and subdomain enumeration"
    category = "dns"
    default_severity = Severity.LOW
    intrusive = False
    order = 30

    def applicable(self, target: "Target", ctx: "ScanContext") -> bool:
        """Run only for domain/host targets whose host is not an IP literal.

        DNS hygiene checks make no sense for bare IP addresses, so we exclude any
        host that parses as an IPv4/IPv6 literal.
        """
        if target.kind not in ("domain", "host"):
            return False
        host = (target.host or "").strip()
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return True  # not an IP literal -> a name we can query
        return False

    async def run(self, target: "Target", ctx: "ScanContext") -> list[Finding]:
        """Perform the DNS checks for ``target`` and return any findings.

        This method never raises on expected DNS failures (NXDOMAIN, NoAnswer,
        timeouts, missing nameservers, etc.); those are caught and logged at debug
        level, yielding an empty or partial result instead.
        """
        # Lazily import dnspython; if it is somehow unavailable we degrade quietly.
        try:
            import dns.asyncresolver
            import dns.exception
            import dns.query
            import dns.resolver
            import dns.zone
        except ImportError as exc:  # pragma: no cover - dependency guaranteed by project
            ctx.log.debug("dns_checks: dnspython unavailable (%s); skipping", exc)
            return []

        domain = (target.host or "").strip().rstrip(".")
        if not domain:
            return []

        findings: list[Finding] = []

        resolver = dns.asyncresolver.Resolver()
        # Bound every lookup by the configured timeout. ``timeout`` is the
        # per-server budget; ``lifetime`` the total across retries/servers.
        resolver.timeout = ctx.config.timeout
        resolver.lifetime = ctx.config.timeout

        # -- passive: published-record hygiene ---------------------------------------
        findings.extend(await self._check_spf(resolver, domain, target, ctx))
        findings.extend(await self._check_dmarc(resolver, domain, target, ctx))
        findings.extend(await self._check_caa(resolver, domain, target, ctx))

        # -- intrusive: AXFR + subdomain wordlist (skipped under --passive) ----------
        if not ctx.config.passive:
            findings.extend(await self._attempt_axfr(resolver, domain, target, ctx))
            findings.extend(await self._enumerate_subdomains(resolver, domain, target, ctx))

        return findings

    # -- record lookups --------------------------------------------------------------

    async def _resolve_txt(
        self,
        resolver: Any,
        name: str,
        ctx: "ScanContext",
    ) -> list[str]:
        """Resolve TXT records for ``name`` into decoded strings (best effort).

        Returns an empty list on any expected DNS failure. dnspython splits a
        single TXT record into one or more quoted chunks; we re-join them.
        """
        import dns.exception
        import dns.resolver

        try:
            async with ctx.slot():
                answer = await resolver.resolve(name, "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as exc:
            ctx.log.debug("dns_checks: TXT lookup for %s failed: %s", name, exc)
            return []
        except dns.exception.DNSException as exc:  # any other dnspython error
            ctx.log.debug("dns_checks: TXT lookup for %s errored: %s", name, exc)
            return []

        records: list[str] = []
        for rdata in answer:
            try:
                chunks = getattr(rdata, "strings", None)
                if chunks is not None:
                    text = b"".join(chunks).decode("utf-8", "replace")
                else:  # pragma: no cover - defensive
                    text = str(rdata).strip('"')
            except Exception as exc:  # pragma: no cover - defensive
                ctx.log.debug("dns_checks: could not decode TXT for %s: %s", name, exc)
                continue
            records.append(text)
        return records

    async def _check_spf(
        self,
        resolver: Any,
        domain: str,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Report a missing SPF record, or an overly permissive ``+all`` policy."""
        records = await self._resolve_txt(resolver, domain, ctx)
        spf_records = [r for r in records if r.lower().startswith("v=spf1")]

        if not spf_records:
            return [
                self.finding(
                    title="No SPF record published",
                    severity=Severity.LOW,
                    description=(
                        f"The domain {domain} publishes no SPF (Sender Policy "
                        "Framework) TXT record. Without SPF, receivers cannot "
                        "verify which hosts are authorized to send mail for the "
                        "domain, easing email spoofing."
                    ),
                    target=target,
                    evidence={"domain": domain, "txt_records": records},
                    remediation=(
                        "Publish a TXT record starting with 'v=spf1' that lists "
                        "authorized senders and ends with a restrictive '-all' "
                        "(hard fail) or '~all' (soft fail) qualifier."
                    ),
                    references=[
                        "CWE-16",
                        "https://datatracker.ietf.org/doc/html/rfc7208",
                    ],
                    confidence="firm",
                )
            ]

        findings: list[Finding] = []
        permissive = [r for r in spf_records if "+all" in r.lower()]
        if permissive:
            findings.append(
                self.finding(
                    title="Overly permissive SPF record (+all)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The SPF record for {domain} contains '+all', which "
                        "authorizes any host on the Internet to send mail for the "
                        "domain. This effectively disables SPF protection and "
                        "enables trivial email spoofing."
                    ),
                    target=target,
                    evidence={"domain": domain, "spf_records": spf_records},
                    remediation=(
                        "Replace the trailing '+all' with '-all' (hard fail) or "
                        "'~all' (soft fail) and explicitly enumerate legitimate "
                        "sending hosts/services."
                    ),
                    references=[
                        "CWE-16",
                        "https://datatracker.ietf.org/doc/html/rfc7208",
                    ],
                    confidence="firm",
                )
            )
        return findings

    async def _check_dmarc(
        self,
        resolver: Any,
        domain: str,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Report a missing DMARC policy at ``_dmarc.<domain>``."""
        dmarc_name = f"_dmarc.{domain}"
        records = await self._resolve_txt(resolver, dmarc_name, ctx)
        dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]

        if dmarc_records:
            return []
        return [
            self.finding(
                title="No DMARC record published",
                severity=Severity.LOW,
                description=(
                    f"No DMARC policy was found at {dmarc_name}. DMARC lets a "
                    "domain owner instruct receivers how to handle mail that fails "
                    "SPF/DKIM alignment; without it, spoofed mail is harder to "
                    "detect and report."
                ),
                target=target,
                evidence={"queried": dmarc_name, "txt_records": records},
                remediation=(
                    "Publish a TXT record at _dmarc.<domain> starting with "
                    "'v=DMARC1' and a policy such as 'p=quarantine' or 'p=reject', "
                    "with an 'rua=' address to receive aggregate reports."
                ),
                references=[
                    "CWE-16",
                    "https://datatracker.ietf.org/doc/html/rfc7489",
                ],
                confidence="firm",
            )
        ]

    async def _check_caa(
        self,
        resolver: Any,
        domain: str,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Report the absence of any CAA record for ``domain`` (informational)."""
        import dns.exception
        import dns.resolver

        try:
            async with ctx.slot():
                answer = await resolver.resolve(domain, "CAA")
            has_caa = len(answer) > 0
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as exc:
            ctx.log.debug("dns_checks: CAA lookup for %s failed: %s", domain, exc)
            has_caa = False
        except dns.exception.DNSException as exc:
            ctx.log.debug("dns_checks: CAA lookup for %s errored: %s", domain, exc)
            has_caa = False

        if has_caa:
            return []
        return [
            self.finding(
                title="No CAA record published",
                severity=Severity.INFO,
                description=(
                    f"The domain {domain} publishes no CAA (Certification "
                    "Authority Authorization) record. CAA records constrain which "
                    "certificate authorities may issue certificates for the "
                    "domain, reducing the risk of mis-issuance."
                ),
                target=target,
                evidence={"domain": domain},
                remediation=(
                    "Publish a CAA record naming the CA(s) authorized to issue "
                    "certificates, e.g. '0 issue \"letsencrypt.org\"'."
                ),
                references=[
                    "CWE-295",
                    "https://datatracker.ietf.org/doc/html/rfc8659",
                ],
                confidence="firm",
            )
        ]

    # -- nameserver discovery --------------------------------------------------------

    async def _nameserver_ips(
        self,
        resolver: Any,
        domain: str,
        ctx: "ScanContext",
    ) -> list[str]:
        """Resolve the nameservers to attempt AXFR against, as IP strings.

        Prefers ``ctx.scope.nameservers`` when the scope explicitly lists them;
        otherwise falls back to the domain's published NS records. Each NS name is
        resolved to one or more A records. Returns a de-duplicated list; empty on
        any failure.
        """
        import dns.exception
        import dns.resolver

        ns_names: list[str] = []
        scope_ns = list(getattr(ctx.scope, "nameservers", []) or [])
        if scope_ns:
            ns_names = [n.strip().rstrip(".") for n in scope_ns if n and n.strip()]
        else:
            try:
                async with ctx.slot():
                    answer = await resolver.resolve(domain, "NS")
                ns_names = [str(rdata.target).rstrip(".") for rdata in answer]
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ) as exc:
                ctx.log.debug("dns_checks: NS lookup for %s failed: %s", domain, exc)
                return []
            except dns.exception.DNSException as exc:
                ctx.log.debug("dns_checks: NS lookup for %s errored: %s", domain, exc)
                return []

        ips: list[str] = []
        seen: set[str] = set()
        for ns in ns_names:
            if not ns:
                continue
            # A nameserver entry may already be an IP literal.
            try:
                ipaddress.ip_address(ns)
                if ns not in seen:
                    seen.add(ns)
                    ips.append(ns)
                continue
            except ValueError:
                pass
            try:
                async with ctx.slot():
                    a_answer = await resolver.resolve(ns, "A")
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ) as exc:
                ctx.log.debug("dns_checks: A lookup for nameserver %s failed: %s", ns, exc)
                continue
            except dns.exception.DNSException as exc:
                ctx.log.debug("dns_checks: A lookup for nameserver %s errored: %s", ns, exc)
                continue
            for rdata in a_answer:
                ip = str(rdata.address)
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        return ips

    # -- AXFR ------------------------------------------------------------------------

    async def _attempt_axfr(
        self,
        resolver: Any,
        domain: str,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Attempt a zone transfer against each nameserver; report any success.

        On a successful transfer we emit a single HIGH finding with the offending
        nameserver, the total record count, and at most :data:`_AXFR_SAMPLE_LIMIT`
        sample record names. We never dump the full zone. Refusals and errors
        produce no finding.
        """
        ns_ips = await self._nameserver_ips(resolver, domain, ctx)
        if not ns_ips:
            ctx.log.debug("dns_checks: no nameserver IPs resolved for %s; skipping AXFR", domain)
            return []

        findings: list[Finding] = []
        for nsip in ns_ips:
            zone = await self._try_xfr(nsip, domain, ctx)
            if zone is None:
                continue
            try:
                names = [name.to_text() for name in zone.nodes.keys()]
            except Exception as exc:  # pragma: no cover - defensive
                ctx.log.debug("dns_checks: could not enumerate AXFR nodes for %s: %s", domain, exc)
                names = []
            record_count = len(names)
            sample = sorted(names)[:_AXFR_SAMPLE_LIMIT]
            findings.append(
                self.finding(
                    title="Zone transfer (AXFR) allowed",
                    severity=Severity.HIGH,
                    description=(
                        f"The nameserver {nsip} permitted a full zone transfer "
                        f"(AXFR) of {domain}. This exposes the complete internal "
                        "DNS layout — every host, service, and subdomain — to any "
                        "anonymous client, dramatically aiding reconnaissance."
                    ),
                    target=target,
                    evidence={
                        "nameserver": nsip,
                        "record_count": record_count,
                        "sample_records": sample,
                    },
                    remediation=(
                        "Restrict AXFR to authorized secondary nameservers only "
                        "(allow-transfer / TSIG). Anonymous zone transfers should "
                        "be disabled on all public-facing nameservers."
                    ),
                    references=[
                        "CWE-200",
                        "https://owasp.org/www-community/attacks/DNS_zone_transfer",
                    ],
                    confidence="firm",
                )
            )
            # One confirmed misconfiguration is enough to demonstrate the issue.
            break
        return findings

    async def _try_xfr(
        self,
        nsip: str,
        domain: str,
        ctx: "ScanContext",
    ) -> Optional[Any]:
        """Attempt a single AXFR against ``nsip`` for ``domain``.

        Runs the blocking dnspython transfer in a worker thread so the event loop
        is not stalled. Returns the parsed zone on success, or ``None`` on refusal,
        timeout, or any error.
        """
        import dns.exception
        import dns.query
        import dns.zone

        timeout = ctx.config.timeout

        def _do_xfr() -> Any:
            return dns.zone.from_xfr(dns.query.xfr(nsip, domain, timeout=timeout))

        try:
            async with ctx.slot():
                return await asyncio.to_thread(_do_xfr)
        except (dns.exception.DNSException, OSError, EOFError, ConnectionError) as exc:
            ctx.log.debug("dns_checks: AXFR against %s for %s refused/failed: %s", nsip, domain, exc)
            return None
        except Exception as exc:  # pragma: no cover - last-resort safety net
            ctx.log.debug("dns_checks: AXFR against %s for %s errored: %s", nsip, domain, exc)
            return None

    # -- subdomain enumeration -------------------------------------------------------

    async def _enumerate_subdomains(
        self,
        resolver: Any,
        domain: str,
        target: "Target",
        ctx: "ScanContext",
    ) -> list[Finding]:
        """Resolve a bundled wordlist of subdomain labels and report any that exist.

        Each candidate ``<label>.<domain>`` is resolved for an A record under the
        shared rate limiter. Discovered names are collapsed into a single INFO
        finding, with the evidence list capped at
        :data:`_SUBDOMAIN_EVIDENCE_LIMIT`.
        """
        try:
            labels = load_lines("subdomains.txt")
        except (OSError, ValueError) as exc:
            ctx.log.debug("dns_checks: could not load subdomains.txt: %s", exc)
            return []
        if not labels:
            return []

        discovered: list[str] = []
        for label in labels:
            candidate = f"{label}.{domain}"
            if await self._resolves_a(resolver, candidate, ctx):
                discovered.append(candidate)

        if not discovered:
            return []

        total = len(discovered)
        listed = discovered[:_SUBDOMAIN_EVIDENCE_LIMIT]
        return [
            self.finding(
                title=f"Subdomains discovered via wordlist ({total})",
                severity=Severity.INFO,
                description=(
                    f"{total} subdomain(s) of {domain} resolved from a common "
                    "wordlist. Each is additional attack surface that should be "
                    "inventoried and assessed."
                ),
                target=target,
                evidence={
                    "domain": domain,
                    "count": total,
                    "subdomains": listed,
                    "truncated": total > len(listed),
                },
                remediation=(
                    "Maintain an inventory of all DNS names that resolve, retire "
                    "stale/forgotten hosts, and ensure each exposed service is "
                    "intended to be public and is patched."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                confidence="firm",
            )
        ]

    async def _resolves_a(
        self,
        resolver: Any,
        name: str,
        ctx: "ScanContext",
    ) -> bool:
        """Return whether ``name`` resolves to at least one A record.

        Swallows every expected DNS failure (returning ``False``); a name that does
        not exist is simply not "discovered".
        """
        import dns.exception
        import dns.resolver

        try:
            async with ctx.slot():
                answer = await resolver.resolve(name, "A")
            return len(answer) > 0
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as exc:
            ctx.log.debug("dns_checks: A lookup for %s failed: %s", name, exc)
            return False
        except dns.exception.DNSException as exc:
            ctx.log.debug("dns_checks: A lookup for %s errored: %s", name, exc)
            return False
