"""Static module that flags sensitive files committed to a repository.

This module walks the working tree and classifies files that should never be
committed to source control: private keys, environment files holding secrets,
cloud-provider credentials, infrastructure state, database dumps, backups, and
similar artefacts. It is strictly detection-and-reporting: it reads file
*content* only for a small set of cases where the filename alone is ambiguous
(e.g. ``.npmrc`` may or may not contain an auth token), and it never includes
file contents in findings -- only the relative path, a classification label,
and boolean confirmation flags.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ...core.models import Finding, Severity
from ..module_base import StaticModule

if TYPE_CHECKING:
    from ..context import RepoContext


# Filename suffixes that almost always indicate a private key or credential
# store. Matched case-insensitively against the file suffix.
_KEY_SUFFIXES: frozenset[str] = frozenset(
    {".pem", ".key", ".ppk", ".p12", ".pfx", ".keystore", ".jks"}
)

# Exact filenames that are private keys regardless of extension.
_KEY_NAMES: frozenset[str] = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})

# Database dump / embedded-database suffixes (MEDIUM).
_DB_SUFFIXES: frozenset[str] = frozenset({".sql", ".sqlite", ".sqlite3", ".db"})

# Backup / editor-swap suffixes (MEDIUM).
_BACKUP_SUFFIXES: frozenset[str] = frozenset({".bak", ".backup", ".old", ".swp"})

# Filenames that, when read, indicate committed secrets if a token marker is
# present. Maps the exact filename to the markers we look for in its content.
_TOKEN_FILE_MARKERS: dict[str, tuple[str, ...]] = {
    ".npmrc": ("_auth", "_authtoken", "_password", "password", "token"),
    ".pypirc": ("password", "token", "username"),
}

# Markers that confirm a JSON file is a GCP service-account key.
_GCP_MARKERS: tuple[str, ...] = ("private_key", "client_email")

# Cap on findings emitted per classification rule to avoid pathological repos
# producing thousands of findings.
_MAX_PER_RULE: int = 25


class SensitiveFilesModule(StaticModule):
    """Flag files that should never be committed to a repository.

    Classifies each file in the working tree by name, suffix, and (for a few
    ambiguous cases) content, then emits a :class:`Finding` per offending file
    with a severity reflecting the exposure risk. Environment *example* files
    (``.env.example`` and friends) are reported at ``INFO`` as a hygiene note.
    """

    name = "sensitive_files"
    description = "Flags sensitive files (keys, .env, credentials, dumps) committed to the repo."
    category = "exposure"
    default_severity = Severity.HIGH
    order = 10

    # Shared finding metadata.
    _REFERENCES = ["CWE-538", "CWE-312"]
    _REMEDIATION = (
        "Remove from the repository, rotate any exposed credentials, add the "
        "path to .gitignore, and purge it from git history (deletion alone "
        "leaves it in history)."
    )

    def applicable(self, repo: "RepoContext") -> bool:
        """Always applicable: every repository is worth checking for secrets."""
        return True

    async def run(self, repo: "RepoContext") -> list[Finding]:
        """Walk the working tree and emit a finding per sensitive file found."""
        findings: list[Finding] = []
        # Per-rule counters so we can cap noisy classifications independently.
        counts: dict[str, int] = {}

        try:
            for path in repo.iter_files():
                try:
                    classified = self._classify(repo, path)
                except Exception:  # noqa: BLE001 - never let one file abort the walk
                    continue
                if classified is None:
                    continue

                category, severity, confidence, why, extra_evidence = classified
                if counts.get(category, 0) >= _MAX_PER_RULE:
                    continue
                counts[category] = counts.get(category, 0) + 1

                rel = repo.rel(path)
                evidence: dict[str, object] = {"file": rel, "category": category}
                evidence.update(extra_evidence)
                findings.append(
                    self.finding(
                        title=f"Sensitive file committed: {rel}",
                        severity=severity,
                        description=why,
                        target=repo.finding_target(path),
                        evidence=evidence,
                        remediation=self._REMEDIATION,
                        references=list(self._REFERENCES),
                        confidence=confidence,
                    )
                )
        except Exception:  # noqa: BLE001 - degrade gracefully on walk failure
            return findings

        return findings

    # -- classification -----------------------------------------------------------

    def _classify(
        self, repo: "RepoContext", path: Path
    ) -> Optional[tuple[str, Severity, str, str, dict[str, object]]]:
        """Classify ``path`` or return ``None`` if it is not sensitive.

        Returns a tuple ``(category, severity, confidence, description, extra)``
        where ``extra`` holds additional non-sensitive evidence fields (never
        file contents -- only booleans/labels).
        """
        name = path.name
        lname = name.lower()
        suffix = path.suffix.lower()
        rel_lower = repo.rel(path).lower()

        # -- private keys / credential stores (CRITICAL) --------------------------
        if name in _KEY_NAMES or suffix in _KEY_SUFFIXES:
            return (
                "private_key",
                Severity.CRITICAL,
                "firm",
                "A private key or credential store appears to be committed to the "
                "repository. Anyone with read access to the repo (or its history) "
                "can use it to impersonate the owner or decrypt protected data.",
                {},
            )

        # -- environment files ----------------------------------------------------
        env_result = self._classify_env(lname)
        if env_result is not None:
            return env_result

        # -- cloud / VCS / shell credential files (CRITICAL/HIGH) -----------------
        # Match by relative path so e.g. ".aws/credentials" or ".kube/config" hit
        # regardless of where in the tree they live.
        if rel_lower.endswith(".aws/credentials") or (lname == "credentials" and "/.aws/" in f"/{rel_lower}"):
            return (
                "aws_credentials",
                Severity.CRITICAL,
                "firm",
                "AWS credentials file committed to the repository. Long-lived "
                "access keys here grant programmatic access to the AWS account.",
                {},
            )
        if lname == ".git-credentials":
            return (
                "git_credentials",
                Severity.CRITICAL,
                "firm",
                "A .git-credentials file stores plaintext credentials for remote "
                "git hosts and must never be committed.",
                {},
            )
        if lname == ".netrc" or lname == "_netrc":
            return (
                "netrc",
                Severity.HIGH,
                "firm",
                "A .netrc file stores plaintext login credentials for remote "
                "hosts (FTP/HTTP) and must never be committed.",
                {},
            )
        if lname == ".pgpass":
            return (
                "pgpass",
                Severity.HIGH,
                "firm",
                "A .pgpass file stores plaintext PostgreSQL passwords and must "
                "never be committed.",
                {},
            )

        # -- terraform state (CRITICAL) ------------------------------------------
        if lname == "terraform.tfstate" or suffix == ".tfstate" or lname.endswith(".tfstate.backup"):
            return (
                "terraform_state",
                Severity.CRITICAL,
                "firm",
                "Terraform state often embeds secrets (DB passwords, access keys, "
                "private keys) in plaintext. Committed state exposes them.",
                {},
            )

        # -- GCP service-account key (CRITICAL, content-confirmed) ----------------
        gcp_result = self._classify_gcp(repo, path, lname, suffix)
        if gcp_result is not None:
            return gcp_result

        # -- kube config (CRITICAL) ----------------------------------------------
        if rel_lower.endswith(".kube/config") or lname == "kubeconfig":
            return (
                "kube_config",
                Severity.CRITICAL,
                "firm",
                "A Kubernetes kubeconfig grants cluster access and typically "
                "embeds client certificates or bearer tokens.",
                {},
            )

        # -- docker config.json with "auths" (HIGH, content-confirmed) -----------
        if lname == "config.json" and (".docker" in rel_lower or rel_lower.endswith("docker/config.json")):
            text = repo.read_text(path)
            if text is not None and '"auths"' in text:
                return (
                    "docker_config",
                    Severity.HIGH,
                    "firm",
                    "A Docker config.json containing an 'auths' block stores "
                    "registry credentials (often base64-encoded) and must not be "
                    "committed.",
                    {"auths_present": True},
                )
            return None

        # -- npmrc / pypirc with auth token (HIGH, content-confirmed) ------------
        token_result = self._classify_token_file(repo, path, lname)
        if token_result is not None:
            return token_result

        # -- .htpasswd (LOW) ------------------------------------------------------
        if lname == ".htpasswd":
            return (
                "htpasswd",
                Severity.LOW,
                "firm",
                "An .htpasswd file holds (hashed) HTTP Basic Auth credentials. "
                "Committed hashes can be cracked offline; it should not be in the repo.",
                {},
            )

        # -- database dumps (MEDIUM) ---------------------------------------------
        if suffix in _DB_SUFFIXES:
            return (
                "database_dump",
                Severity.MEDIUM,
                "firm",
                "A database dump or embedded database file may contain production "
                "data (PII, password hashes, secrets) and should not be committed.",
                {},
            )

        # -- backups / editor swap files (MEDIUM) --------------------------------
        if suffix in _BACKUP_SUFFIXES or (name.endswith("~") and not name.startswith(".")):
            return (
                "backup_file",
                Severity.MEDIUM,
                "firm",
                "A backup or editor swap file may contain an older or working copy "
                "of source/config (including secrets) and should not be committed.",
                {},
            )

        # -- backup-looking archives (MEDIUM) ------------------------------------
        archive_result = self._classify_backup_archive(lname)
        if archive_result is not None:
            return archive_result

        return None

    # -- per-category helpers -----------------------------------------------------

    def _classify_env(
        self, lname: str
    ) -> Optional[tuple[str, Severity, str, str, dict[str, object]]]:
        """Classify ``.env``-family files; example files are INFO, real ones HIGH."""
        if lname != ".env" and not lname.startswith(".env."):
            return None

        example_suffixes = (".example", ".sample", ".template", ".dist")
        if any(lname.endswith(sfx) for sfx in example_suffixes):
            return (
                "env_example",
                Severity.INFO,
                "tentative",
                "An environment example/template file is present. This is expected, "
                "but verify it contains only placeholder values and no real secrets.",
                {"is_example": True},
            )

        return (
            "env_file",
            Severity.HIGH,
            "firm",
            "An environment file (.env) typically holds API keys, database "
            "passwords, and other secrets and must never be committed.",
            {},
        )

    def _classify_gcp(
        self, repo: "RepoContext", path: Path, lname: str, suffix: str
    ) -> Optional[tuple[str, Severity, str, str, dict[str, object]]]:
        """Detect a GCP service-account key by filename hint or content markers."""
        if suffix != ".json":
            return None

        name_hint = lname.startswith("service-account") or "service-account" in lname
        text = repo.read_text(path)
        content_match = text is not None and all(m in text for m in _GCP_MARKERS)

        if content_match:
            return (
                "gcp_service_account_key",
                Severity.CRITICAL,
                "firm",
                "A GCP service-account key (contains both 'private_key' and "
                "'client_email') is committed. It grants programmatic access to "
                "Google Cloud resources and must be rotated immediately.",
                {"content_confirmed": True, "private_key_present": True},
            )
        if name_hint:
            # Filename strongly suggests a service-account key but content did not
            # confirm (binary/oversize/renamed); report tentatively.
            return (
                "gcp_service_account_key",
                Severity.HIGH,
                "tentative",
                "A file named like a GCP service-account key is committed. If it "
                "contains a private key it must be removed and rotated.",
                {"content_confirmed": False},
            )
        return None

    def _classify_token_file(
        self, repo: "RepoContext", path: Path, lname: str
    ) -> Optional[tuple[str, Severity, str, str, dict[str, object]]]:
        """Flag ``.npmrc``/``.pypirc`` only when their content holds an auth token."""
        markers = _TOKEN_FILE_MARKERS.get(lname)
        if markers is None:
            return None

        text = repo.read_text(path)
        if text is None:
            return None
        low = text.lower()
        if not any(marker in low for marker in markers):
            return None

        return (
            "package_registry_token",
            Severity.HIGH,
            "firm",
            f"A {lname} file contains what appears to be a package-registry auth "
            "token or password. Committed registry credentials allow publishing "
            "malicious packages or accessing private packages.",
            {"token_present": True},
        )

    def _classify_backup_archive(
        self, lname: str
    ) -> Optional[tuple[str, Severity, str, str, dict[str, object]]]:
        """Flag archives whose names indicate they are backups/dumps."""
        archive_exts = (".zip", ".tar.gz", ".tgz", ".tar", ".gz", ".rar", ".7z", ".sql.gz")
        is_archive = any(lname.endswith(ext) for ext in archive_exts)
        if not is_archive:
            return None

        looks_like_backup = (
            lname.startswith("backup")
            or "backup" in lname
            or "dump" in lname
        )
        if not looks_like_backup:
            return None

        return (
            "backup_archive",
            Severity.MEDIUM,
            "firm",
            "An archive named like a backup/dump is committed. Such archives "
            "frequently contain databases, source snapshots, or secrets and "
            "should not live in the repository.",
            {},
        )
