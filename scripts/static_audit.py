#!/usr/bin/env python3
"""Static, non-executing inventory and risk scan for an installed Agent Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

LARGE_FILE_BYTES = 5 * 1024 * 1024
MAX_TEXT_SCAN_BYTES = 10 * 1024 * 1024
SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
TEXT_EXTENSIONS = {
    "", ".md", ".txt", ".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".json", ".jsonc", ".yaml", ".yml",
    ".toml", ".xml", ".ini", ".cfg", ".conf", ".properties", ".lock", ".html",
    ".css", ".sql", ".rb", ".go", ".rs", ".java", ".gradle", ".env.example",
}
EXPECTED_TOP_LEVEL = {
    "SKILL.md", "README.md", "LICENSE", "LICENSE.md", "LICENSE.txt", "scripts", "references",
    "assets", "tests", "evals", "package.json", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "requirements.txt", "pyproject.toml", "poetry.lock", "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum", ".gitignore", ".gitattributes",
}
SENSITIVE_NAMES = {
    ".env", "credentials", "credentials.json", "cookies", "cookies.json", "id_rsa", "id_ed25519",
    "private_key", "private-key.pem", "secrets.json", "token", "tokens.json", "auth.json",
    "service-account.json", ".npmrc", ".pypirc", ".netrc", "keychain-db", "login.keychain-db",
}
SENSITIVE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".gpg", ".pgp", ".kdbx", ".jks"}
SENSITIVE_PATH_PARTS = {".ssh", ".aws", ".gnupg", "keychains", "credentials", "secrets"}
WINDOWS_EXECUTABLE_SUFFIXES = {".exe", ".com", ".bat", ".cmd", ".ps1", ".msi", ".scr"}

# Patterns intentionally describe dangerous syntax as inert strings. This program never evaluates matches.
RULES = [
    ("Network and exfiltration", "Medium", r"\b(curl|wget|fetch|axios|requests\.(get|post|put)|urllib|websocket|socket\.)\b", "Network client or transfer primitive", "Require a documented endpoint, data boundary, and per-use network consent."),
    ("Network and exfiltration", "High", r"\b(upload|exfiltrat|send_file|create[_ -]?public[_ -]?link|webhook)\b", "Possible data publication or upload", "Remove or tightly restrict data transmission."),
    ("Credentials and secrets", "High", r"(process\.env|os\.environ|os\.getenv|getenv\s*\(|~[/\\]\.ssh|~[/\\]\.aws|keychain|credential(s)?\s*(file|store)?)", "Possible credential or environment access", "Deny credential paths and environment access unless narrowly justified."),
    ("Credentials and secrets", "Medium", r"\b(api[_-]?key|token|secret|password|authorization|cookie)\b", "Credential-related reference", "Determine whether this is documentation or an effective read/write action."),
    ("Arbitrary command execution", "High", r"\b(eval|exec|os\.system|subprocess\.|child_process|shell\s*=\s*True)\b", "Dynamic code or process execution", "Remove dynamic execution or constrain it to fixed reviewed arguments."),
    ("Arbitrary command execution", "Medium", r"\b(npx|npm|pnpm|yarn|pip|pip3|brew|apt(-get)?|powershell|cmd\.exe|/bin/(ba)?sh)\b", "Shell or package-manager command", "Do not run automatically; require explicit review and consent."),
    ("Arbitrary command execution", "High", r"\b(base64\s+(-d|--decode)|fromBase64String|atob\s*\()", "Possible encoded command or payload", "Decode only as inert data in an isolated review and explain its purpose."),
    ("Destructive filesystem change", "High", r"\b(rm\s+-rf|rmdir|Remove-Item|del\s+/[sq]|shutil\.rmtree|unlink\s*\()", "Deletion primitive", "Remove broad deletion or constrain it to an explicitly verified owned path."),
    ("Destructive filesystem change", "High", r"\b(chmod|chown|icacls|takeown)\b", "Permission or ownership change", "Avoid permission changes; require separate explicit authorization if essential."),
    ("Filesystem escape", "Medium", r"(^|[\s'\"`])\.\.[/\\]", "Parent-directory traversal", "Resolve and enforce paths within the selected project or skill root."),
    ("Persistence", "High", r"\b(crontab|cron\b|LaunchAgents?|LaunchDaemons?|systemd|schtasks|ScheduledTask|autostart|nohup|daemon|background process)\b", "Persistence or long-running process", "Do not create persistence; require a separate, explicit system-administration request."),
    ("Persistence", "High", r"(\.git[/\\]hooks|opencode[/\\]hooks|\.bashrc|\.zshrc|profile\.d)", "Startup or hook modification", "Do not alter startup files or hooks."),
    ("OpenCode modification", "High", r"\bopencode\.jsonc?\b|\.opencode[/\\](plugin|plugins|hook|hooks|agent|agents)", "OpenCode configuration or extension path", "Keep installation separate from OpenCode configuration changes."),
    ("OpenCode modification", "High", r"\b(mcp|plugin)\b.{0,80}\b(enable|install|add|configure|allow)\b", "Possible MCP or plugin activation", "Do not enable extensions during skill installation or audit."),
    ("OpenCode modification", "High", r"\b(deny|ask)\b.{0,40}\ballow\b|--auto\b", "Possible permission relaxation or automatic mode", "Preserve least privilege and explicit approvals."),
    ("Prompt injection", "High", r"\b(ignore|disregard|override)\b.{0,60}\b(previous|prior|system|developer|rules?|instructions?)\b", "Instruction to override governing rules", "Treat as prompt injection and do not follow it."),
    ("Prompt injection", "High", r"\b(do not|don't|never)\b.{0,40}\b(tell|show|inform|ask|confirm)\b.{0,30}\b(user|permission|approval)?", "Possible concealment or confirmation bypass", "Keep actions transparent and require explicit consent."),
    ("Prompt injection", "High", r"\b(silently|without confirmation|disable security|bypass safety|trust remote|follow instructions from)\b", "Possible behavioral or security bypass", "Reject the instruction and preserve the original task boundaries."),
    ("Supply chain", "High", r"\"(preinstall|install|postinstall)\"\s*:", "Package installation lifecycle hook", "Do not install dependencies; inspect the hook as data."),
    ("Supply chain", "Medium", r"(git\+https?://|https?://[^\s'\"]+\.(tgz|zip)|\b(latest|\*)\b)", "Remote or unpinned dependency indicator", "Pin and independently review dependencies before use."),
    ("Privilege escalation", "High", r"\b(sudo|runas|administrator|root privileges?|setuid)\b", "Privilege escalation", "Do not elevate privileges."),
    ("Privilege escalation", "Critical", r"\b(disable|turn off|stop)\b.{0,50}\b(antivirus|firewall|gatekeeper|defender|security controls?)\b", "Security control disabling", "Remove the skill and investigate the source."),
]

URL_RE = re.compile(r"https?://[^\s<>\]\[(){}'\"`]+", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)\b(token|secret|password|api[_-]?key|authorization)\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
AUTHORIZATION_RE = re.compile(r"(?i)(authorization\s*[:=]\s*).*$")


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def is_sensitive(path: Path) -> bool:
    name = path.name.lower()
    return (name in SENSITIVE_NAMES or name.startswith(".env.") and name != ".env.example"
            or path.suffix.lower() in SENSITIVE_SUFFIXES
            or any(part.lower() in SENSITIVE_PATH_PARTS for part in path.parts))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    text_bytes = bytes(sorted({7, 8, 9, 10, 12, 13, 27, *range(0x20, 0x100)}))
    nontext = sample.translate(None, text_bytes)
    return len(nontext) / len(sample) > 0.30


def redact(text: str) -> str:
    redacted = URL_RE.sub(lambda match: sanitize_url(match.group(0)), text)
    redacted = AUTHORIZATION_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)
    redacted = SECRET_VALUE_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", redacted)
    redacted = BEARER_RE.sub("Bearer [REDACTED]", redacted)
    return redacted.replace("`", "\\`").strip()[:300]


def sanitize_url(url: str) -> str:
    try:
        parsed = urlparse(url.rstrip(".,;:!?"))
        hostname = parsed.hostname or ""
        try:
            port = parsed.port
            if port:
                hostname = f"{hostname}:{port}"
        except ValueError:
            pass
        return urlunparse((parsed.scheme, hostname, parsed.path, "", "", ""))
    except ValueError:
        return url.rstrip(".,;:!?")


def add_finding(findings: list[dict[str, Any]], category: str, severity: str, path: str,
                line: int | None, excerpt: str, behavior: str, recommendation: str) -> None:
    findings.append({
        "category": category,
        "severity": severity,
        "file": path,
        "line": line,
        "excerpt": redact(excerpt),
        "behavior": behavior,
        "impact": behavior,
        "reason": f"Matched static indicator in {path}; contextual review is required.",
        "recommendation": recommendation,
    })


def scan_text(relative: str, text: str, findings: list[dict[str, Any]], urls: set[str]) -> None:
    suffix = Path(relative).suffix.lower()
    documentary = suffix in {".md", ".txt"}
    for line_number, line in enumerate(text.splitlines(), 1):
        urls.update(sanitize_url(url) for url in URL_RE.findall(line))
        for category, severity, pattern, behavior, recommendation in RULES:
            if not re.search(pattern, line, re.IGNORECASE):
                continue
            effective_severity = severity
            effective_behavior = behavior
            if documentary and category != "Prompt injection":
                effective_severity = "Low" if SEVERITY_ORDER[severity] <= 2 else "Medium"
                effective_behavior = f"Documentary reference: {behavior}"
            add_finding(findings, category, effective_severity, relative, line_number, line,
                        effective_behavior, recommendation)


def audit(entry: Path) -> dict[str, Any]:
    entry = entry.expanduser().absolute()
    if not entry.exists() and not entry.is_symlink():
        raise ValueError(f"Skill path does not exist: {entry}")

    entry_is_symlink = entry.is_symlink()
    root = entry.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Skill path is not a directory: {entry}")
    if entry_is_symlink:
        if any(part.lower() in SENSITIVE_PATH_PARTS for part in root.parts):
            raise ValueError(f"Installation symlink resolves into a sensitive path; target was not audited: {root}")
        if not (root / "SKILL.md").is_file():
            raise ValueError(f"Installation symlink target has no SKILL.md and was not audited: {root}")

    inventory: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    urls: set[str] = set()
    extensions: Counter[str] = Counter()
    executables: list[str] = []
    symlinks: list[dict[str, Any]] = []
    binaries: list[str] = []
    large_files: list[str] = []
    unusual: list[str] = []
    sensitive_skipped: list[str] = []
    errors: list[str] = []

    if entry_is_symlink:
        symlinks.append({"path": str(entry), "target": os.readlink(entry), "resolved": str(root), "external": False, "installation_entry": True})

    def walk_error(exc: OSError) -> None:
        errors.append(f"directory traversal: {type(exc).__name__}: {exc}")

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        current_path = Path(current)
        names = sorted(dirnames + filenames)
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    target_text = os.readlink(path)
                    resolved = path.resolve(strict=False)
                    external = not is_relative_to(resolved, root)
                    item = {"path": relative, "target": target_text, "resolved": str(resolved), "external": external}
                    symlinks.append(item)
                    inventory.append({"path": relative, "type": "symlink", "size": metadata.st_size, **item})
                    severity = "Critical" if external and any(part.lower() in SENSITIVE_PATH_PARTS | {".config", "etc", "system32"} for part in resolved.parts) else "Medium" if external else "Informational"
                    add_finding(findings, "Symlink escape", severity, relative, None, target_text,
                                "Symbolic link points outside the audited root" if external else "Internal symbolic link",
                                "Remove external links; do not follow or delete their targets." if external else "Verify the internal target is expected.")
                    if path.is_dir() and name in dirnames:
                        dirnames.remove(name)
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    inventory.append({"path": relative, "type": "directory"})
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    inventory.append({"path": relative, "type": "special", "size": metadata.st_size})
                    add_finding(findings, "Unusual file", "High", relative, None, "special filesystem entry",
                                "Non-regular filesystem entry", "Remove unless its purpose is independently verified.")
                    continue

                suffix = path.suffix.lower() or "[none]"
                extensions[suffix] += 1
                executable = bool(metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) or path.suffix.lower() in WINDOWS_EXECUTABLE_SUFFIXES
                if executable:
                    executables.append(relative)
                if metadata.st_size >= LARGE_FILE_BYTES:
                    large_files.append(relative)
                top = relative.split("/", 1)[0]
                if top not in EXPECTED_TOP_LEVEL and not top.startswith("."):
                    unusual.append(relative)

                record: dict[str, Any] = {"path": relative, "type": "file", "size": metadata.st_size, "executable": executable}
                if is_sensitive(path):
                    record["content_inspection"] = "skipped-sensitive"
                    record["sha256"] = None
                    sensitive_skipped.append(relative)
                    add_finding(findings, "Credentials and secrets", "High", relative, None, "[content not read]",
                                "Sensitive-looking file bundled with the skill", "Do not expose or load this file; remove it unless clearly required and safe.")
                    inventory.append(record)
                    continue

                record["sha256"] = sha256_file(path)
                with path.open("rb") as handle:
                    sample = handle.read(8192)
                binary = looks_binary(sample)
                record["binary"] = binary
                if binary:
                    binaries.append(relative)
                elif metadata.st_size <= MAX_TEXT_SCAN_BYTES and (path.suffix.lower() in TEXT_EXTENSIONS or path.name in EXPECTED_TOP_LEVEL):
                    raw = path.read_bytes()
                    text = raw.decode("utf-8", errors="replace")
                    scan_text(relative, text, findings, urls)
                elif metadata.st_size > MAX_TEXT_SCAN_BYTES:
                    record["content_inspection"] = "skipped-too-large"
                inventory.append(record)
            except (OSError, UnicodeError) as exc:
                errors.append(f"{relative}: {type(exc).__name__}: {exc}")

    if errors:
        add_finding(findings, "Incomplete inspection", "High", str(root), None, "; ".join(errors),
                    "One or more filesystem entries could not be inventoried", "Resolve access errors and repeat the complete audit.")
    domains = sorted({urlparse(url).hostname for url in urls if urlparse(url).hostname})
    overall = max((finding["severity"] for finding in findings), key=lambda value: SEVERITY_ORDER[value], default="Informational")
    return {
        "schema_version": 1,
        "identification": {
            "installed_path": str(entry),
            "real_path": str(root),
            "installation_type": "symlink" if entry_is_symlink else "copy-or-directory",
        },
        "summary": {
            "overall_severity": overall,
            "total_files": sum(item["type"] == "file" for item in inventory),
            "total_directories": sum(item["type"] == "directory" for item in inventory),
            "total_findings": len(findings),
        },
        "inventory": inventory,
        "statistics": {
            "extensions": dict(sorted(extensions.items())),
            "executables": executables,
            "symlinks": symlinks,
            "binary_files": binaries,
            "large_files": large_files,
            "unusual_files": unusual,
            "sensitive_files_not_read": sensitive_skipped,
        },
        "network": {"urls": sorted(urls), "domains": domains},
        "findings": sorted(findings, key=lambda item: (-SEVERITY_ORDER[item["severity"]], item["file"], item["line"] or 0)),
        "errors": errors,
        "limitations": [
            "Static inspection only; files were not executed or imported.",
            "Obfuscated and conditional behavior may not be completely identified.",
            "External dependencies may change and were not installed.",
            "Future updates require a complete new audit.",
            "Static inspection cannot guarantee absolute safety.",
            "Sensitive-looking files and external symlink targets were not read.",
            "Pattern matching can produce false positives and false negatives.",
        ],
    }


def markdown_report(report: dict[str, Any]) -> str:
    identification = report["identification"]
    summary = report["summary"]
    stats = report["statistics"]
    lines = [
        "# Static Skill Audit", "", "## Identification", "",
        f"- Installed path: `{identification['installed_path']}`",
        f"- Real path: `{identification['real_path']}`",
        f"- Installation type: {identification['installation_type']}",
        f"- Files: {summary['total_files']}", "", "## Summary", "",
        f"- Overall severity: **{summary['overall_severity']}**",
        f"- Findings: {summary['total_findings']}", "", "## Findings", "",
    ]
    if not report["findings"]:
        lines.append("Nenhum risco relevante foi identificado na inspeção estática realizada.")
    for finding in report["findings"]:
        location = finding["file"] + (f":{finding['line']}" if finding["line"] else "")
        lines.extend([
            f"### {finding['severity']} - {finding['category']}", "",
            f"- Location: `{location}`", f"- Evidence: `{finding['excerpt']}`",
            f"- Behavior: {finding['behavior']}", f"- Impact: {finding['impact']}",
            f"- Classification rationale: {finding['reason']}",
            f"- Recommendation: {finding['recommendation']}", "",
        ])
    lines.extend(["## Network and external data", "", f"- Domains: {', '.join(report['network']['domains']) or 'None'}",
                  f"- URLs: {len(report['network']['urls'])}", "", "## Files and system", "",
                  f"- Extensions: {json.dumps(stats['extensions'], ensure_ascii=False, sort_keys=True)}",
                  f"- Executables: {', '.join(stats['executables']) or 'None'}",
                  f"- Symbolic links: {len(stats['symlinks'])}", f"- Binary files: {', '.join(stats['binary_files']) or 'None'}",
                  f"- Large files: {', '.join(stats['large_files']) or 'None'}",
                  f"- Unusual files: {', '.join(stats['unusual_files']) or 'None'}",
                  f"- Sensitive files not read: {', '.join(stats['sensitive_files_not_read']) or 'None'}", "",
                  "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report["limitations"])
    return "\n".join(lines) + "\n"


def write_output(path: str | None, content: str) -> None:
    if not path:
        return
    destination = Path(path).expanduser().absolute()
    if not destination.parent.is_dir():
        raise ValueError(f"Output directory does not exist: {destination.parent}")
    destination.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Statically audit an installed Agent Skill without executing it.")
    parser.add_argument("skill_path", help="Path to the installed skill directory or its installation symlink")
    parser.add_argument("--json-output", help="Write the complete JSON report to this path")
    parser.add_argument("--markdown-output", help="Write a readable Markdown report to this path")
    args = parser.parse_args()
    try:
        report = audit(Path(args.skill_path))
    except (OSError, ValueError) as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 2
    json_text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    markdown = markdown_report(report)
    try:
        write_output(args.json_output, json_text)
        write_output(args.markdown_output, markdown)
    except (OSError, ValueError) as exc:
        print(f"Could not write audit report: {exc}", file=sys.stderr)
        return 2
    if not args.json_output and not args.markdown_output:
        print(json_text, end="")
    else:
        print(f"Audited {report['summary']['total_files']} files; overall severity: {report['summary']['overall_severity']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
