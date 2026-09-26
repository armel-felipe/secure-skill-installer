# Secure Skill Installer

Global OpenCode Agent Skill for installing third-party skills with explicit consent and a static post-install audit.

## Usage

Ask OpenCode to install or inspect a skill using one of these inputs:

```text
Instale com segurança https://skills.sh/owner/repository/skill-name
Instale com segurança https://github.com/owner/repository, skill skill-name
Revise e execute: npx skills add owner/repository --skill skill-name
```

The workflow asks for scope and confirmation before installation. Local installation also requires an explicitly confirmed project root.

## Auditor

The bundled Python program performs static inspection only:

```text
python3 scripts/static_audit.py /absolute/path/to/installed-skill
```

Optional machine-readable and Markdown output:

```text
python3 scripts/static_audit.py /path/to/skill --json-output report.json --markdown-output report.md
```

It never invokes files from the inspected skill and does not make network requests. Do not run OpenCode in automatic mode for installation or audit. Restart OpenCode after installing or changing this skill so the global skill registry is reloaded.

## How it works

1. **Consent first** — the skill never installs anything silently. It presents the source URL, the requested scope (global vs. project), and asks for explicit confirmation before any file is written.
2. **Install** — after confirmation, the skill is fetched (e.g. via `npx skills add`) into the confirmed location.
3. **Static audit** — the bundled `scripts/static_audit.py` inspects the installed skill directory without executing anything from it: it scans for dangerous patterns (network calls, shell execution, credential access, obfuscation) and produces a human-readable report, optionally with JSON/Markdown output.
4. **Report & restart** — the audit result is shown to the user, who decides whether to keep or remove the skill. OpenCode should be restarted afterwards so the global skill registry reloads.

The auditor is strictly static: it never runs code from the inspected skill and never makes network requests.

## Credits

This project was inspired by and created based on the teachings of [sandeco](https://github.com/sandeco) — thanks for sharing the knowledge that made this skill possible. 🙏
