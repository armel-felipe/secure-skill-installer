#!/usr/bin/env node
/**
 * secure-skill-installer — installer CLI
 *
 * Copies the bundled skill into the right directory for your agent:
 *   claude   -> ~/.claude/skills/secure-skill-installer/
 *   codex    -> ~/.codex/skills/secure-skill-installer/  (+ pointer in ~/.codex/AGENTS.md)
 *   opencode -> ~/.config/opencode/skills/secure-skill-installer/  (or ./.opencode/skills/ with --project)
 *   all      -> every target found above
 *
 * Usage:
 *   npx secure-skill-installer [target] [--project] [--uninstall] [--list]
 *
 * Targets: claude | codex | opencode | all   (default: all)
 */

import { existsSync, mkdirSync, cpSync, rmSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKILL_SRC = resolve(__dirname, "..");
const SKILL_NAME = "secure-skill-installer";

const args = process.argv.slice(2);
const flags = args.filter((a) => a.startsWith("--"));
const positional = args.filter((a) => !a.startsWith("--"));

const wantProject = flags.includes("--project");
const wantUninstall = flags.includes("--uninstall");
const wantList = flags.includes("--list");

const targets = {
  claude: () => join(homedir(), ".claude", "skills", SKILL_NAME),
  codex: () => join(homedir(), ".codex", "skills", SKILL_NAME),
  opencode: () =>
    wantProject
      ? join(process.cwd(), ".opencode", "skills", SKILL_NAME)
      : join(homedir(), ".config", "opencode", "skills", SKILL_NAME),
};

const AGENTS_MD = join(homedir(), ".codex", "AGENTS.md");
const AGENTS_MARKER = `<!-- secure-skill-installer: ${SKILL_NAME} -->`;

function log(msg) {
  process.stdout.write(msg + "\n");
}

function listTargets() {
  log("Install targets:");
  for (const [name, pathFn] of Object.entries(targets)) {
    const dest = pathFn();
    const installed = existsSync(join(dest, "SKILL.md"));
    log(`  ${name.padEnd(9)} ${dest}${installed ? "  [installed]" : ""}`);
  }
  log("\nUsage: npx secure-skill-installer [claude|codex|opencode|all] [--project] [--uninstall]");
}

function install(target) {
  const dest = targets[target]();
  mkdirSync(dirname(dest), { recursive: true });

  // Copy only the skill payload (SKILL.md + references/), never node_modules or bin.
  cpSync(join(SKILL_SRC, "SKILL.md"), join(dest, "SKILL.md"));
  const refs = join(SKILL_SRC, "references");
  if (existsSync(refs)) cpSync(refs, join(dest, "references"), { recursive: true });

  log(`  ✓ ${target}: ${dest}`);

  // Codex has no native skills loader — add a pointer in ~/.codex/AGENTS.md.
  if (target === "codex") {
    mkdirSync(dirname(AGENTS_MD), { recursive: true });
    if (!existsSync(AGENTS_MD)) writeFileSync(AGENTS_MD, "# AGENTS.md\n\n");
    const content = readFileSync(AGENTS_MD, "utf8");
    if (!content.includes(AGENTS_MARKER)) {
      appendFileSync(
        AGENTS_MD,
        `\n${AGENTS_MARKER}\n## Skill: secure-skill-installer\nSecurity-first workflow for installing external Agent Skills. Read and follow: ~/.codex/skills/${SKILL_NAME}/SKILL.md\n`
      );
      log(`    ↳ pointer added to ${AGENTS_MD}`);
    }
  }
}

function uninstall(target) {
  const dest = targets[target]();
  if (existsSync(dest)) {
    rmSync(dest, { recursive: true, force: true });
    log(`  ✓ removed ${target}: ${dest}`);
  } else {
    log(`  - ${target}: nothing to remove at ${dest}`);
  }
  if (target === "codex" && existsSync(AGENTS_MD)) {
    const content = readFileSync(AGENTS_MD, "utf8");
    if (content.includes(AGENTS_MARKER)) {
      const cleaned = content
        .split("\n")
        .filter((line, i, arr) => {
          // drop marker line and the two lines that follow it
          if (line.trim() === AGENTS_MARKER) return false;
          const prev = arr[i - 1] ?? "";
          const prev2 = arr[i - 2] ?? "";
          return !(prev.trim() === AGENTS_MARKER || prev2.trim() === AGENTS_MARKER);
        })
        .join("\n");
      writeFileSync(AGENTS_MD, cleaned);
      log(`    ↳ pointer removed from ${AGENTS_MD}`);
    }
  }
}

// ---- main ----
if (wantList || positional.length === 0) {
  listTargets();
  process.exit(0);
}

const chosen = positional[0].toLowerCase();
if (!targets[chosen]) {
  log(`Unknown target "${positional[0]}". Use: claude | codex | opencode | all`);
  process.exit(1);
}

const runTargets = chosen === "all" ? Object.keys(targets) : [chosen];
const verb = wantUninstall ? "Uninstalling" : "Installing";
log(`${verb} ${SKILL_NAME} → ${runTargets.join(", ")}\n`);

for (const t of runTargets) {
  wantUninstall ? uninstall(t) : install(t);
}

log(`\nDone. Restart your agent session so the skill is picked up.`);
