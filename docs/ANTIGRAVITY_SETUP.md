# Setting Up This Project in Google Antigravity

Antigravity is Google's agentic development platform, released November 2025.
(cite index="38-1">The platform introduces two distinct ways to interact with your code: The Editor View: When you need to be hands-on, you get a state-of-the-art, AI-powered IDE equipped with tab completions and inline commands for the synchronous workflow you already know. The Manager Surface: This is where the shift happens. It's a dedicated interface where you can spawn, orchestrate, and observe multiple agents working asynchronously across different workspaces</cite>. (cite index="38-1">This cross-platform solution is compatible with MacOS, Windows, and Linux</cite>.

Since the 2.0 release, (cite index="40-1">Antigravity 2.0 is a standalone desktop command center for launching, monitoring, and orchestrating multiple agents in parallel across projects and workspaces, while the separate Antigravity IDE keeps the Editor view for synchronous coding</cite>.

---

## Step 1 — Install

Download from Google's Antigravity page for macOS, Windows or Linux.
(cite index="41-1">it is free during the preview phase, with generous free Gemini 3 Pro usage</cite>.

## Step 2 — Open the project folder

Unzip `ech-idps` somewhere sensible, then open that folder in Antigravity.
(cite index="41-1">Open the folder in the editor. Go to the Agent Manager panel and select the folder we created. Click New Task.</cite>

## Step 3 — Install the Python extensions

(cite index="37-1">Antigravity inherits VS Code's extension ecosystem, so install the Python extension, Jupyter extension, and any framework-specific extensions you use</cite>.

Install at minimum: **Python**, **Jupyter**.

> Note one friction point: (cite index="42-1">Pylance: The high-performance Python language server is also restricted</cite> in Antigravity, so IntelliSense is weaker than stock VS Code. For this project that's fine — it's plain Python with no exotic typing.

## Step 4 — Set the autonomy level

(cite index="37-1">Antigravity also offers four preconfigured autonomy profiles: Secure mode: Restricted external access, all commands reviewed. Best for compliance-sensitive environments. Review-driven development: Balanced autonomy with checkpoints. Recommended for most users starting out. Agent-driven development: Minimal human intervention. Best for prototyping and experimental work. Custom configuration: Full control over each policy independently.</cite>

**Pick "Review-driven development."** You are close to a submission deadline —
you want checkpoints, not an agent silently rewriting your evaluation harness.

## Step 5 — AGENTS.md is already written for you

(cite index="37-1">Create an AGENTS.md file in your project root to define standing instructions for all agents working in that workspace. This file functions similarly to Cursor's .cursorrules or Claude Code's CLAUDE.md. Define your coding standards, naming conventions, testing requirements, and any project-specific constraints here. Every agent spawned in the workspace reads this file before starting work.</cite>

**`AGENTS.md` is already in your project root.** It contains the architectural
rules that must not be broken (the 14-D contract, the privacy boundary, the
"attacker cost must be measured" rule) and the research-integrity rules. Don't
delete it — it is what stops an agent from accidentally destroying your central
result while "improving" things.

## Step 6 — Set up the environment

Open a terminal in Antigravity and run:

```bash
pip install -r requirements.txt
python3 run_all.py
```

If it finishes and writes `results/evaluation.png`, you're fully set up.

---

## Good first tasks to hand an agent

Type these into **New Task** in the Agent Manager:

**Build the dashboard** (the one piece not yet written):
```
Build a FastAPI dashboard in src/idps/dashboard/ that serves the SOAR
incident log from results/incidents.jsonl. Show each incident's verdict,
dissonance score, TreeSHAP top features, and the mitigation decision with
its scope and TTL. Single HTML page, no build step. Follow AGENTS.md.
```

**Write the paper skeleton:**
```
Create paper/main.tex with a LaTeX skeleton following the section structure
in docs/ and using ONLY the narrowed novelty claims from
docs/RESEARCH_AND_NOVELTY.md. Include the reference list from section 7 of
that file. Do not broaden any claim.
```

**Add tests:**
```
Add pytest tests under tests/ covering: the JA4 parser round-tripping all
four browser profiles, the 14-D extractor producing correct shapes, and the
Module 5 policy never returning SOURCE_IP scope when infra_mass exceeds the
veto threshold. Follow AGENTS.md.
```

---

## A warning about agentic IDEs and your deadline

Antigravity's agents can (cite index="42-1">modify files you aren't currently looking at</cite>. That is powerful and also risky
three days before a submission.

**Before you let any agent loose on this repo:**

```bash
cd ech-idps
git init
git add -A
git commit -m "Working baseline: full pipeline runs, all results verified"
```

Now if an agent breaks something you can `git checkout .` and you're back to a
working project. This takes fifteen seconds and it is the single most valuable
thing you can do right now.

---

## If you'd rather not use Antigravity at all

You don't need it. The project runs with plain Python:

```bash
pip install -r requirements.txt
python3 run_all.py
```

Antigravity is a convenience for *extending* the project. Everything required
for your submission already works without it.
