# Running ja4next with Google Antigravity (checked 14 Nov 2026: App v2.32.0, IDE v2.7.0, CLI v1.5.8)

Antigravity's docs change fast; read https://antigravity.google/docs/rules.md (add `.md` to any docs URL for raw
text) or type `/antigravity-guide` inside Antigravity if something below no longer matches.

## What is already in this repo
| Path | What Antigravity does with it |
|---|---|
| `AGENTS.md` | Always-on project brief (no frontmatter needed) |
| `.agents/rules/pipeline-guardrails.md` | Always-on rule (`trigger: always_on`): safety, holdout, long-job handling |
| `.agents/skills/<name>/SKILL.md` | One skill per stage, run as `/<name>`: setup-env, fetch-data, extract-label, evaluate, add-source, paper-numbers, confirmatory-run |
| `.agents/hooks.json` + `.agents/hooks/guard.sh` | PreToolUse hook that denies rm -r, sudo, git push/clean/reset --hard, `--allow-holdout`, 2022-2026 MTA URLs and "malware" zips |
| `scripts/run_stage.sh` | The only way stages run: PID lock, `state/<stage>.done`, `logs/<stage>.exitcode`, stdin from /dev/null |

Notes on the format (official docs): the folder is `.agents/` (the older `.agent/` is still read); a rules file
needs YAML frontmatter with a valid `trigger` (`always_on`, `model_decision`, `glob`, `manual`) or it is silently
ignored; rules are capped at 24,000 bytes each and ~20,000 tokens in total; workflows (`.agents/workflows/`) are
deprecated and IDE-only, and a skill with the same name wins over a workflow.

## One-time setup (do this yourself)
1. `brew install --cask wireshark` then `sudo ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark`; check `tshark --version` (4.2 or newer).
2. In the repo: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`.
3. `git init && git add -A && git commit -m "start"` (data/ is gitignored). Make sure Time Machine has a recent backup.
4. Antigravity App -> open the folder as a project in **Local** mode (not Worktree).
5. Settings -> Projects -> this project -> permission preset **Default** (sandboxed; commands outside the sandbox ask). **Auto** is fine once things work. **Never Turbo** (full disk, nothing asks).
6. Fine-grained rules (Settings -> General -> Global Permissions, or the project's permissions):
   - allow: `read_url(www.malware-traffic-analysis.net)`, `read_url(github.com)`, `read_url(objects.githubusercontent.com)`, `read_url(sslbl.abuse.ch)`, `read_url(feodotracker.abuse.ch)`, `read_url(pypi.org)`, `read_url(files.pythonhosted.org)`; add `read_url(mcfp.felk.cvut.cz)` and `read_url(zenodo.org)` when you run `/add-source`
   - ask: `command(rm)`
   - deny: `command(rm -rf)`, `command(sudo)`, `command(git push)`, `command(git reset --hard)`, `command(git clean)`, `write_file(.git/)`
   - do NOT add a `command(scripts/run_stage.sh)` allow rule: allow rules also let a command run outside the sandbox without asking.
7. Settings -> General -> Plan Review Policy: **Always Ask** until the skills behave. AI Credit Overages: **Never**.
8. Settings -> Application -> Enable Remote Control (approve prompts from your phone). Keep the Mac on power.
9. Model: free plan -> Gemini 4 Hydrogen (High); Pro -> Orchestrator (Argon); Ultra -> Orchestrator (Carbon). Claude Sonnet/Opus 4.6 and GPT-OSS-120b are removed on 18 Nov 2026.

## Running the stages
Run each skill in a fresh conversation, in this order:

```
/setup-env
/fetch-data
/extract-label
/evaluate
/paper-numbers
```

Unattended (after `/setup-env` passes):

```
/goal Run /fetch-data, then /extract-label, then /evaluate, following the always-on guardrails. Done when state/evaluate.done exists and logs/PROGRESS.md summarises every stage. Check long stages every 10 minutes with /schedule; never sleep-loop; stop and write logs/BLOCKERS.md if a stage fails twice.
```

Adding a dataset:

```
/add-source Add Stratosphere CTU-Mixed-Capture-3, 4 and 5 as source "ctu_mixed". Labels come from each README's infection time and C2 IPs (the binetflow label columns are empty). Skip every *.exe.zip, *.json and *.html file.
```

Paper tables after a run:

```
/paper-numbers Write reports/new_sections.md and .tex for section 5.10 "Host-relative features" from results/hostname_only and results/gold_only.
```

## Copy-paste prompts for the open research tasks
1. **DG baselines (CPU):** "Add MLP-based DANN (gradient reversal on the source label), GroupDRO (groups = source x label) and JTT to src/ja4next/dg.py with scikit-learn/PyTorch CPU; evaluate them with the same leave-one-source-out folds as evaluate.py on the HRb+TLS+BEH and TLS+BEH features; report mean and worst-source balanced accuracy; add tests; do not change existing results files."
2. **Training exercises as a source:** "/add-source Add the 38 MTA training exercises 2019-2021 from training-exercises.html as source mta_exercises. Use the answers PDFs (page2.html, *-answers.pdf.zip, password infected_YYYYMMDD) as analyst labels: infected host IP and IOC domains/IPs. Treat every other internal host in the capture as a clean host."
3. **TLS-version stratification:** "Extend evaluate.py to report every metric separately for connections whose JA4 starts with t13 and t12, and add a 'TLS version only' baseline (a depth-1 tree on the version)."
4. **Variance decomposition:** "For each BEH feature, compute the intra-class correlation by capture and by source (one-way ANOVA), before and after host-relative standardisation; write results/variance_decomposition.csv and a short table."

## Pitfalls seen in practice (and what the repo does about them)
| Pitfall | Mitigation in this repo |
|---|---|
| Terminal shows "Running" forever; background command never reports done | `logs/<stage>.exitcode` is the truth; skills poll it with /schedule every 10 min |
| Agent re-launches a job it thinks is hung | PID lock + `state/<stage>.done` |
| Agent deletes or "cleans up" data | guard hook + deny rules + `chmod -R a-w data/raw` after download + git |
| Sandbox has no network by default | the `read_url(...)` allow rules above |
| Headless CLI (`agy -p`) skips approvals and still exits 0 | use the App, not headless mode, for these stages |
| Context bloat from logs | rules forbid printing whole files; one conversation per stage; state in logs/PROGRESS.md |
| macOS has no GNU `timeout` | timeouts live inside the Python code |
