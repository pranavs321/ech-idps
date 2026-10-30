# Prompt to paste into Antigravity (open the unzipped project folder first)

You are working in an existing, tested Python research project (`ja4lab/`) that studies whether
JA4+ pre-hash TLS components let a model detect and attribute clients whose exact fingerprint was
never seen. Read `README.md` and `RESEARCH_PLAN.md` fully before doing anything.

Rules:
1. Do NOT rewrite or "simplify" `ja4lab/tlsparse.py` or `ja4lab/extract.py`. They are validated
   against FoxIO's reference implementation. If you change them, rerun
   `python tests/validate_against_foxio.py` and `python tests/test_reassembly.py`; both must still pass.
2. Never use fingerprint hashes (`ja4`, `ja4s`, `ja3` ...) or `sni` as model features. That is lookup, not learning.
3. Vocabularies and thresholds must be fitted on training folds only. Never tune on test folds.
4. Never report numbers from `results_SMOKE/` or from `make_smoke_data.py`. They are synthetic.
5. Explain every change you make in plain language in `CHANGELOG.md`, so our team can defend it in the viva.

Tasks, in order:
A. Create a venv, `pip install -r requirements.txt`, and run `bash scripts/smoke_test.sh`. Fix environment issues only.
B. Scan `data/raw/` and report pcaps per label, source and family, plus families with fewer than 2 PCAPs.
C. For each malicious PCAP without an entry in `data/meta/infected_hosts.csv`, list the top 3 client IPs
   by TLS connections so we can fill in the victim IP manually. Do not guess it silently.
D. Run `bash scripts/run_all.sh`. Then write `results/REPORT.md` containing:
   - a dataset table (from `data/processed/instances.report.csv`);
   - RQ1–RQ5 results tables with mean ± std;
   - the three figures;
   - a paragraph flagging any sign of shortcut learning, such as a large drop from
     leave_fingerprint_out to leave_dataset_out, or JA4T/TTL dominating importance.
E. Error analysis: export the 20 most confident false negatives and false positives under
   leave_fingerprint_out to `results/errors.csv`, with pcap, src_ip, sni, ja4, ja4_ro, ja4s and ja4t,
   so we can inspect them in Wireshark.
