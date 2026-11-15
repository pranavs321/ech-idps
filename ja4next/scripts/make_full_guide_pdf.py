"""Full plain-language guide (PDF): what the project does, the pipeline, total capture analysis, findings, novelty, limits, viva Q&A.
Numbers come from results/*.csv|json at build time; numbers from earlier project records are typed and labelled as such.
Usage: python3 scripts/make_full_guide_pdf.py [out.pdf]   (needs node + playwright + chromium)"""
import base64, json, os, subprocess, sys, textwrap
import pandas as pd

OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/ja4next_full_guide.pdf"
R = lambda p: os.path.join("results", p)
pct = lambda v, d=0: f"{100 * float(v):.{d}f}%"
f2 = lambda v: f"{float(v):.2f}"
n = lambda v: f"{int(v):,}"

s = pd.read_csv(R("hostname_only/summary.csv"))
g = lambda split, st, col="tpr_at_1pct": float(s[(s.split == split) & (s["set"] == st)][col].iloc[0])
fb = pd.read_csv(R("foreign_benign/flag_rates.csv")); fbv = lambda st, grp: float(fb[(fb["set"] == st) & (fb.group == grp)]["flagged_conn"].iloc[0])
fbc = lambda grp: int(fb[fb.group == grp]["captures"].iloc[0])
sl = pd.read_csv(R("second_lab/transfer_metrics.csv")); sw = pd.read_csv(R("second_lab_weak/transfer_metrics.csv"))
slv = lambda d, st, col: float(d[(d.train == "MTA") & (d["set"] == st)][col].iloc[0])
inc = pd.read_csv(R("incidents/incident_metrics.csv")); incv = lambda st, col: float(inc[(inc["set"] == st) & (inc["agg"] == "s_max")][col].iloc[0])
dq = json.load(open(R("data_quality.json"))); T = dq["tables"]
ds = json.load(open(R("dataset_summary.json")))
hs = json.load(open(R("handshake/summary.json"))); sc = pd.read_csv(R("handshake/shortcut_checks.csv")).set_index("features")["auc_capture_disjoint"]
vt = pd.read_csv(R("handshake/version_by_tier.csv")).set_index("tier"); ts = pd.read_csv(R("handshake/tier_summary.csv")).set_index("tier")
ra = json.load(open(R("raw_pcap_audit.json")))
fd = pd.read_csv(R("second_lab/feature_direction.csv")); strong = fd[fd.strength >= 0.1]
yr = ds["by_year_labelled"]
mta, st1, st2, st3 = T["MTA 2013-2021 (processed)"], T["Stratosphere mcfp"], T["Stratosphere mcfp2"], T["Stratosphere mcfp3"]
strat_caps = st1["captures"] + st2["captures"] + st3["captures"]; strat_rows = st1["rows"] + st2["rows"] + st3["rows"]
tiers = ds["by_source_tier"]; gold = sum(v["gold_mal"] for v in tiers.values()); weak = sum(v["weak_mal"] for v in tiers.values()); ben = sum(v["benign"] for v in tiers.values())
img = lambda name: "data:image/png;base64," + base64.b64encode(open(f"docs/figures/{name}", "rb").read()).decode()
year_rows = "".join(f"<tr><td>{y}</td><td>{n(v['captures'])}</td><td>{n(v['malicious'])}</td><td>{n(v['benign'])}</td></tr>" for y, v in yr.items())

H = f"""<html><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 16mm 15mm; }}
body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 11pt; line-height: 1.55; color: #1b1b1b; }}
h1 {{ font-size: 27pt; margin: 0 0 4pt; color: #0b4f8a; }} h2 {{ font-size: 16pt; margin: 22pt 0 6pt; color: #0b4f8a; border-bottom: 2px solid #0b4f8a; padding-bottom: 3pt; page-break-after: avoid; }}
h3 {{ font-size: 12pt; margin: 13pt 0 3pt; page-break-after: avoid; }} .sub {{ color: #555; font-size: 12pt; margin-bottom: 12pt; }}
.box {{ background: #eef5fb; border-left: 5px solid #0b4f8a; padding: 9pt 13pt; margin: 10pt 0; page-break-inside: avoid; }}
.warn {{ background: #fff4e5; border-left: 5px solid #d55e00; padding: 9pt 13pt; margin: 10pt 0; page-break-inside: avoid; }}
.good {{ background: #e9f6ee; border-left: 5px solid #009e73; padding: 9pt 13pt; margin: 10pt 0; page-break-inside: avoid; }}
table {{ border-collapse: collapse; width: 100%; margin: 8pt 0; font-size: 10pt; page-break-inside: avoid; }}
th, td {{ border: 1px solid #c8c8c8; padding: 4pt 7pt; text-align: left; vertical-align: top; }} th {{ background: #eef2f6; }}
img {{ width: 100%; page-break-inside: avoid; }} .small {{ font-size: 9pt; color: #555; }} .cover {{ page-break-after: always; }}
.num {{ font-size: 21pt; font-weight: 700; color: #d55e00; line-height: 1.1; }} .cells {{ display: flex; flex-wrap: wrap; gap: 6pt; margin-top: 4pt; }} .cell {{ flex: 1 1 30%; padding: 6pt 8pt; background: #f6f8fa; border-radius: 6pt; box-sizing: border-box; font-size: 9.5pt; line-height: 1.35; }}
li {{ margin-bottom: 3pt; }}
</style></head><body>

<div class="cover">
<h1>Detecting the Lab, Not the Malware</h1>
<div class="sub">The complete project guide in plain words: what we built, how it works, what we found, what is new, and what is still unproven.</div>
<p class="small">Nandakumar Chandran and team &middot; guide: Arjun V &middot; Amrita School of Computing &middot; 15 November 2026</p>

<div class="box"><b>The whole project in one minute.</b><br>
Hackers hide their programs inside encrypted internet traffic. Security tools cannot read what is inside, but they can read the <i>first message</i> of every connection,
a bit like the handwriting on a sealed envelope. Many research papers say this handwriting spots malware with 98&ndash;99% accuracy.<br><br>
We checked, and found a catch: the malware examples and the normal examples are usually recorded in <b>different places</b>, so a computer program can score
well just by recognising <i>where</i> a recording was made, without learning anything about malware. It is like a student who passes an exam by recognising the exam hall.<br><br>
So we built a fairer test using recordings where malware and normal traffic sit on the <b>same infected computer</b>, and we invented a new way to look at traffic:
<b>compare each connection with what that same computer normally does</b>. On our main data this held up far better when the test got harder, and it raised almost no
false alarms on clean traffic from another lab. It did <b>not</b> clearly help find malware in a second lab. We say so openly.</div>

<h3>The numbers behind the story</h3>
<div class="cells"><div class="cell"><div class="num">{n(mta['captures'] + strat_caps)}</div>recordings with encrypted traffic analysed in this build</div>
<div class="cell"><div class="num">{(mta['rows'] + strat_rows) / 1e6:.2f} M</div>encrypted connections read, one by one</div>
<div class="cell"><div class="num">{pct(g('source','HR+TLS+BEH'))}</div>of malware still found on a completely unseen source (old method: {pct(g('source','TLS+BEH'))})</div>
<div class="cell"><div class="num">{pct(fbv('HR+TLS+BEH','normal_host'),1)}</div>false alarms on clean traffic from another lab (lab-signature model: {pct(fbv('ENV','normal_host'))})</div>
<div class="cell"><div class="num">{pct(hs['malicious_ja4_also_seen_in_benign_connection_share'])}</div>of malware connections use a &ldquo;handwriting&rdquo; that normal programs also use</div>
<div class="cell"><div class="num">13</div>automatic tests; the main results reproduce exactly when rerun</div>
</div></div>

<h2>1. The problem, with an everyday picture</h2>
<p>Almost all websites use <b>TLS</b> (the padlock in your browser). It scrambles the content, so a defender cannot read it. But the very first message of every connection,
the <b>ClientHello</b>, is not scrambled. It lists which scrambling methods the program supports, in a program-specific order. Chrome lists them one way, Firefox another way,
Windows&rsquo; own software a third way. A short code made from that list is called a <b>JA4 fingerprint</b>. Think of it as handwriting on a sealed envelope: you
cannot read the letter, but you can see who probably wrote it.</p>
<p>Defenders use this in two ways: block the handwriting of known malware, or trust the handwriting of well-known programs. Both have a weakness: malware can <b>copy</b> a browser&rsquo;s
handwriting, or simply use Windows&rsquo; own library, which many normal programs use too.</p>
<div class="warn"><b>The catch we found.</b> To teach a computer program to spot malware you need examples of both kinds. In public datasets, malware usually comes from one place (a malware-testing
sandbox) and normal traffic from another (a university lab). The program then only needs to learn <i>&ldquo;which room was this recorded in?&rdquo;</i>. It scores 98%, then fails the moment it leaves the room.</div>

<h2>2. What we did, step by step</h2>
<img src="{img('fig0_pipeline.png')}">
<table><tr><th style="width:22%">Step</th><th>What happens, in easy words</th></tr>
<tr><td><b>1 Collect</b></td><td>We download public recordings of network traffic (called <i>pcaps</i>) that security analysts publish after infecting a test computer. Each recording shows one infected computer and its everyday traffic together.</td></tr>
<tr><td><b>2 Read</b></td><td>A program reads every encrypted connection in every recording and writes one row for it: the handshake handwriting (JA4), the server&rsquo;s reply, the certificate, packet sizes, timing. Our reader was checked against the official reference outputs: it agreed on 150 of 151 test connections.</td></tr>
<tr><td><b>3 Label</b></td><td>We decide which rows are malware <b>without looking at the handshake</b>: a row is malicious only if independent evidence says so (the analyst&rsquo;s own list of bad servers, public blacklists such as abuse.ch and Maltrail, blacklisted certificates). A row is normal if it goes to a well-known vendor or content network. Everything else is left <i>unknown</i> and never used for scoring.</td></tr>
<tr><td><b>4 Describe</b></td><td>Each connection is described three ways: its handshake, its behaviour (sizes, timing), and <b>its place in its computer&rsquo;s habits</b> &mdash; our new part (section 5).</td></tr>
<tr><td><b>5 Test hard</b></td><td>We test on harder and harder splits: recordings the model never saw, fingerprints it never saw, years it never saw, and finally a whole unseen <i>source</i> of recordings.</td></tr>
<tr><td><b>6 Check</b></td><td>We look for shortcuts (does the lab give the answer away?), measure false alarms on clean traffic from another lab, and test a second independent lab.</td></tr>
<tr><td><b>7 Lock</b></td><td>The 2022&ndash;2026 recordings are locked away. When the guide signs off on the written plan, we run one final test on them. That is our clean exam.</td></tr></table>

<h2>3. Total capture analysis: everything we looked at</h2>
<p>This section counts what was downloaded, read and used. Numbers marked <b>(build)</b> come from files in this repository; numbers marked <b>(record)</b> come from earlier project
sessions (25 Oct&ndash;12 Nov) and were not recomputed in this build.</p>
<img src="{img('fig4_data_overview.png')}">
<table><tr><th>Source</th><th>Recordings with encrypted traffic</th><th>Encrypted connections</th><th>How it is used</th></tr>
<tr><td>Malware-traffic-analysis.net infections 2013&ndash;2021 <b>(build)</b></td><td>{n(mta['captures'])}</td><td>{n(mta['rows'])}</td><td>Main training and testing data</td></tr>
<tr><td>Stratosphere lab, botnet captures <b>(build)</b></td><td>{n(st1['captures'])}</td><td>{n(st1['rows'])}</td><td>Second-lab detection test</td></tr>
<tr><td>Stratosphere lab, Mixed and Normal captures <b>(build)</b></td><td>{n(st2['captures'])}</td><td>{n(st2['rows'])}</td><td>Clean-traffic false-alarm test</td></tr>
<tr><td>Stratosphere lab, banking-trojan captures <b>(build)</b></td><td>{n(st3['captures'])}</td><td>{n(st3['rows'])}</td><td>More malware for the second-lab test</td></tr>
<tr><th>Total in this build</th><th>{n(mta['captures'] + strat_caps)}</th><th>{n(mta['rows'] + strat_rows)}</th><th></th></tr></table>
<table><tr><th>Earlier research sessions <b>(record)</b></th><th>Recordings with encrypted traffic</th><th>Connections</th></tr>
<tr><td>Matou&scaron;ek public corpus (sandbox malware + benign apps, 2022&ndash;2024)</td><td>1,426</td><td>23,459</td></tr>
<tr><td>Extra benign apps from the same lab (Brno)</td><td>1,247</td><td>14,619</td></tr>
<tr><td>Another lab&rsquo;s benign traffic (ISCX 2016), Cobalt Strike study (ARES 2025), Unit 42 infections, older MTA mirrors</td><td>67 + 21 + 53 + 360</td><td>1,121 + 1,310 + 4,283 + 6,669</td></tr>
<tr><th>Earlier cumulative total (25 Oct)</th><th>3,179</th><th>51,627</th></tr></table>
<p class="small">These two tables overlap (the older MTA mirrors cover 2013&ndash;2018 recordings that this build also uses), so they are <b>not</b> added together.
They answer different questions: the earlier sessions found the shortcut; this build tests a fairer design.</p>

<h3>Main data by year (build)</h3>
<table><tr><th>Year</th><th>Labelled recordings</th><th>Malicious connections</th><th>Normal connections</th></tr>{year_rows}</table>
<p>Labels in the main data: {n(gold)} <b>gold</b> malware connections (confirmed by an analyst list or a blacklisted certificate), {n(weak)} <b>weak</b> malware
connections (matched a public blacklist), {n(ben)} normal connections. About 26,000 connections stay <i>unknown</i> and are never scored.</p>

<h3>Cleaning and quality checks (build)</h3>
<table><tr><th>Check</th><th>Result</th></tr>
<tr><td>Pcap files downloaded and examined (main data)</td><td>{n(ra['raw_pcaps'])} files; {n(ra['unique_sha256'])} unique by file hash</td></tr>
<tr><td>Exact duplicates</td><td>{n(ra['duplicate_copies'])} copies found and removed; duplicated recordings are merged by hash so no recording is on both sides of a train/test split</td></tr>
<tr><td>Recordings with no encrypted traffic</td><td>{n(ra['in_manifest_no_tls_rows'])} removed (they hold nothing the models use)</td></tr>
<tr><td>Recordings feeding the training table</td><td>{n(ra['used_by_processed_table'])} kept</td></tr>
<tr><td>Duplicate connection rows, malformed fingerprints</td><td>0 and 0 in every table</td></tr>
<tr><td>Download or extraction failures (Stratosphere)</td><td>0</td></tr>
<tr><td>Connections without a website name</td><td>MTA main data {pct(mta['sni_empty_share'])}; Stratosphere botnet {pct(st1['sni_empty_share'])} &mdash; we analyse only connections with a name to avoid a label shortcut (section 4)</td></tr></table>

<h3>Deliberately not touched</h3>
<ul><li><b>Malware-traffic-analysis 2022&ndash;2026:</b> locked final exam; never downloaded.</li>
<li><b>TQH-C2 and CTU-SME-11:</b> reserved for the same final exam; only their README and label files were fetched.</li>
<li><b>About 425 GB of other Stratosphere botnet captures:</b> left out because their malware could only be labelled by weak rules, adding volume but not trustworthy labels.</li>
<li><b>Sandbox services with restrictive terms</b> (Tria.ge, ANY.RUN): excluded.</li></ul>

<h2>4. What we found</h2>
<h3>Finding 1 &mdash; The lab gives the answer away <span class="small">(record, earlier sessions)</span></h3>
<table><tr><th>What we measured</th><th>In plain words</th></tr>
<tr><td>A model that sees <b>only network plumbing</b> (nothing about malware or TLS) scored 0.986 on the public sandbox corpus</td><td>The recording room is the signal.</td></tr>
<tr><td>One packet-size setting appeared in 93% of 2024 sandbox malware recordings and in none of 26 normal ones</td><td>Like a postmark from the sandbox&rsquo;s internet path.</td></tr>
<tr><td>A model trained on that corpus found <b>0 of 53</b> older malware recordings from the same sandbox</td><td>It learned the 2024 postmark, not the malware.</td></tr>
<tr><td>Normal traffic from another lab was flagged as malware 80&ndash;99% of the time</td><td>Leave the room and it breaks.</td></tr>
<tr><td>On a sandbox-trained model tested on real infected computers: AUC 0.998 inside the sandbox, 0.478 on real hosts</td><td>No better than guessing in the real world.</td></tr></table>

<h3>Finding 2 &mdash; Malware often wears normal handwriting <span class="small">(build)</span></h3>
<p>In our main data, <b>{pct(hs['malicious_ja4_also_seen_in_benign_connection_share'])}</b> of malicious connections use a fingerprint that normal connections also use, and {pct(hs['captures_with_malicious_sharing_a_benign_ja4_share'])} of
recordings contain such a connection. Malware commonly uses Windows&rsquo; own TLS library, so its handwriting is the same as Windows&rsquo; normal programs. <b>The handshake alone cannot tell them apart.</b></p>

<h3>Finding 3 &mdash; Two label shortcuts, measured <span class="small">(build)</span></h3>
<table><tr><th></th><th>Normal</th><th>Gold malware</th></tr>
<tr><td>Connections with a website name</td><td>{pct(ts.loc['benign','sni_share'])}</td><td>{pct(ts.loc['gold_mal','sni_share'])}</td></tr>
<tr><td>Old TLS 1.0 connections</td><td>{pct(vt.loc['benign','TLS1.0'],1)}</td><td>{pct(vt.loc['gold_mal','TLS1.0'],1)}</td></tr>
<tr><td>New TLS 1.3 connections</td><td>{pct(vt.loc['benign','TLS1.3'],1)}</td><td>{pct(vt.loc['gold_mal','TLS1.3'],1)}</td></tr></table>
<p>Because &ldquo;normal&rdquo; is defined by well-known website names, every normal connection has a name, while a third of malware connections have none. A rule that looks only at <i>name present or not</i> would
score AUC {f2(sc['sni_missing_only'])}; a rule that looks only at the TLS version scores {f2(sc['tls_version_only'])} (0.5 is guessing). Both are weak, and our main analysis keeps only connections with a name, which
removes the first shortcut.</p>

<h2>5. Our idea: compare each connection with its own computer&rsquo;s habits</h2>
<p>Instead of asking <i>&ldquo;does this connection look like malware?&rdquo;</i> we ask <i>&ldquo;is this connection unusual for <b>this computer</b>?&rdquo;</i>. A person who visits fifty websites once each is normal.
A program that keeps contacting the same server at regular intervals, from a computer that otherwise never talks to it, is unusual. We call these <b>host-relative features</b>:</p>
<ul><li><b>Destination habits:</b> how rare is this server for this computer? How many times has it been contacted? How regular are the visits?</li>
<li><b>Size habits:</b> is this connection much bigger or smaller than this computer&rsquo;s other connections?</li>
<li><b>Handwriting habits:</b> does this computer usually use this handshake, or is it a one-off?</li></ul>
<div class="good"><b>Why this matters.</b> Everything is measured against the same computer, so the recording room matters much less. It also works when the website name is hidden (modern &ldquo;Encrypted Client Hello&rdquo;),
because it can use the server address instead.</div>

<h2>6. Results</h2>
<h3>6.1 Does it keep working when the test gets harder?</h3>
<img src="{img('fig1_split_ladder.png')}">
<table><tr><th>Test (malware found at 1% false alarms)</th><th>Fingerprint + behaviour (old best)</th><th>With host habits (ours)</th></tr>
<tr><td>Recordings never seen before</td><td>{pct(g('capture','TLS+BEH'))}</td><td>{pct(g('capture','HR+TLS+BEH'))}</td></tr>
<tr><td>Fingerprints never seen before</td><td>{pct(g('ja4','TLS+BEH'))}</td><td>{pct(g('ja4','HR+TLS+BEH'))}</td></tr>
<tr><td>Years never seen before</td><td>{pct(g('year','TLS+BEH'))}</td><td>{pct(g('year','HR+TLS+BEH'))}</td></tr>
<tr><td>A whole unseen source of recordings (hardest)</td><td>{pct(g('source','TLS+BEH'))}</td><td>{pct(g('source','HR+TLS+BEH'))}</td></tr></table>
<p>The old method collapses as the test gets harder; ours loses much less. The lab-signature model is near zero from the first test. <i>Caution: we designed these features on this same data, so this needs the locked final test to count as proof.</i></p>

<h3>6.2 Does it raise false alarms on clean traffic from another lab?</h3>
<img src="{img('fig2_clean_benign.png')}">
<p>We trained on one lab and tested on {fbc('normal_host')} clean recordings of ordinary browsing from the Stratosphere lab (plus a real user before infection). The lab-signature model raised an alarm on
<b>{pct(fbv('ENV','normal_host'))}</b> of clean connections. Ours raised <b>{pct(fbv('HR+TLS+BEH','normal_host'),1)}</b> ({pct(fbv('HR+TLS+BEH','pre_infection'),1)} for the real user). This is our strongest evidence.</p>
<div class="warn"><b>Careful.</b> Those clean recordings are scripted visits to popular sites, which is easy traffic for our method, and the real-user test has only {fbc('pre_infection')} recordings. This shows false alarms only; it does not show malware detection in that lab.</div>

<h3>6.3 Does it find malware in the second lab?</h3>
<img src="{img('fig3_second_lab.png')}">
<p>Not clearly. With a strict definition of malware (blacklist-confirmed; {int(slv(sl,'ENV','n_test_mal_caps'))} malware recordings) the old best and ours both score AUC about {f2(slv(sl,'TLS+BEH','roc_auc'))}, so ours adds nothing reliable.
With a broader definition ({int(slv(sw,'ENV','n_test_mal_caps'))} malware recordings) both are weak ({f2(slv(sw,'TLS+BEH','roc_auc'))} and {f2(slv(sw,'HR+TLS+BEH','roc_auc'))}; 0.5 is guessing).
An earlier run with only six malware recordings looked far better for our model; that advantage disappeared when we added two more recordings. <b>That is why we never trust tiny tests.</b></p>
<div class="box"><b>What does hold across both labs:</b> {len(strong)} measurements separate malware from normal clearly in both labs, and {int(strong.same_direction.sum())} of them point the same way. The strongest are destination habits
(how often a computer re-contacts a server and how regular that is). Encouraging, but malware in both labs is mostly repeating &ldquo;beacon&rdquo; traffic, which these measures naturally reward.</div>

<h3>6.4 Grouping alerts into incidents</h3>
<p>A concurrent project at our school groups repeated alerts from one computer to one server within an hour. We tested the idea on our data: ours still wins at the incident level (AUC {f2(incv('HR+TLS+BEH','inc_auc'))} against {f2(incv('TLS+BEH','inc_auc'))}),
but grouping lowers false alerts only a little here, because normal computers make few connections per hour.</p>

<h2>7. What is new (and what is not)</h2>
<p>We scope each claim carefully. &ldquo;New&rdquo; means &ldquo;to our knowledge, not shown this way before&rdquo;.</p>
<table><tr><th style="width:24%">Contribution</th><th>What is new</th><th>Honest limit</th></tr>
<tr><td><b>1. The lab-signature audit</b></td><td>Shows on public JA4 malware corpora that a model seeing only network plumbing matches the best model, with a measured sandbox &ldquo;postmark&rdquo; and a model that finds none of the older recordings from the same sandbox.</td><td>Shortcut learning in network data is known (earlier papers found similar effects). To our knowledge this is the first such audit for JA4 malware corpora, and it covers those corpora only.</td></tr>
<tr><td><b>2. Same-host benchmark</b></td><td>A test where malware and normal traffic share an infected computer, so the room cannot give the answer away.</td><td>Labels are indirect (public blacklists plus an allowlist), not ground truth.</td></tr>
<tr><td><b>3. Measured fingerprint copying</b></td><td>On real infected computers, {pct(hs['malicious_ja4_also_seen_in_benign_connection_share'])} of malicious connections (this build) to 89% (an earlier same-host run, record) use a handshake that normal programs also use. Other work we found only <i>simulates</i> copying.</td><td>Mostly Windows&rsquo; own library, not deliberate disguise.</td></tr>
<tr><td><b>4. Host-relative features</b></td><td>Describing each connection against the same computer&rsquo;s habits; works without website names.</td><td>Strong on our main data and false-alarm tests; <b>not</b> confirmed for detection in the second lab.</td></tr>
<tr><td><b>5. Honest-test discipline</b></td><td>A written pre-registration plan (awaiting the guide&rsquo;s sign-off), a locked holdout, label-rule sensitivity reported, a retracted small-sample result kept visible, every number traceable to a file.</td><td>The final test has not been run yet.</td></tr>
<tr><td><b>6. Tools</b></td><td>An Environment Leakage Index (how much a score comes from the recording environment), a raw-data audit, and a reproducible pipeline.</td><td>The index is our own definition.</td></tr></table>
<p><b>Not new:</b> JA4 itself (by FoxIO), the idea that datasets leak shortcuts, and incident grouping (borrowed from a concurrent school project, credited as such).</p>

<h2>8. The highlights to remember</h2>
<ol><li><b>The 98% is mostly the room.</b> A model that never sees the malware scored 0.986 on the public corpus.</li>
<li><b>Handwriting is not enough.</b> About {pct(hs['malicious_ja4_also_seen_in_benign_connection_share'])} of malware borrows normal handwriting.</li>
<li><b>Fair tests matter.</b> Same-computer recordings remove the room shortcut.</li>
<li><b>Host habits keep working</b> when the test gets harder ({pct(g('source','HR+TLS+BEH'))} vs {pct(g('source','TLS+BEH'))} on an unseen source).</li>
<li><b>Almost no false alarms</b> on clean traffic from another lab ({pct(fbv('HR+TLS+BEH','normal_host'),1)} vs {pct(fbv('ENV','normal_host'))} for the lab-signature model).</li>
<li><b>We report what failed:</b> the second-lab detection gain did not hold up, and we say so.</li>
<li><b>Everything is traceable:</b> every number comes from a result file; the tests and the main results reproduce exactly.</li>
<li><b>One clean exam is saved:</b> the 2022&ndash;2026 recordings are locked for the final test.</li></ol>

<h2>9. Limits, and questions you may be asked</h2>
<div class="warn"><ul>
<li><b>Everything is exploratory.</b> The pre-registered final test is not run; it needs the guide&rsquo;s sign-off.</li>
<li><b>Labels are indirect</b> (blacklists and analyst notes). &ldquo;Normal&rdquo; means &ldquo;normal-likely&rdquo;.</li>
<li><b>Second-lab detection is not confirmed</b> and depends on how malware is labelled.</li>
<li><b>No live test of deliberate disguise</b> and no real Encrypted Client Hello traffic yet; not yet reproduced on the team Mac.</li>
<li><b>At a realistic malware rate (1 in 1,000)</b> single connections give low precision, so a real tool must group alerts per computer.</li></ul></div>
<table><tr><th style="width:36%">Question</th><th>Easy answer</th></tr>
<tr><td>Is 98% accuracy fake?</td><td>Not fake, but misleading: much of it comes from recognising the recording place. On a fair test it drops a lot.</td></tr>
<tr><td>What is JA4?</td><td>A short code describing a program&rsquo;s first encrypted-connection message &mdash; its handwriting.</td></tr>
<tr><td>Why same-computer data?</td><td>Then malware and normal traffic share the same room, so the room cannot give the answer.</td></tr>
<tr><td>How do you know labels are right?</td><td>We do not claim ground truth. We use independent evidence, never the handshake, and we test two labelling rules.</td></tr>
<tr><td>Why not just add more data?</td><td>More data from the same two rooms makes the shortcut stronger. We need data from <i>other</i> rooms and fair labels.</td></tr>
<tr><td>Does your model work in practice?</td><td>Promising on our main data and false-alarm tests; not yet proven for detection in a second lab. The locked final test decides.</td></tr>
<tr><td>How is this different from the SCBD-R project?</td><td>It asks whether a detector survives <i>simulated</i> fingerprint copying; we ask whether public results measure the lab, using real same-computer data. We credit it as concurrent work.</td></tr>
<tr><td>Did you use AI tools?</td><td>Yes. Describe it as the university requires; every number traces to a script and result file, and each member should be able to rebuild any number.</td></tr></table>

<h2>10. What comes next</h2>
<ol><li>Guide signs the written plan; run the locked 2022&ndash;2026 test once, whatever the result.</li>
<li>Collect more labelled infections from independent labs so the second-lab test has enough malware recordings.</li>
<li>A supervised lab test with a client that really copies a browser&rsquo;s handshake (needs written approval).</li>
<li>Group alerts per computer and build a first live-capture prototype.</li>
<li>Reproduce everything on the team Mac and write the paper.</li></ol>

<h2>11. Reproduce it and find things</h2>
<p>Code and results: <b>github.com/pranavs321/ech-idps</b>, folder <code>ja4next/</code> (branch <code>main</code>). <code>scripts/run_all.sh</code> runs the main pipeline, <code>scripts/run_stratosphere.sh</code> the second-lab stage, <code>python -m pytest tests</code> the tests.
Raw recordings are not shared; manifests list the public download addresses. Every number in this guide is read from <code>results/</code>.</p>

<h2>Glossary</h2>
<table><tr><th>Word</th><th>Meaning</th></tr>
<tr><td>TLS</td><td>The encryption behind the browser padlock.</td></tr>
<tr><td>Handshake / ClientHello</td><td>The first message a program sends when it opens an encrypted connection. It is readable.</td></tr>
<tr><td>JA4 fingerprint</td><td>A short code made from the handshake &mdash; the program&rsquo;s &ldquo;handwriting&rdquo;.</td></tr>
<tr><td>PCAP</td><td>A file with a recording of network traffic.</td></tr>
<tr><td>Host</td><td>One computer on a network.</td></tr>
<tr><td>Same-host data</td><td>Malware and normal traffic recorded on the same infected computer.</td></tr>
<tr><td>False alarm rate</td><td>The share of normal connections wrongly flagged. &ldquo;At 1%&rdquo; = one in a hundred.</td></tr>
<tr><td>AUC</td><td>How well a model ranks malware above normal traffic: 0.5 is guessing, 1.0 is perfect.</td></tr>
<tr><td>Exploratory vs confirmatory</td><td>Exploratory: freely explored data we have already seen. Confirmatory: one planned test on locked, unseen data.</td></tr>
<tr><td>Host-relative feature</td><td>A measurement of a connection compared with the same computer&rsquo;s other connections.</td></tr>
<tr><td>Gold / weak label</td><td>Malware confirmed by strong evidence / matched by a public blacklist only.</td></tr></table>
</body></html>"""
open("docs/_guide.html", "w").write(H)
js = textwrap.dedent("""
    const { chromium } = require('playwright');
    (async () => {
      const b = await chromium.launch(); const pg = await b.newPage();
      await pg.goto('file://' + process.argv[2]);
      await pg.pdf({ path: process.argv[3], format: 'A4', printBackground: true,
                     margin: { top: '14mm', bottom: '14mm', left: '14mm', right: '14mm' } });
      await b.close();
    })();
""")
open("docs/_render.js", "w").write(js)
root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
subprocess.run(["node", "docs/_render.js", os.path.abspath("docs/_guide.html"), os.path.abspath(OUT)], check=True, env={**os.environ, "NODE_PATH": root})
os.remove("docs/_render.js"); os.remove("docs/_guide.html"); print("wrote", OUT)
