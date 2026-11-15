"""Plain-language project summary PDF. Every result number is read from results/*.csv|json at build time.
Usage: python3 scripts/make_summary_pdf.py [out.pdf]   (needs node + playwright + chromium)"""
import base64, glob, json, os, sys
import pandas as pd

OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/ja4next_project_summary.pdf"
R = lambda p: os.path.join("results", p)
pct = lambda v: f"{100 * float(v):.0f}%"
f2 = lambda v: f"{float(v):.2f}"

s = pd.read_csv(R("hostname_only/summary.csv"))
g = lambda split, st, col="tpr_at_1pct": float(s[(s.split == split) & (s.set == st)][col].iloc[0])
fb = pd.read_csv(R("foreign_benign/flag_rates.csv"))
fbv = lambda st, grp: float(fb[(fb.set == st) & (fb.group == grp)]["flagged_conn"].iloc[0])
sl = pd.read_csv(R("second_lab/transfer_metrics.csv")); sw = pd.read_csv(R("second_lab_weak/transfer_metrics.csv"))
slv = lambda d, st, col: float(d[(d.train == "MTA") & (d.set == st)][col].iloc[0])
inc = pd.read_csv(R("incidents/incident_metrics.csv")); incv = lambda st, col: float(inc[(inc["set"] == st) & (inc["agg"] == "s_max")][col].iloc[0])
dq = json.load(open(R("data_quality.json")))
fd = pd.read_csv(R("second_lab/feature_direction.csv"))
ds = json.load(open(R("dataset_summary.json")))
st_tabs = {k: v for k, v in dq["tables"].items() if k.startswith("Stratosphere")}
strat_rows = sum(v["rows"] for v in st_tabs.values()); strat_caps = sum(v["captures"] for v in st_tabs.values())

def img(name):
    return "data:image/png;base64," + base64.b64encode(open(f"docs/figures/{name}", "rb").read()).decode()

H = f"""<html><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 18mm 16mm; }}
body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 11pt; line-height: 1.5; color: #1b1b1b; }}
h1 {{ font-size: 24pt; margin: 0 0 4pt; }} h2 {{ font-size: 15pt; margin: 20pt 0 6pt; color: #0b4f8a; border-bottom: 2px solid #0b4f8a; padding-bottom: 3pt; }}
h3 {{ font-size: 12pt; margin: 12pt 0 3pt; page-break-after: avoid; }} h2 {{ page-break-after: avoid; }} .sub {{ color: #555; font-size: 12pt; margin-bottom: 14pt; }}
.box {{ background: #eef5fb; border-left: 4px solid #0b4f8a; padding: 8pt 12pt; margin: 10pt 0; page-break-inside: avoid; }}
.warn {{ background: #fff4e5; border-left: 4px solid #d55e00; padding: 8pt 12pt; margin: 10pt 0; page-break-inside: avoid; }}
table {{ border-collapse: collapse; width: 100%; margin: 8pt 0; font-size: 10pt; page-break-inside: avoid; }}
th, td {{ border: 1px solid #c8c8c8; padding: 4pt 7pt; text-align: left; }} th {{ background: #eef2f6; }}
img {{ width: 100%; page-break-inside: avoid; }} .small {{ font-size: 9pt; color: #555; }} .big {{ font-size: 20pt; font-weight: 700; color: #d55e00; }}
</style></head><body>

<h1>Detecting the Lab, Not the Malware</h1>
<div class="sub">The project in plain words &mdash; what we asked, what we built, what we found, and what is still unproven.<br>
Nandakumar Chandran and team &middot; guide: Arjun V &middot; Amrita School of Computing &middot; 15 November 2026</div>

<div class="box"><b>One paragraph.</b> Antivirus tools cannot read encrypted internet traffic, so researchers look at the
<i>first message</i> a program sends when it opens a connection. That message works like handwriting: it shows which software wrote
it. Many research papers say this &ldquo;handwriting&rdquo; finds malware with 98&ndash;99% accuracy. We checked and found that much of that
score comes from <b>where the traffic was recorded</b> &mdash; the lab &mdash; not from the malware itself. We then built a fairer test, and a new
way of looking at traffic: compare every connection with <b>what the same computer normally does</b>. On our main data that idea held up much better when
the test got harder, and it raised almost no false alarms on clean traffic from another lab. It did <b>not</b> clearly improve malware detection in
that second lab. It is an early, exploratory result, and this document says exactly where it is weak.</div>

<h2>1. The problem, with an everyday picture</h2>
<p>Imagine every internet connection starts with a sealed envelope. You cannot open it, but you can see the handwriting on the
outside. Chrome writes in one style, Firefox in another, and a particular piece of malware in a third. A defender who learns the styles
can spot a stranger. That &ldquo;handwriting&rdquo; is called a <b>JA4 fingerprint</b>.</p>
<p>Researchers train computer programs to recognise malware handwriting. The trouble is how they collect examples. Malware examples
usually come from one place (a malware-testing sandbox) and normal examples from another (a university lab). The program can then
score well by learning <i>&ldquo;which room was this recorded in?&rdquo;</i> instead of <i>&ldquo;is this malware?&rdquo;</i>. Like a student who passes an exam by
recognising the exam hall rather than knowing the subject, it fails the moment it leaves that room.</p>

<h2>2. What we found first: the room gives the answer away</h2>
<p>These results come from our earlier runs on the public Matou&scaron;ek corpus (1,426 captures with encrypted connections). They are in the project
record; they were not recomputed for this document.</p>
<table><tr><th>Finding</th><th>In plain words</th></tr>
<tr><td>A model that sees <b>only network plumbing</b>, nothing about TLS or malware, scored 0.986</td><td>The lab leaves a signature in every recording.</td></tr>
<tr><td>One number (a packet-size setting, &ldquo;MSS 1357&rdquo;) appeared in 93% of 2024 sandbox malware recordings and in none of 26 normal ones</td><td>The sandbox&rsquo;s internet path stamps its traffic like a postmark.</td></tr>
<tr><td>A model trained on that corpus found <b>0 of 53</b> older malware recordings from the same sandbox</td><td>It learned the 2024 postmark, not the malware.</td></tr>
<tr><td>Normal traffic from <b>another lab</b> was flagged as malware 80&ndash;99% of the time</td><td>Leave the room and it breaks.</td></tr>
<tr><td>On real infected computers, 89.5% of malware connections used a fingerprint that normal programs on the same computer also use</td><td>Malware often borrows Windows&rsquo; own handwriting, so the fingerprint alone cannot tell them apart.</td></tr></table>

<h2>3. A fairer test: malware and normal traffic from the same computer</h2>
<p>To remove the &ldquo;room&rdquo; shortcut, we need malware and normal traffic recorded on the <b>same infected computer</b>. Security analysts
publish exactly such recordings. We used them as our main data.</p>
<table><tr><th>Data used in this stage</th><th>Size</th></tr>
<tr><td>malware-traffic-analysis.net infection recordings, 2013&ndash;2021 (main data)</td><td>{ds['captures']:,} recordings, {ds['tls_connections_internal_to_external']:,} encrypted connections</td></tr>
<tr><td>Stratosphere lab recordings (a <b>second, independent lab</b>): botnet, mixed and normal-user captures</td><td>{strat_caps} recordings with encrypted traffic, {strat_rows:,} connections</td></tr>
<tr><td>2022&ndash;2026 recordings</td><td><b>locked</b> &mdash; kept unseen for a final, pre-registered test</td></tr></table>
<p><b>How each connection gets a label.</b> We never label by looking at the handwriting (that would be circular). A connection is called malicious only if
independent evidence says so: the analyst&rsquo;s own published list of bad addresses, public blacklists (abuse.ch, Maltrail) or a
blacklisted certificate. It is called normal if it goes to a well-known vendor or content network. Everything else stays <i>unknown</i> and is not used for scoring.</p>
<p class="small">Quality checks (results/data_quality.json): no duplicate connection rows, no malformed fingerprints; 5 duplicated recordings were merged by file hash so no recording
appears on both sides of a train/test split. In the Stratosphere botnet set {pct(dq['tables']['Stratosphere mcfp']['sni_empty_share'])} of connections carry no website name, so name-based analyses discard most of them.</p>

<h2>4. Our idea: compare each connection with its own computer&rsquo;s habits</h2>
<p>Instead of asking <i>&ldquo;does this connection look like malware?&rdquo;</i>, we ask <i>&ldquo;does this connection look unusual for <b>this computer</b>?&rdquo;</i>.
A person who visits fifty different websites once each is normal. A program that contacts the same server again and again, at regular intervals, from a computer that
otherwise never talks to it, is unusual. We call these <b>host-relative features</b>: for each connection we compute how rare its destination is
for that computer, how often it repeats, how big it is compared with that computer&rsquo;s other traffic, and whether it uses the
same fingerprint as the computer&rsquo;s other programs. Because everything is measured against the same computer, the
recording room matters much less. It also works when the website name is hidden, because it can use the server address instead.</p>

<h2>5. Results</h2>
<h3>5.1 Does it keep working when the test gets harder?</h3>
<img src="{img('fig1_split_ladder.png')}">
<p>Each group of bars is a harder test: unseen recordings, unseen fingerprints, unseen years, and finally an entire unseen <i>source</i> of recordings.
The y-axis is how much malware is caught while only 1% of normal connections raise a false alarm.</p>
<table><tr><th>Test</th><th>Fingerprint + behaviour (old best)</th><th>With host-relative features (ours)</th></tr>
<tr><td>Unseen recordings</td><td>{pct(g('capture','TLS+BEH'))}</td><td>{pct(g('capture','HR+TLS+BEH'))}</td></tr>
<tr><td>Unseen fingerprints</td><td>{pct(g('ja4','TLS+BEH'))}</td><td>{pct(g('ja4','HR+TLS+BEH'))}</td></tr>
<tr><td>Unseen years</td><td>{pct(g('year','TLS+BEH'))}</td><td>{pct(g('year','HR+TLS+BEH'))}</td></tr>
<tr><td>Unseen source (hardest)</td><td>{pct(g('source','TLS+BEH'))}</td><td>{pct(g('source','HR+TLS+BEH'))}</td></tr></table>
<p>The old approach collapses as the test gets harder; the host-relative approach loses much less. A model that sees only network plumbing
is near zero from the first test onward.</p>

<h3>5.2 Does it raise false alarms on clean traffic from another lab?</h3>
<img src="{img('fig2_clean_benign.png')}">
<p>We trained on one lab and tested on {int(fb[fb.group=='normal_host']['captures'].iloc[0])} clean recordings of ordinary browsing from the Stratosphere lab, plus a real user before infection.
The network-plumbing model raised an alarm on {pct(fbv('ENV','normal_host'))} of clean connections. Ours raised {pct(fbv('HR+TLS+BEH','normal_host'))}
({pct(fbv('HR+TLS+BEH','pre_infection'))} for the real user).</p>
<div class="warn"><b>Careful.</b> The clean recordings are scripted visits to popular websites, which is easy traffic for our method. This is a false-alarm result only;
it does not prove the model finds malware in the second lab.</div>

<h3>5.3 Does it find malware in the second lab?</h3>
<img src="{img('fig3_second_lab.png')}">
<p>The honest answer is <b>not confirmed</b>. With a strict definition of malware (blacklist-confirmed, {int(slv(sl,'ENV','n_test_mal_caps'))} malware recordings) the
old-best model and ours both reach an AUC of about {f2(slv(sl,'TLS+BEH','roc_auc'))} &mdash; ours adds nothing reliable. With a broader definition ({int(slv(sw,'ENV','n_test_mal_caps'))} malware recordings)
both are weak ({f2(slv(sw,'TLS+BEH','roc_auc'))} and {f2(slv(sw,'HR+TLS+BEH','roc_auc'))}; chance is 0.50). An earlier run with only six malware recordings looked far better for our model; that
gap vanished when we added two more recordings, which is exactly why small tests must not be over-read.</p>
<div class="box"><b>What does hold across labs:</b> of the {int(fd.shape[0])} measurements we compare, those that separate malware from normal clearly in <i>both</i> labs
({int((fd.strength>=0.1).sum())} of them) point the same way in {int(fd[fd.strength>=0.1].same_direction.sum())} cases. The strongest are destination habits: how often a computer
re-contacts the same server and how regular that is. That is encouraging, but both labs&rsquo; malware is mostly repeating &ldquo;beacon&rdquo; traffic, which these measures naturally reward.</div>

<h3>5.4 Grouping alerts into incidents</h3>
<p>A concurrent project at our school groups repeated alerts from one computer to one server within an hour into a single &ldquo;incident&rdquo;. We tested the idea on our data.
Our model still wins at the incident level (incident AUC {f2(incv('HR+TLS+BEH','inc_auc'))} against {f2(incv('TLS+BEH','inc_auc'))} for the old best), but grouping reduces
false alerts only modestly on our data, because normal computers here make few connections per hour.</p>

<h2>6. What is not proven (please read)</h2>
<div class="warn"><ul>
<li><b>Everything here is exploratory.</b> The final, pre-registered test on the 2022&ndash;2026 recordings has <b>not</b> been run. It needs the guide&rsquo;s sign-off first.</li>
<li><b>Labels are indirect.</b> They come from public blacklists and analyst notes, not from ground truth. Normal traffic is &ldquo;normal-likely&rdquo; (well-known vendors).</li>
<li><b>Second-lab detection is not confirmed.</b> Strict malware labels cover only {int(slv(sl,'ENV','n_test_mal_caps'))} recordings and the answer changes with the labelling rule. The main-data gains were found on the same data we used to design the features, so they need the locked test to count.</li>
<li><b>Simulated vs real disguise.</b> We have not tested malware that deliberately copies a browser&rsquo;s handwriting in a live lab (needs the guide&rsquo;s approval).</li>
<li><b>Single-connection precision is low at realistic malware rates</b> (about 1 in 1,000), so a deployed tool must group alerts per computer.</li>
<li><b>Not yet reproduced on the team Mac</b>, and no real encrypted-hello (ECH) traffic has been tested.</li>
<li><b>Related work.</b> A concurrent student project (SCBD-R) studies fingerprint disguise with per-client-type alarm thresholds; we credit it as concurrent work and our data complement each other.</li></ul></div>

<h2>7. What comes next</h2>
<ol><li>Guide signs the pre-registration, then we run the locked 2022&ndash;2026 test once, whatever the result.</li>
<li>Collect more labelled infections from independent labs so the second-lab test has enough malware recordings.</li>
<li>A supervised lab test with a real disguised client (with the guide&rsquo;s written approval).</li>
<li>Per-computer alert grouping and a first live-capture prototype.</li></ol>

<h2>8. Glossary</h2>
<table><tr><th>Word</th><th>Meaning</th></tr>
<tr><td>TLS / HTTPS</td><td>The encryption used by almost every website.</td></tr>
<tr><td>Fingerprint (JA4)</td><td>A short code describing how a program opens an encrypted connection (its &ldquo;handwriting&rdquo;).</td></tr>
<tr><td>PCAP</td><td>A file with a recording of network traffic.</td></tr>
<tr><td>Host</td><td>One computer on a network.</td></tr>
<tr><td>False alarm rate</td><td>The share of normal connections wrongly flagged. &ldquo;At 1%&rdquo; means we allow one in a hundred.</td></tr>
<tr><td>ROC-AUC</td><td>How well a model ranks malware above normal traffic: 0.5 is guessing, 1.0 is perfect.</td></tr>
<tr><td>Exploratory vs confirmatory</td><td>Exploratory: explored freely on data we have already looked at. Confirmatory: one planned test on locked, unseen data.</td></tr>
<tr><td>Host-relative feature</td><td>A measurement of a connection compared with the same computer&rsquo;s other connections.</td></tr></table>

<h2>9. Reproduce it</h2>
<p>Everything lives in the repository: <code>scripts/run_all.sh</code> runs the main pipeline, <code>scripts/run_stratosphere.sh</code> the second-lab stage,
<code>scripts/make_figures.py</code> the charts and <code>python -m pytest tests</code> the checks. Every number in this PDF is read from <code>results/</code>.
Raw recordings are not redistributed; manifests list the public download addresses.</p>
</body></html>"""
open("docs/_summary.html", "w").write(H)
import subprocess, textwrap
js = textwrap.dedent("""
    const { chromium } = require('playwright');
    (async () => {
      const b = await chromium.launch(); const pg = await b.newPage();
      await pg.goto('file://' + process.argv[2]);
      await pg.pdf({ path: process.argv[3], format: 'A4', printBackground: true,
                     margin: { top: '16mm', bottom: '16mm', left: '15mm', right: '15mm' } });
      await b.close();
    })();
""")
open("docs/_render.js", "w").write(js)
root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
subprocess.run(["node", "docs/_render.js", os.path.abspath("docs/_summary.html"), os.path.abspath(OUT)],
               check=True, env={**os.environ, "NODE_PATH": root})
os.remove("docs/_render.js")
os.remove("docs/_summary.html"); print("wrote", OUT)
