import React, { useEffect, useState } from "react";
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";
import TextEngine from "spring-text-engine";
import {
  Activity, ArrowUpRight, BadgeCheck, Bell, Blocks, Check, ChevronDown,
  CircleHelp, Clock3, Copy, ExternalLink, Fingerprint, Globe2, LayoutDashboard,
  Link2, LockKeyhole, Menu, MessageSquareText, Radar, ScanSearch, Search,
  Shield, ShieldAlert, ShieldCheck, Sparkles, Terminal, X, Zap
} from "lucide-react";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const DEMO = import.meta.env.VITE_DEMO_MODE !== "false";

function Heading({ tag = "h2", children, className = "" }) {
  return <TextEngine
    tag={tag}
    mode="once"
    letterOut={{ opacity: 0, scale: 0 }}
    letterIn={{ opacity: 1, scale: 1 }}
    letterConfig={{ tension: 320, friction: 14 }}
    letterStagger={25}
    style={{ width: "100%", minWidth: 0, display: "flex", flexWrap: "wrap" }}
    className={`justify-center ${className}`}
  >{children}</TextEngine>;
}

const demoReport = (url) => ({
  id: "TL-" + Math.random().toString(36).slice(2, 8).toUpperCase(),
  target: url,
  classification: "Suspicious",
  risk_score: 68,
  coverage: 86,
  timestamp: new Date().toISOString(),
  findings: [
    { id: "F-01", check: "Domain reputation", severity: "medium", confidence: 0.91, evidence: "Domain was not found in the local allowlist; reputation requires additional context.", source: "Reputation rules" },
    { id: "F-02", check: "Transport security", severity: "low", confidence: 0.99, evidence: "TLS endpoint responded. A valid certificate does not establish that a site is trustworthy.", source: "TLS inspection" },
    { id: "F-03", check: "HTTP security headers", severity: "high", confidence: 0.96, evidence: "Content-Security-Policy header was not observed in the response.", source: "Header analysis" }
  ],
  unavailable_checks: ["Threat-intelligence provider (demo mode)"]
});

function CursorFX() {
  const [pos, setPos] = useState({ x: -100, y: -100 });
  const [active, setActive] = useState(false);
  useEffect(() => {
    if (window.matchMedia("(pointer: coarse)").matches) return;
    const move = (e) => { setPos({ x: e.clientX, y: e.clientY }); setActive(true); };
    window.addEventListener("mousemove", move);
    return () => window.removeEventListener("mousemove", move);
  }, []);
  return <>
    <div className={`cursor-aura ${active ? "visible" : ""}`} style={{ transform: `translate3d(${pos.x}px, ${pos.y}px, 0)` }} />
    <div className={`cursor-ring ${active ? "visible" : ""}`} style={{ transform: `translate3d(${pos.x}px, ${pos.y}px, 0)` }} />
    <div className={`cursor-dot ${active ? "visible" : ""}`} style={{ transform: `translate3d(${pos.x}px, ${pos.y}px, 0)` }} />
  </>;
}

function BackgroundFX() {
  return <div className="ambient" aria-hidden="true">
    <div className="ambient-grid" /><div className="orb orb-one" /><div className="orb orb-two" />
    <div className="ambient-noise" />
  </div>;
}

function AuthPage({ mode = "signin", onModeChange, onBack, onSuccess }) {
  const [formMode, setFormMode] = useState(mode);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    setFormMode(mode);
    setSubmitted(false);
  }, [mode]);

  const register = formMode === "register";
  const submit = (event) => {
    event.preventDefault();
    setSubmitted(true);
    window.setTimeout(() => onSuccess(), 450);
  };

  return <div className="auth-shell">
    <BackgroundFX/><CursorFX/>
    <header className="auth-nav">
      <button className="brand brand-button" onClick={onBack} aria-label="Back to TrustLens home"><span className="brand-mark"><ShieldCheck size={20}/></span><span>trust<span className="brand-light">lens</span><small> DIGITAL TRUST INTELLIGENCE</small></span></button>
      <button className="auth-back" onClick={onBack}><ArrowUpRight size={14}/> Back to home</button>
    </header>
    <main className="auth-main">
      <motion.section className="auth-story" initial={{ opacity: 0, x: -24 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: reduceMotion ? 0 : .55 }}>
        <div className="eyebrow"><span/> TRUSTLENS WORKSPACE</div>
        <Heading tag="h1" className="auth-story-title">See the signal before the noise.</Heading>
        <p>One secure workspace for evidence-led decisions across URLs, messages, and report integrity.</p>
        <div className="auth-signal-stack" aria-label="TrustLens capabilities">
          <div><span className="signal-pulse"><ShieldCheck size={15}/></span><div><b>Evidence stays visible</b><small>Every conclusion carries its source.</small></div><Check size={15}/></div>
          <div><span className="signal-pulse violet"><Fingerprint size={15}/></span><div><b>Signals stay in context</b><small>Confidence, coverage, and gaps included.</small></div><Check size={15}/></div>
          <div><span className="signal-pulse green"><Blocks size={15}/></span><div><b>Integrity stays verifiable</b><small>Preserve a tamper-evident trail.</small></div><Check size={15}/></div>
        </div>
      </motion.section>
      <motion.section className="auth-card glass" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: reduceMotion ? 0 : .55, delay: reduceMotion ? 0 : .08 }}>
        <div className="auth-card-top"><div><div className="eyebrow"><span/> SECURE ACCESS</div><Heading tag="h2" className={register ? "auth-register-title" : ""}></Heading><p>{register ? "Start with a private TrustLens workspace." : "Continue to your security workspace."}</p></div><span className="auth-lock"><LockKeyhole size={17}/></span></div>
        <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button className={!register ? "active" : ""} onClick={() => { setFormMode("signin"); onModeChange("signin"); }} role="tab" aria-selected={!register}>Sign in</button>
          <button className={register ? "active" : ""} onClick={() => { setFormMode("register"); onModeChange("register"); }} role="tab" aria-selected={register}>Register</button>
        </div>
        <form className="auth-form" onSubmit={submit}>
          {register && <div className="auth-name-grid"><label>First name<input value={firstName} onChange={e=>setFirstName(e.target.value)} autoComplete="given-name" placeholder="First name" required/></label><label>Last name<input value={lastName} onChange={e=>setLastName(e.target.value)} autoComplete="family-name" placeholder="Last name" required/></label></div>}
          <label>Work email<input value={email} onChange={e=>setEmail(e.target.value)} autoComplete="email" type="email" placeholder="you@company.com" required/></label>
          <label>Password <span>{!register && <button type="button" className="forgot-link">Forgot password?</button>}</span><input value={password} onChange={e=>setPassword(e.target.value)} autoComplete={register ? "new-password" : "current-password"} type="password" placeholder="••••••••" minLength={8} required/></label>
          {register && <label className="auth-check"><input type="checkbox" required/><span>I agree to the TrustLens terms and privacy policy.</span></label>}
          <button className="primary-button auth-submit" type="submit" disabled={submitted}>{submitted ? <><span className="spinner"/> CONNECTING</> : <>{register ? "Create workspace" : "Sign in to workspace"}<ArrowUpRight size={16}/></>}</button>
        </form>
        <p className="auth-switch">{register ? "Already have an account?" : "New to TrustLens?"} <button onClick={() => { const next = register ? "signin" : "register"; setFormMode(next); onModeChange(next); }}>{register ? "Sign in" : "Create an account"}</button></p>
        <div className="auth-foot"><LockKeyhole size={12}/> Your workspace is protected with privacy-minded defaults.</div>
      </motion.section>
    </main>
  </div>;
}

function LandingPage({ onEnter, onAuth }) {
  const [model, setModel] = useState({ x: 0, y: 0, scroll: 0 });
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    if (reduceMotion) return undefined;
    const move = (event) => setModel(value => ({ ...value, x: (event.clientX / window.innerWidth - .5) * 18, y: (event.clientY / window.innerHeight - .5) * 18 }));
    const scroll = () => setModel(value => ({ ...value, scroll: Math.min(window.scrollY, 620) }));
    window.addEventListener("mousemove", move);
    window.addEventListener("scroll", scroll, { passive: true });
    return () => { window.removeEventListener("mousemove", move); window.removeEventListener("scroll", scroll); };
  }, [reduceMotion]);

  return <main className="landing-page">
    <nav className="landing-nav">
      <a className="brand" href="#home"><span className="brand-mark"><ShieldCheck size={20}/></span><span>trust<span className="brand-light">lens</span><small> DIGITAL TRUST INTELLIGENCE</small></span></a>
      <div className="landing-links"><a href="#platform">Platform</a><a href="#approach">Our approach</a><button className="secondary-button" onClick={() => onAuth("signin")}>Sign in <ArrowUpRight size={14}/></button></div>
    </nav>
    <section className="landing-hero" id="home">
      <div className="landing-copy"><div className="eyebrow"><span/> A CLEARER VIEW OF ONLINE RISK</div><Heading tag="h1" className="landing-hero-title">Trust what you can verify.</Heading><p>Understand the signals behind a suspicious link or message. TrustLens turns security checks into evidence your team can act on.</p><div className="landing-actions"><button className="primary-button" onClick={() => onAuth("register")}>Open security workspace <ArrowUpRight size={16}/></button><a href="#platform">Explore the platform <span>↓</span></a></div><div className="landing-proof"><span><ShieldCheck size={15}/> Evidence-led assessments</span><span><LockKeyhole size={14}/> Privacy-minded by design</span></div></div>
      <motion.div className="landing-visual" aria-label="TrustLens security assessment preview" style={{ "--model-x": `${model.x}px`, "--model-y": `${model.y - model.scroll * .08}px`, "--model-rotate": `${model.x * .12}deg` }} animate={reduceMotion ? undefined : { y: [0, -9, 0] }} transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}><div className="visual-orbit orbit-one"/><div className="visual-orbit orbit-two"/><div className="visual-core"><ShieldCheck size={38}/></div><div className="signal-card signal-top"><span className="signal-icon"><Globe2 size={16}/></span><div><b>Destination check</b><small>Domain · TLS · headers</small></div><Check size={16}/></div><div className="signal-card signal-bottom"><span className="signal-icon violet"><Fingerprint size={16}/></span><div><b>Evidence, in context</b><small>Confidence with every finding</small></div><span className="signal-dot"/></div><div className="visual-caption"><span className="live-pill"><i/> ANALYSIS READY</span><b>Signal before verdict.</b></div></motion.div>
    </section>
    <motion.section className="landing-stats" id="platform" initial={{ opacity: 0, y: 26 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: .35 }} transition={{ duration: reduceMotion ? 0 : .55 }}><div><b>01</b><span>Inspect destinations</span><small>Review reputation, transport security and web posture.</small></div><div><b>02</b><span>Understand messages</span><small>Surface embedded links and social engineering cues.</small></div><div><b>03</b><span>Preserve integrity</span><small>Verify report commitments with tamper-evident records.</small></div></motion.section>
    <motion.section className="landing-cta" id="approach" initial={{ opacity: 0, y: 26 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: .35 }} transition={{ duration: reduceMotion ? 0 : .55 }}><div><div className="eyebrow"><span/> BUILT FOR CLARITY</div><Heading tag="h2">Make the next click an informed one.</Heading><p>Start an assessment in the TrustLens workspace.</p></div><button className="primary-button" onClick={() => onAuth("register")}>Create workspace <ArrowUpRight size={16}/></button></motion.section>
    <footer className="landing-footer"><span>TRUSTLENS <b>·</b> DIGITAL TRUST INTELLIGENCE</span><span>DETERMINISTIC ANALYSIS <i/> AI-ASSISTED EXPLANATION</span></footer>
  </main>;
}

function Topbar({ onMenu, onHome }) {
  return <header className="topbar">
    <button className="mobile-menu icon-button" onClick={onMenu} aria-label="Open menu"><Menu size={19}/></button>
    <a className="brand" href="#home" onClick={(e)=>{e.preventDefault();onHome?.()}} aria-label="TrustLens home">
      <span className="brand-mark"><ShieldCheck size={20}/></span>
      <span>trust<span className="brand-light">lens</span><small> DIGITAL TRUST INTELLIGENCE</small></span>
    </a>
    <div className="topbar-right">
      <span className="system-status"><i /> ALL SYSTEMS OPERATIONAL</span>
      <button className="icon-button" aria-label="Notifications"><Bell size={17}/><b className="notification-dot"/></button>
      <div className="avatar">SM</div>
    </div>
  </header>;
}

function Sidebar({ active, setActive, mobileOpen, close }) {
  const nav = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "url-scanner", label: "URL intelligence", icon: ScanSearch },
    { id: "message-scanner", label: "Message analysis", icon: MessageSquareText },
    { id: "reports", label: "Threat reports", icon: Activity },
    { id: "verification", label: "On-chain verification", icon: Blocks }
  ];
  return <>
    {mobileOpen && <button className="sidebar-scrim" onClick={close} aria-label="Close navigation"/>}
    <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
      <div className="workspace-label">WORKSPACE</div>
      <nav>{nav.map(item => {
        const Icon = item.icon;
        return <button key={item.id} className={`nav-item ${active === item.id ? "selected" : ""}`} onClick={() => { setActive(item.id); close(); }}>
          <Icon size={17}/><span>{item.label}</span>{item.id === "reports" && <em>4</em>}
        </button>;
      })}</nav>
      <div className="sidebar-bottom">
        <div className="plan-card"><div className="plan-icon"><Zap size={15}/></div><strong>Threat engine</strong><span>Rule-based analysis active</span><div className="plan-progress"><i/></div><small>CORE ENGINE · v1.0</small></div>
        <button className="nav-item"><CircleHelp size={17}/><span>Documentation</span><ExternalLink size={13}/></button>
        <div className="profile-row"><div className="avatar">SM</div><div><b>Security analyst</b><small>Local workspace</small></div><ChevronDown size={15}/></div>
      </div>
    </aside>
  </>;
}

function SectionHeading({ eyebrow, title, description, right }) {
  return <div className="section-heading"><div><div className="eyebrow"><span/>{eyebrow}</div><Heading tag="h1">{title}</Heading><p>{description}</p></div>{right && <div className="heading-action">{right}</div>}</div>;
}

function Metric({ label, value, detail, icon: Icon, tone = "cyan" }) {
  return <motion.div className="metric-card glass" whileHover={{ y: -4, transition: { duration: .2 } }}>
    <div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={17}/></span></div>
    <div className="metric-value">{value}</div><div className="metric-detail">{detail}</div>
  </motion.div>;
}

function DashboardAnalysis() {
  const reduceMotion = useReducedMotion();
  const [phase, setPhase] = useState(0);
  const trend = [42, 58, 49, 71, 65, 82, 76];
  const trendPoints = trend.map((value, index) => `${24 + index * 48},${126 - value}`).join(" ");
  const nodes = [
    { id: "source", x: 42, y: 92, label: "LINK IN" },
    { id: "dns", x: 158, y: 46, label: "DNS VM" },
    { id: "tls", x: 158, y: 138, label: "TLS VM" },
    { id: "headers", x: 274, y: 46, label: "HEADERS VM" },
    { id: "reputation", x: 274, y: 138, label: "REPUTATION VM" },
    { id: "verdict", x: 390, y: 92, label: "VERDICT" }
  ];
  const edges = [[0,1],[0,2],[1,3],[2,4],[3,5],[4,5]];

  useEffect(() => {
    if (reduceMotion) return undefined;
    const timer = window.setInterval(() => setPhase(value => (value + .018) % 1), 50);
    return () => window.clearInterval(timer);
  }, [reduceMotion]);

  return <section className="analysis-section">
    <div className="analysis-header"><div><div className="eyebrow"><span/> WORKSPACE ANALYTICS</div><Heading tag="h2">Signal flow, in motion.</Heading><p>Track assessment volume and see how each link moves through the live analysis fleet.</p></div><span className="live-pill"><i/> STREAMING</span></div>
    <div className="analysis-grid">
      <div className="panel glass trend-panel"><div className="panel-heading"><div><Heading tag="h3">Assessment activity</Heading><p>Completed checks · last 7 days</p></div><div className="trend-value"><b>+18.4%</b><small>vs previous week</small></div></div><div className="trend-chart" role="img" aria-label="Assessment activity increased over the last seven days"><svg viewBox="0 0 360 150" preserveAspectRatio="none"><defs><linearGradient id="trendFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#62e5ef" stopOpacity=".24"/><stop offset="1" stopColor="#62e5ef" stopOpacity="0"/></linearGradient></defs><polygon points={`24,126 ${trendPoints} 312,126`} fill="url(#trendFill)"/><polyline points={trendPoints} fill="none" stroke="#62e5ef" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>{trend.map((value, index) => <circle key={index} cx={24 + index * 48} cy={126 - value} r="3.5" fill="#08121d" stroke="#62e5ef" strokeWidth="2"/>)}</svg><div className="chart-labels">{["MON","TUE","WED","THU","FRI","SAT","SUN"].map(day => <span key={day}>{day}</span>)}</div></div><div className="analysis-legend"><span><i className="legend-cyan"/> Assessments</span><span><i className="legend-green"/> Coverage 86.4%</span><span><i className="legend-violet"/> Threats 067</span></div></div>
      <div className="panel glass live-model"><div className="panel-heading"><div><Heading tag="h3">Live link model</Heading><p>Virtual analysis machines · current session</p></div><span className="model-status"><i/> 6 NODES</span></div><svg className="model-canvas" viewBox="0 0 432 184" role="img" aria-label="Live link analysis model showing links moving through virtual analysis machines"><g className="model-grid-lines"><path d="M0 46H432M0 92H432M0 138H432"/><path d="M72 0V184M144 0V184M216 0V184M288 0V184M360 0V184"/></g>{edges.map(([from, to], index) => { const a = nodes[from], b = nodes[to]; const progress = reduceMotion ? .5 : (phase + index * .17) % 1; return <g key={`${from}-${to}`}><line className="model-edge" x1={a.x} y1={a.y} x2={b.x} y2={b.y}/><circle className="model-packet" cx={a.x + (b.x - a.x) * progress} cy={a.y + (b.y - a.y) * progress} r="3"/></g>; })}{nodes.map((node, index) => <g key={node.id} className="model-node"><circle cx={node.x} cy={node.y} r="18"/><circle className="model-node-core" cx={node.x} cy={node.y} r="5"/><text x={node.x} y={node.y + 32} textAnchor="middle">{node.label}</text><text className="model-node-index" x={node.x} y={node.y + 3} textAnchor="middle">{String(index + 1).padStart(2, "0")}</text></g>)}</svg><div className="model-footer"><span><Activity size={13}/> Routing events: 24/min</span><span><ShieldCheck size={13}/> All workers healthy</span></div></div>
    </div>
  </section>;
}

function ScanPanel({ onScan, loading }) {
  const [url, setUrl] = useState("");
  const submit = (e) => { e.preventDefault(); onScan(url); };
  return <div className="scan-panel glass">
    <div className="scan-panel-head"><div className="scan-symbol"><Radar size={21}/></div><div><Heading tag="h3">Inspect a destination</Heading><p>Run a multi-layer security assessment against a URL.</p></div><span className="live-pill"><i/> LIVE ENGINE</span></div>
    <form className="scan-form" onSubmit={submit}>
      <div className="url-input-wrap"><Globe2 size={18}/><input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" type="text" aria-label="URL to scan" required/><span className="input-shortcut">URL</span></div>
      <button className="primary-button" disabled={loading || !url.trim()}>{loading ? <><span className="spinner"/> ANALYSING</> : <><ScanSearch size={16}/> Scan URL <ArrowUpRight size={15}/></>}</button>
    </form>
    <div className="scan-foot"><span><LockKeyhole size={13}/> Safe-fetch controls required on backend</span><span>HTTP · DNS · TLS · Reputation</span></div>
  </div>;
}

function Findings({ report }) {
  if (!report) return <div className="empty-state glass"><div className="empty-icon"><Fingerprint size={24}/></div><Heading tag="h3">Evidence will appear here</Heading><p>Run a URL assessment to inspect findings, confidence and source evidence.</p></div>;
  return <div className="findings-list">{(report.findings || []).map((f, i) => <motion.div className="finding glass" key={f.id || i} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * .07 }}>
    <div className={`finding-severity ${String(f.severity).toLowerCase()}`}/><div className="finding-main"><div className="finding-title">{f.check || "Security check"}<span className={`severity-tag ${String(f.severity).toLowerCase()}`}>{f.severity}</span></div><p>{f.evidence}</p><small>{f.source || "Analysis engine"} · Confidence {Math.round((f.confidence ?? 0) * 100)}%</small></div><ChevronDown size={16} className="finding-chevron"/>
  </motion.div>)}</div>;
}

function ReportCard({ report, onRegister, registering, onVerify }) {
  if (!report) return null;
  const score = Number(report.risk_score ?? 0);
  const label = report.classification || "Inconclusive";
  return <motion.div className="report-card glass" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }}>
    <div className="report-top"><div><div className="eyebrow"><span/> LATEST ASSESSMENT</div><Heading tag="h3">{report.target}</Heading><small>REPORT ID · {report.id || "Pending"}</small></div><span className={`classification ${label.toLowerCase().replaceAll(" ", "-")}`}>{label}</span></div>
    <div className="risk-row"><div className="risk-number">{score}<small>/100</small></div><div className="risk-copy"><b>Risk score</b><span>Rule-based classification · Evidence-led assessment</span><div className="risk-track"><i style={{ width: `${Math.max(0, Math.min(100, score))}%` }}/></div></div></div>
    <div className="report-stats"><div><span>Coverage</span><b>{report.coverage ?? 0}%</b></div><div><span>Findings</span><b>{report.findings?.length ?? 0}</b></div><div><span>Unavailable checks</span><b>{report.unavailable_checks?.length ?? 0}</b></div></div>
    {report.unavailable_checks?.length > 0 && <div className="notice"><CircleHelp size={14}/><span>Some checks could not run: {report.unavailable_checks.join(", ")}</span></div>}
    <div className="report-actions"><button className="secondary-button" onClick={onVerify}><BadgeCheck size={15}/> Verify integrity</button><button className="primary-button" onClick={onRegister} disabled={registering}>{registering ? <span className="spinner"/> : <Blocks size={15}/>} Register on-chain</button></div>
  </motion.div>;
}

function Overview({ report, onScan, loading, onRegister, registering, onVerify }) {
  return <div className="page-content">
    <SectionHeading eyebrow="SECURITY OPERATIONS / OVERVIEW" title="Digital trust, made visible." description="Assess web destinations, inspect evidence and preserve report integrity." right={<span className="date-chip"><Clock3 size={14}/> LIVE SESSION</span>}/>
    <div className="metrics-grid">
      <Metric label="ASSESSMENTS TODAY" value="1,284" detail={<><span className="up">↑ 12.8%</span> vs previous period</>} icon={ScanSearch}/>
      <Metric label="THREATS IDENTIFIED" value="067" detail="Across monitored indicators" icon={ShieldAlert} tone="violet"/>
      <Metric label="INTELLIGENCE COVERAGE" value="86.4%" detail="Checks successfully executed" icon={Activity} tone="green"/>
      <Metric label="CHAIN INTEGRITY" value="100%" detail="Latest local verification status" icon={Link2}/>
    </div>
    <DashboardAnalysis/>
    <ScanPanel onScan={onScan} loading={loading}/>
    {report && <div className="report-grid"><ReportCard report={report} onRegister={onRegister} registering={registering} onVerify={onVerify}/><div><div className="subsection-head"><div><Heading tag="h3">Evidence & findings</Heading><p>Signals contributing to this assessment</p></div><span className="count-chip">{report.findings?.length || 0} SIGNALS</span></div><Findings report={report}/></div></div>}
    {!report && <div className="lower-grid"><div className="panel glass"><div className="panel-heading"><div><Heading tag="h3">Analysis pipeline</Heading><p>Independent checks build an evidence-led result.</p></div><span className="live-pill"><i/> READY</span></div><div className="pipeline">{[{n:"01",t:"Normalisation",d:"Canonical URL and domain parsing",s:"ready"},{n:"02",t:"Network & reputation",d:"DNS, TLS and threat intelligence",s:"queued"},{n:"03",t:"Security posture",d:"Headers and browser-facing controls",s:"queued"},{n:"04",t:"Risk assessment",d:"Deterministic scoring and coverage",s:"queued"}].map(x=><div className="pipeline-step" key={x.n}><span>{x.n}</span><div><b>{x.t}</b><small>{x.d}</small></div><i className={x.s}/></div>)}</div></div><div className="panel glass trust-note"><div className="trust-art"><ShieldCheck size={34}/><div className="orbit orbit-a"/><div className="orbit orbit-b"/></div><div className="eyebrow">OUR TRUST MODEL</div><Heading tag="h3">Evidence over assumptions.</Heading><p>Risk classification is determined by deterministic checks. AI can explain findings, but it never decides whether a destination is malicious.</p><div className="trust-foot"><LockKeyhole size={14}/> Integrity does not equal truth.</div></div></div>}
  </div>;
}

function MessageScanner({ onScan, loading }) {
  const [message, setMessage] = useState("");
  return <div className="page-content"><SectionHeading eyebrow="SECURITY OPERATIONS / MESSAGE ANALYSIS" title="Read between the lines." description="Inspect suspicious messages for social-engineering tactics and embedded indicators."/>
    <div className="message-layout"><div className="panel glass message-input-panel"><div className="panel-heading"><div><Heading tag="h3">Message inspection</Heading><p>Paste message text for structured analysis.</p></div><MessageSquareText size={19}/></div><textarea value={message} onChange={e=>setMessage(e.target.value)} placeholder="Paste an email, SMS or chat message here…" rows={10}/><div className="message-tools"><span>Text is sent to your configured backend only.</span><button className="primary-button" disabled={!message.trim() || loading} onClick={()=>onScan(message)}>{loading ? <span className="spinner"/> : <Sparkles size={15}/>} Analyse message</button></div></div><div className="panel glass message-guide"><div className="eyebrow"><span/> DETECTION SCOPE</div><Heading tag="h3">Signals we look for</Heading>{[{i:Link2,t:"Embedded links",d:"Extracted URLs and domain indicators"},{i:Zap,t:"Urgency & pressure",d:"Artificial deadlines and coercive language"},{i:Fingerprint,t:"Identity impersonation",d:"Brand, authority and account claims"},{i:ShieldAlert,t:"Payment manipulation",d:"UPI, refund and credential requests"}].map(({i:Icon,t,d})=><div className="guide-item" key={t}><Icon size={17}/><div><b>{t}</b><small>{d}</small></div></div>)}<div className="notice"><CircleHelp size={14}/> Urgent language alone is not a fraud verdict.</div></div></div></div>;
}

function Verification({ report, onVerify, verifyState }) {
  return <div className="page-content"><SectionHeading eyebrow="TRUST LAYER / BLOCKCHAIN" title="Integrity you can verify." description="Anchor report commitments on-chain. Raw URLs and message content stay off-chain."/>
    <div className="verification-hero glass"><div className="verification-icon"><Blocks size={26}/></div><div><div className="eyebrow">TAMPER-EVIDENT RECORDS</div><Heading tag="h2">Proof of integrity, not proof of truth.</Heading><p>The blockchain preserves a timestamped commitment to a report. Verification checks whether the current report still matches the committed content.</p></div></div>
    <div className="verification-grid"><div className="panel glass"><Heading tag="h3">Report commitment</Heading><p className="muted">Choose a report to verify its stored commitment.</p><div className="commitment-box"><span>SELECTED REPORT</span><b>{report?.id || "No report selected"}</b><small>{report?.target || "Run a scan to generate a report"}</small></div><button className="primary-button full-button" disabled={!report} onClick={onVerify}><BadgeCheck size={16}/> Verify report integrity</button>{verifyState && <div className={`verification-result ${verifyState.ok ? "success" : "error"}`}><span>{verifyState.ok ? <Check size={16}/> : <ShieldAlert size={16}/>}</span><div><b>{verifyState.title}</b><small>{verifyState.detail}</small></div></div>}</div>
      <div className="panel glass"><Heading tag="h3">How verification works</Heading><div className="verify-steps">{["Canonicalise report JSON (sorted keys)","Recompute the Keccak-256 commitment","Read the anchored commitment from chain","Compare hashes and report the result"].map((s,i)=><div key={s}><span>{String(i+1).padStart(2,"0")}</span>{s}</div>)}</div><div className="notice"><LockKeyhole size={14}/> Never store raw URLs or personal message content on-chain.</div></div></div></div>;
}

function Reports({ report }) {
  return <div className="page-content"><SectionHeading eyebrow="SECURITY OPERATIONS / REPORTS" title="Assessment history." description="A workspace for reviewing generated security assessments."/>
    <div className="panel glass"><div className="panel-heading"><div><Heading tag="h3">Recent reports</Heading><p>Reports created in this browser session.</p></div><span className="count-chip">{report ? "1 REPORT" : "0 REPORTS"}</span></div>{report ? <div className="history-row"><div className="history-icon"><Globe2 size={17}/></div><div className="history-main"><b>{report.target}</b><small>{report.id} · {new Date(report.timestamp || Date.now()).toLocaleString()}</small></div><span className={`classification ${String(report.classification).toLowerCase()}`}>{report.classification}</span></div> : <div className="empty-state compact"><Heading tag="h3">No reports yet</Heading><p>Run your first URL scan to create an assessment.</p></div>}</div>
  </div>;
}

function LandingPreviewPage({ onOpenDashboard }) {
  const [demoUrl, setDemoUrl] = useState("");
  const submit = (event) => { event.preventDefault(); onOpenDashboard(demoUrl.trim()); };
  return <div className="landing-shell">
    <BackgroundFX/><CursorFX/>
    <header className="landing-nav">
      <a className="brand" href="#top" aria-label="TrustLens home"><span className="brand-mark"><ShieldCheck size={20}/></span><span>trust<span className="brand-light">lens</span><small> DIGITAL TRUST INTELLIGENCE</small></span></a>
      <nav className="landing-links" aria-label="Primary navigation"><a href="#how-it-works">How it works</a><a href="#signals">Signals</a><a href="#security">Security</a></nav>
      <button className="nav-cta" onClick={() => onOpenDashboard()}><LayoutDashboard size={15}/> Open dashboard <ArrowUpRight size={14}/></button>
    </header>
    <main id="top">
      <section className="landing-hero">
        <div className="hero-copy">
          <div className="eyebrow landing-eyebrow"><span/> DIGITAL TRUST INTELLIGENCE <i>●</i> LIVE ENGINE</div>
          <Heading tag="h1">Know what you’re really trusting.</Heading>
          <p className="hero-lede">TrustLens turns suspicious links and messages into clear, evidence-led decisions—before your team clicks, pays, or shares.</p>
          <form className="hero-scan" onSubmit={submit}><label htmlFor="hero-url">Start with a URL</label><div className="hero-input-row"><div className="hero-input"><Globe2 size={17}/><input id="hero-url" value={demoUrl} onChange={e=>setDemoUrl(e.target.value)} placeholder="https://example.com"/><span>URL</span></div><button className="primary-button" type="submit"><ScanSearch size={16}/> Inspect now <ArrowUpRight size={15}/></button></div><small><LockKeyhole size={12}/> Demo mode is on · no data leaves your browser</small></form>
          <div className="hero-proof"><span><ShieldCheck size={15}/> Evidence first</span><span><Zap size={15}/> Deterministic checks</span><span><Blocks size={15}/> Tamper-evident reports</span></div>
        </div>
        <div className="hero-visual" aria-label="TrustLens security dashboard preview"><div className="hero-orbit orbit-one"/><div className="hero-orbit orbit-two"/><div className="preview-window glass"><div className="preview-top"><span className="window-dots"><i/><i/><i/></span><span>TRUSTLENS / LIVE ASSESSMENT</span><span className="preview-live"><i/> LIVE</span></div><div className="preview-body"><div className="preview-sidebar"><span className="mini-logo"><ShieldCheck size={13}/></span><i/><i/><i/><i/><b/></div><div className="preview-main"><div className="mini-heading"><span>SECURITY OPERATIONS</span><b>Overview</b></div><div className="mini-metrics"><span/><span/><span/></div><div className="mini-scan"><div><Radar size={17}/><b>Inspect a destination</b></div><div className="mini-input">https://checkout-verify.io <small>SCAN</small></div><i/></div><div className="mini-grid"><div className="mini-report"><span>RISK SCORE</span><strong>68<small>/100</small></strong><i/></div><div className="mini-findings"><span>FINDINGS</span><b><i/> Domain reputation</b><b><i/> HTTP security headers</b><b><i/> Transport security</b></div></div></div></div></div><div className="floating-chip chip-risk"><ShieldAlert size={15}/><span><b>68</b> risk score</span></div><div className="floating-chip chip-safe"><BadgeCheck size={15}/><span>Evidence captured</span></div></div>
      </section>
      <section className="landing-stats" id="signals"><div><strong>04</strong><span>independent signal layers</span></div><div><strong>86%</strong><span>coverage in demo assessment</span></div><div><strong>100%</strong><span>report integrity status</span></div><div><strong>0</strong><span>secrets stored in frontend</span></div></section>
      <section className="landing-section" id="how-it-works"><div className="section-intro"><div className="eyebrow"><span/> THE TRUSTLENS METHOD</div><Heading tag="h2">Clarity at every layer of trust.</Heading><p>Security decisions feel less like guesswork when every conclusion has a visible trail.</p></div><div className="feature-grid"><article className="feature-card glass"><div className="feature-icon"><ScanSearch size={20}/></div><span>01 / DISCOVER</span><Heading tag="h3">Scan the destination</Heading><p>Normalize the URL, inspect DNS, TLS, headers, and reputation signals in one controlled pass.</p><a href="#top" onClick={(e)=>{e.preventDefault();onOpenDashboard()}}>Run an assessment <ArrowUpRight size={14}/></a></article><article className="feature-card glass"><div className="feature-icon violet"><Fingerprint size={20}/></div><span>02 / EXPLAIN</span><Heading tag="h3">See the evidence</Heading><p>Separate observed facts from assumptions with confidence, source, and unavailable-check context.</p><a href="#signals">Explore the signals <ArrowUpRight size={14}/></a></article><article className="feature-card glass"><div className="feature-icon green"><Blocks size={20}/></div><span>03 / PRESERVE</span><Heading tag="h3">Verify the report</Heading><p>Anchor a commitment to your report and confirm that the record has not changed over time.</p><a href="#security">Protect integrity <ArrowUpRight size={14}/></a></article></div></section>
      <section className="landing-quote" id="security"><div className="quote-mark">“</div><blockquote>Integrity does not equal truth.<br/><em>It gives truth a trail.</em></blockquote><div className="quote-rule"/><span>BUILT FOR SECURITY TEAMS WHO NEED TO SHOW THEIR WORK</span></section>
    </main>
    <footer className="landing-footer"><span>TRUSTLENS <b>·</b> DIGITAL TRUST INTELLIGENCE</span><button onClick={() => onOpenDashboard()}>Enter workspace <ArrowUpRight size={14}/></button><span>DETERMINISTIC ANALYSIS <i/></span></footer>
  </div>;
}

export default function App() {
  const [view, setView] = useState(() => window.location.hash === "#dashboard" ? "dashboard" : window.location.hash === "#auth" ? "auth" : "landing");
  const [authMode, setAuthMode] = useState("signin");
  const [active, setActive] = useState("overview");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [verifyState, setVerifyState] = useState(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    document.documentElement.style.scrollBehavior = reduceMotion ? "auto" : "smooth";
    return () => { document.documentElement.style.scrollBehavior = "auto"; };
  }, [reduceMotion]);

  useEffect(() => {
    const sync = () => setView(window.location.hash === "#dashboard" ? "dashboard" : window.location.hash === "#auth" ? "auth" : "landing");
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  const enterDashboard = () => { window.location.hash = "dashboard"; setView("dashboard"); };
  const openAuth = (mode = "signin") => { setAuthMode(mode); window.location.hash = "auth"; setView("auth"); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const goHome = () => { history.replaceState(null, "", window.location.pathname + window.location.search); setView("landing"); };

  async function scan(input, kind = "url") {
    setLoading(true); setVerifyState(null);
    try {
      let result;
      if (DEMO) {
        await new Promise(r => setTimeout(r, 1300));
        result = kind === "url" ? demoReport(input) : {
          ...demoReport("Message analysis"), id: "MSG-" + Math.random().toString(36).slice(2,7).toUpperCase(),
          target: "Message analysis", classification: "Needs review",
          findings: [{ id:"M-01", check:"Message tactics", severity:"medium", confidence:.88, evidence:"Demo analysis only. Connect the message-analysis endpoint for actual extraction and classification.", source:"Local demo" }]
        };
      } else {
        const endpoint = kind === "url" ? "/api/scan/url" : "/api/scan/message";
        const key = kind === "url" ? "url" : "message";
        const res = await fetch(`${API}${endpoint}`, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({[key]:input}) });
        if (!res.ok) throw new Error(`Analysis failed (${res.status})`);
        result = await res.json();
      }
      setReport(result); setActive("overview");
    } catch (e) {
      alert(`${e.message}. Check that the FastAPI backend is running and VITE_API_BASE_URL is correct.`);
    } finally { setLoading(false); }
  }

  async function register() {
    if (!report) return;
    setRegistering(true);
    try {
      if (DEMO) await new Promise(r=>setTimeout(r,900));
      else {
        const res = await fetch(`${API}/api/reports/${encodeURIComponent(report.id)}/register`, {method:"POST"});
        if (!res.ok) throw new Error(`Registration failed (${res.status})`);
        const data = await res.json(); setReport({...report, blockchain:data});
      }
      alert(DEMO ? "Demo only: connect the Hardhat contract integration to submit a real on-chain commitment." : "Report registration request completed.");
    } catch(e) { alert(e.message); } finally { setRegistering(false); }
  }

  async function verify() {
    if (!report) return;
    try {
      if (DEMO) {
        await new Promise(r=>setTimeout(r,700));
        setVerifyState({ok:false,title:"Demo verification unavailable",detail:"Connect the report hash and on-chain verification endpoint to verify a real commitment."});
      } else {
        const res = await fetch(`${API}/api/reports/${encodeURIComponent(report.id)}/verify`);
        if (!res.ok) throw new Error(`Verification failed (${res.status})`);
        const data = await res.json();
        setVerifyState({ok:!!data.valid,title:data.valid?"Integrity verified":"Integrity mismatch",detail:data.message || "The recomputed report commitment was compared with the on-chain value."});
      }
    } catch(e) { setVerifyState({ok:false,title:"Verification error",detail:e.message}); }
  }

  const page = active === "message-scanner"
    ? <MessageScanner onScan={v=>scan(v,"message")} loading={loading}/>
    : active === "verification"
    ? <Verification report={report} onVerify={verify} verifyState={verifyState}/>
    : active === "reports"
    ? <Reports report={report}/>
    : active === "url-scanner"
    ? <div className="page-content"><SectionHeading eyebrow="SECURITY OPERATIONS / URL INTELLIGENCE" title="Investigate a URL." description="Inspect a destination with layered, evidence-backed security checks."/><ScanPanel onScan={v=>scan(v)} loading={loading}/>{report && <div className="report-grid"><ReportCard report={report} onRegister={register} registering={registering} onVerify={verify}/><div><div className="subsection-head"><div><Heading tag="h3">Evidence & findings</Heading><p>Signals contributing to this assessment</p></div></div><Findings report={report}/></div></div>}</div>
    : <Overview report={report} onScan={v=>scan(v)} loading={loading} onRegister={register} registering={registering} onVerify={verify}/>;

  if (view === "landing") return <div className="app-shell landing-shell"><BackgroundFX/><CursorFX/><LandingPage onEnter={enterDashboard} onAuth={openAuth}/></div>;
  if (view === "auth") return <div className="app-shell"><AuthPage mode={authMode} onModeChange={setAuthMode} onBack={goHome} onSuccess={enterDashboard}/></div>;
  return <div className="app-shell"><BackgroundFX/><CursorFX/><Topbar onMenu={()=>setMobileOpen(true)} onHome={goHome}/><div className="app-body"><Sidebar active={active} setActive={setActive} mobileOpen={mobileOpen} close={()=>setMobileOpen(false)}/><main className="main-area"><AnimatePresence mode="wait"><motion.div key={active} initial={{opacity:0,y:reduceMotion?0:10}} animate={{opacity:1,y:0}} exit={{opacity:0,y:reduceMotion?0:-8}} transition={{duration:reduceMotion?0:.28}}>{page}</motion.div></AnimatePresence><footer className="footer"><span>TRUSTLENS <b>·</b> DIGITAL TRUST INTELLIGENCE</span><span>DETERMINISTIC ANALYSIS <i/> AI-ASSISTED EXPLANATION</span></footer></main></div></div>;
}
