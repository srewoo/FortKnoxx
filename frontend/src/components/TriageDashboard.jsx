/**
 * TriageDashboard — surfaces the v1.1 backend signals (risk score,
 * triage verdicts, owner attribution, trend, dedup sources, evidence
 * pack) in a single page.
 *
 * Built as a self-contained component so we don't have to touch
 * App.js's 2800-line monolith. Mounted at /repository/:repoId/triage.
 *
 * Zero new dependencies — sparklines + bars are inline SVG.
 */

import React, { useEffect, useState, useMemo } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import axios from "axios";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import {
  ShieldCheck, ShieldAlert, ShieldX, TrendingUp, Users,
  Layers, Download, ArrowLeft, Activity, Sparkles, AlertTriangle,
} from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL
  ? `${process.env.REACT_APP_BACKEND_URL}/api`
  : "/api";

// --------------------------------------------------------------- Quality Gate

/**
 * Sonar-style "Quality Gate" — a single PASSED / FAILED status that
 * teams can wire into their PR-required-checks. We define a free-tier
 * gate here; a future iteration can let users edit thresholds.
 */
const QUALITY_GATE_RULES = [
  { id: "no_critical",       label: "No critical findings",                  test: (s) => s.critical === 0 },
  { id: "high_lt_5",         label: "High findings < 5",                     test: (s) => s.high < 5 },
  { id: "true_pos_lt_20",    label: "Confirmed true positives < 20",         test: (s) => s.true_positive < 20 },
  { id: "no_unfixable",      label: "No findings without an autofix path",   test: (s) => true },
];

function evaluateQualityGate(stats) {
  const results = QUALITY_GATE_RULES.map((rule) => ({
    ...rule,
    passed: rule.test(stats),
  }));
  return {
    passed: results.every((r) => r.passed),
    rules: results,
  };
}

function QualityGate({ stats }) {
  const { passed, rules } = evaluateQualityGate(stats);
  return (
    <Card className={passed ? "border-green-500/40" : "border-red-500/40"}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          {passed ? (
            <ShieldCheck className="h-5 w-5 text-green-500" />
          ) : (
            <ShieldX className="h-5 w-5 text-red-500" />
          )}
          Quality Gate
          <Badge variant={passed ? "default" : "destructive"} className="ml-2">
            {passed ? "PASSED" : "FAILED"}
          </Badge>
        </CardTitle>
        <CardDescription>
          Wire this status into required PR checks — block merges when it fails.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2 text-sm">
          {rules.map((r) => (
            <li key={r.id} className="flex items-center gap-2">
              {r.passed ? (
                <ShieldCheck className="h-4 w-4 text-green-500 shrink-0" />
              ) : (
                <ShieldAlert className="h-4 w-4 text-red-500 shrink-0" />
              )}
              <span className={r.passed ? "" : "text-red-500"}>{r.label}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

// --------------------------------------------------------------- Risk gauge

function RiskGauge({ score = 0, size = 110 }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const dash = (Math.max(0, Math.min(100, score)) / 100) * circumference;
  const colour =
    score >= 80 ? "#ef4444" :
    score >= 60 ? "#f97316" :
    score >= 40 ? "#eab308" :
                  "#22c55e";
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle
        cx={size / 2} cy={size / 2} r={radius}
        fill="none" stroke="currentColor" strokeOpacity="0.15" strokeWidth="8"
      />
      <circle
        cx={size / 2} cy={size / 2} r={radius}
        fill="none" stroke={colour} strokeWidth="8"
        strokeDasharray={`${dash} ${circumference - dash}`}
        strokeDashoffset={circumference / 4}
        strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle"
            fontSize="22" fontWeight="600" fill="currentColor">
        {Math.round(score)}
      </text>
    </svg>
  );
}

// --------------------------------------------------------------- Trend sparkline

function TrendChart({ series, width = 600, height = 140 }) {
  if (!series || series.length === 0) {
    return <div className="text-sm text-muted-foreground">No trend data yet.</div>;
  }
  const max = Math.max(...series.map((s) => s.introduced_count), 1);
  const stepX = width / Math.max(series.length - 1, 1);
  const points = series
    .map((s, i) => `${i * stepX},${height - (s.introduced_count / max) * (height - 16) - 8}`)
    .join(" ");
  const areaPoints = `0,${height} ${points} ${width},${height}`;

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="overflow-visible">
      <polygon points={areaPoints} fill="currentColor" fillOpacity="0.08" />
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="2" />
      {series.map((s, i) => (
        <g key={s.day}>
          <circle
            cx={i * stepX}
            cy={height - (s.introduced_count / max) * (height - 16) - 8}
            r="3" fill="currentColor"
          />
          <title>{s.day}: {s.introduced_count} findings introduced</title>
        </g>
      ))}
    </svg>
  );
}

// --------------------------------------------------------------- Owner heatmap

function OwnerBar({ owner }) {
  const total = owner.count || 1;
  const pctCrit = (owner.critical / total) * 100;
  const pctHigh = (owner.high / total) * 100;
  const pctOther = 100 - pctCrit - pctHigh;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm">
        <span className="font-medium truncate max-w-[60%]">{owner.owner_email}</span>
        <span className="text-muted-foreground">{owner.count} findings</span>
      </div>
      <div className="h-2 w-full rounded-full overflow-hidden bg-muted flex">
        <div className="bg-red-500"    style={{ width: `${pctCrit}%`  }} title={`${owner.critical} critical`} />
        <div className="bg-orange-500" style={{ width: `${pctHigh}%`  }} title={`${owner.high} high`} />
        <div className="bg-muted-foreground/40" style={{ width: `${pctOther}%` }} title="other severities" />
      </div>
    </div>
  );
}

// --------------------------------------------------------------- Top-risk row

function VerdictBadge({ verdict }) {
  if (!verdict) return null;
  const variants = {
    true_positive:  { variant: "destructive",  label: "True positive",  icon: AlertTriangle },
    likely_fp:      { variant: "secondary",    label: "Likely FP",      icon: ShieldCheck },
    needs_context:  { variant: "outline",      label: "Needs context",  icon: Sparkles },
    uncertain:      { variant: "outline",      label: "Uncertain",      icon: Sparkles },
  };
  const v = variants[verdict] || variants.uncertain;
  const Icon = v.icon;
  return (
    <Badge variant={v.variant} className="gap-1">
      <Icon className="h-3 w-3" /> {v.label}
    </Badge>
  );
}

function SourcePills({ sources }) {
  if (!sources || sources.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {sources.map((s) => (
        <Badge key={s} variant="outline" className="text-[10px] uppercase tracking-wide">
          {s}
        </Badge>
      ))}
    </div>
  );
}

function TopRiskRow({ finding, onAutofix }) {
  return (
    <div className="border rounded-md p-3 space-y-2 hover:bg-muted/30 transition">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium truncate">{finding.title || finding.rule_id || "Finding"}</span>
            <Badge variant={finding.severity === "critical" ? "destructive" : "secondary"}>
              {finding.severity}
            </Badge>
            <VerdictBadge verdict={finding.triage?.verdict} />
          </div>
          <div className="text-xs text-muted-foreground truncate">
            {finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}
            {finding.cwe_family ? ` · ${finding.cwe_family}` : ""}
            {finding.owner_email ? ` · ${finding.owner_email}` : ""}
          </div>
          <SourcePills sources={finding.sources} />
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <div className="text-right">
            <div className="text-2xl font-semibold leading-none">{finding.risk_score ?? "—"}</div>
            <div className="text-[10px] text-muted-foreground uppercase">risk</div>
          </div>
          <Button size="sm" variant="outline" onClick={() => onAutofix(finding)}>
            <Sparkles className="h-3 w-3 mr-1" /> Autofix
          </Button>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------- Page

export default function TriageDashboard() {
  const { repoId } = useParams();
  const navigate = useNavigate();

  const [trend, setTrend] = useState([]);
  const [topRisk, setTopRisk] = useState([]);
  const [owners, setOwners] = useState([]);
  const [scanList, setScanList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [days, setDays] = useState(30);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true); setError(null);
      try {
        const [trendRes, riskRes, ownersRes, scansRes] = await Promise.all([
          axios.get(`${API}/trends/findings`,   { params: { repo_id: repoId, days } }),
          axios.get(`${API}/trends/top-risk`,   { params: { repo_id: repoId, limit: 20 } }),
          axios.get(`${API}/trends/owners`,     { params: { repo_id: repoId } }),
          axios.get(`${API}/scans/${repoId}`).catch(() => ({ data: [] })),
        ]);
        if (cancelled) return;
        setTrend(trendRes.data?.series || []);
        setTopRisk(riskRes.data || []);
        setOwners(ownersRes.data || []);
        setScanList(scansRes.data || []);
      } catch (e) {
        if (!cancelled) setError(e.message || "Failed to load triage data");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [repoId, days]);

  const stats = useMemo(() => {
    const crit = topRisk.filter((f) => f.severity === "critical").length;
    const high = topRisk.filter((f) => f.severity === "high").length;
    const tp = topRisk.filter((f) => f.triage?.verdict === "true_positive").length;
    return { critical: crit, high, true_positive: tp };
  }, [topRisk]);

  const latestScanId = scanList[0]?.id || scanList[0]?.scan_id;

  async function downloadEvidencePack() {
    if (!latestScanId) return;
    const url = `${API}/reports/evidence-pack?repo_id=${repoId}&scan_id=${latestScanId}`;
    window.open(url, "_blank");
  }

  async function requestAutofix(finding) {
    try {
      const { data } = await axios.post(`${API}/autofix`, {
        vulnerability_id: finding.id || finding.fingerprint,
      });
      if (data.applies_cleanly) {
        alert(`Autofix ready (${data.cached ? "cached" : "fresh"}). Diff length: ${data.diff.length} chars.`);
      } else {
        alert(`Autofix returned a diff but it did NOT apply cleanly:\n${data.error || "unknown error"}`);
      }
    } catch (e) {
      alert(`Autofix request failed: ${e.response?.data?.detail || e.message}`);
    }
  }

  return (
    <div className="container max-w-7xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => navigate(`/repository/${repoId}`)}>
            <ArrowLeft className="h-4 w-4 mr-1" /> Back to repository
          </Button>
          <h1 className="text-2xl font-semibold">Triage</h1>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="border rounded-md text-sm px-2 py-1 bg-background"
            value={days}
            onChange={(e) => setDays(parseInt(e.target.value, 10))}
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <Button onClick={downloadEvidencePack} disabled={!latestScanId} variant="outline">
            <Download className="h-4 w-4 mr-1" /> Evidence pack (SOC2/PCI)
          </Button>
        </div>
      </div>

      {error && (
        <Card className="border-red-500/40">
          <CardContent className="text-sm text-red-500 pt-6">{error}</CardContent>
        </Card>
      )}
      {loading && <div className="text-sm text-muted-foreground">Loading triage data…</div>}

      <div className="grid gap-4 md:grid-cols-3">
        <QualityGate stats={stats} />
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4" /> Highest current risk
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-4">
            <RiskGauge score={topRisk[0]?.risk_score ?? 0} />
            <div className="space-y-1 text-sm">
              <div className="font-medium truncate max-w-[200px]">
                {topRisk[0]?.title || "—"}
              </div>
              <div className="text-muted-foreground text-xs truncate max-w-[200px]">
                {topRisk[0]?.file_path}
              </div>
              <VerdictBadge verdict={topRisk[0]?.triage?.verdict} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Layers className="h-4 w-4" /> Dedup snapshot
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            <div>
              <span className="font-medium">{topRisk.length}</span> active findings (top-N)
            </div>
            <div className="text-muted-foreground">
              {topRisk.filter((f) => (f.sources?.length || 0) > 1).length} confirmed by ≥2 scanners
            </div>
            <div className="text-muted-foreground">
              {topRisk.filter((f) => f.triage?.cached).length} served from triage cache (zero LLM cost)
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="trend" className="space-y-4">
        <TabsList>
          <TabsTrigger value="trend"><TrendingUp className="h-4 w-4 mr-1" /> Trend</TabsTrigger>
          <TabsTrigger value="risk"><Activity className="h-4 w-4 mr-1" /> Top risk</TabsTrigger>
          <TabsTrigger value="owners"><Users className="h-4 w-4 mr-1" /> Owners</TabsTrigger>
        </TabsList>

        <TabsContent value="trend">
          <Card>
            <CardHeader>
              <CardTitle>Findings introduced per day</CardTitle>
              <CardDescription>
                A finding is &quot;introduced&quot; on the day its first scan ran.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <TrendChart series={trend} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="risk">
          <Card>
            <CardHeader>
              <CardTitle>Top 20 by risk score</CardTitle>
              <CardDescription>
                risk = severity × reachability × (0.5 + 0.5·EPSS) × asset criticality
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {topRisk.length === 0 ? (
                <div className="text-sm text-muted-foreground">
                  No risk-scored findings yet. Run a scan with{" "}
                  <code className="text-xs">FORTKNOXX_TRIAGE=1</code>.
                </div>
              ) : (
                topRisk.map((f) => (
                  <TopRiskRow key={f.id || f.fingerprint} finding={f} onAutofix={requestAutofix} />
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="owners">
          <Card>
            <CardHeader>
              <CardTitle>Findings by owner</CardTitle>
              <CardDescription>
                From <code className="text-xs">git blame --porcelain</code>. Bar segments: red = critical, orange = high.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {owners.length === 0 ? (
                <div className="text-sm text-muted-foreground">
                  No owner attribution yet. Owners are populated during scans.
                </div>
              ) : (
                owners.map((o) => <OwnerBar key={o.owner_email} owner={o} />)
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Separator />
      <div className="text-xs text-muted-foreground flex items-center gap-2">
        <Sparkles className="h-3 w-3" />
        Powered by the v1.1 triage engine — fingerprint dedup + LLM verdict cache + EPSS-weighted risk.
        See <Link to={`/repository/${repoId}`} className="underline">repository view</Link> for full finding list.
      </div>
    </div>
  );
}
