/**
 * CodeReviewView — Sonar-style file viewer with inline finding
 * annotations + hotspot review workflow.
 *
 * Sonar's killer dev-loop UX is "open the file, see the findings
 * annotated next to the lines, mark each one as confirmed / safe /
 * fixed". This component delivers that on top of the v1.1 backend.
 *
 * Mounted at /repository/:repoId/file?path=<encoded path>
 */

import React, { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import axios from "axios";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  ArrowLeft, ShieldAlert, ShieldCheck, AlertTriangle, FileCode2,
  Sparkles, Layers, Eye, Wand2,
} from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL
  ? `${process.env.REACT_APP_BACKEND_URL}/api`
  : "/api";

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEVERITY_COLOUR = {
  critical: "bg-red-500/15 border-l-red-500 text-red-600",
  high:     "bg-orange-500/15 border-l-orange-500 text-orange-600",
  medium:   "bg-yellow-500/15 border-l-yellow-500 text-yellow-700",
  low:      "bg-blue-500/15 border-l-blue-500 text-blue-600",
  info:     "bg-muted border-l-muted-foreground text-muted-foreground",
};

// ---------------------------------------------------------------- header

function FileHeader({ filePath, findings, qualityScore, onBack }) {
  const counts = useMemo(() => {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => { out[f.severity] = (out[f.severity] || 0) + 1; });
    return out;
  }, [findings]);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 min-w-0">
            <Button variant="ghost" size="sm" onClick={onBack}>
              <ArrowLeft className="h-4 w-4 mr-1" /> Back
            </Button>
            <FileCode2 className="h-5 w-5 text-muted-foreground shrink-0" />
            <div className="min-w-0">
              <CardTitle className="truncate">{filePath}</CardTitle>
              <CardDescription>
                {findings.length} finding{findings.length === 1 ? "" : "s"} in this file
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {Object.entries(counts).filter(([, n]) => n > 0).map(([sev, n]) => (
              <Badge
                key={sev}
                variant={sev === "critical" || sev === "high" ? "destructive" : "secondary"}
              >
                {n} {sev}
              </Badge>
            ))}
            <FileQualityScore score={qualityScore} />
          </div>
        </div>
      </CardHeader>
    </Card>
  );
}

function FileQualityScore({ score }) {
  const grade =
    score >= 90 ? { letter: "A", colour: "bg-green-500" } :
    score >= 75 ? { letter: "B", colour: "bg-lime-500" } :
    score >= 60 ? { letter: "C", colour: "bg-yellow-500" } :
    score >= 40 ? { letter: "D", colour: "bg-orange-500" } :
                  { letter: "E", colour: "bg-red-500" };
  return (
    <div className="flex items-center gap-2">
      <div className={`h-8 w-8 rounded-md flex items-center justify-center font-bold text-white ${grade.colour}`}>
        {grade.letter}
      </div>
      <div className="text-xs text-muted-foreground">
        Quality<br />{Math.round(score)}/100
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- finding card

function HotspotCard({ finding, onTriage, onAutofix }) {
  const [busy, setBusy] = useState(false);
  const verdict = finding.triage?.verdict;

  async function mark(verdictValue) {
    setBusy(true);
    try {
      await onTriage(finding, verdictValue);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="border-l-4" style={{ borderLeftColor: undefined }}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1 min-w-0 flex-1">
            <CardTitle className="text-base flex items-center gap-2 flex-wrap">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              {finding.title || finding.rule_id || "Finding"}
              <Badge variant={finding.severity === "critical" ? "destructive" : "secondary"}>
                {finding.severity}
              </Badge>
              {finding.cwe && <Badge variant="outline">{finding.cwe}</Badge>}
              {finding.cwe_family && <Badge variant="outline">{finding.cwe_family}</Badge>}
            </CardTitle>
            <CardDescription className="line-clamp-2">{finding.description}</CardDescription>
            {finding.sources?.length > 1 && (
              <div className="flex gap-1 mt-1">
                <Layers className="h-3 w-3 text-muted-foreground" />
                <span className="text-[11px] text-muted-foreground">Confirmed by:</span>
                {finding.sources.map((s) => (
                  <Badge key={s} variant="outline" className="text-[10px]">{s}</Badge>
                ))}
              </div>
            )}
          </div>
          {typeof finding.risk_score === "number" && (
            <div className="text-right shrink-0">
              <div className="text-xl font-semibold">{finding.risk_score}</div>
              <div className="text-[10px] text-muted-foreground uppercase">risk</div>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="pt-0 space-y-3">
        {finding.code_snippet && (
          <pre className="text-xs bg-muted/40 p-3 rounded border overflow-x-auto">
{finding.code_snippet}
          </pre>
        )}
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            size="sm"
            variant={verdict === "true_positive" ? "destructive" : "outline"}
            disabled={busy}
            onClick={() => mark("true_positive")}
          >
            <AlertTriangle className="h-3 w-3 mr-1" /> Confirm
          </Button>
          <Button
            size="sm"
            variant={verdict === "likely_fp" ? "secondary" : "outline"}
            disabled={busy}
            onClick={() => mark("likely_fp")}
          >
            <ShieldCheck className="h-3 w-3 mr-1" /> Mark safe
          </Button>
          <Button
            size="sm"
            variant={verdict === "needs_context" ? "default" : "outline"}
            disabled={busy}
            onClick={() => mark("needs_context")}
          >
            <Eye className="h-3 w-3 mr-1" /> Needs review
          </Button>
          <Button size="sm" variant="ghost" onClick={() => onAutofix(finding)}>
            <Wand2 className="h-3 w-3 mr-1" /> Autofix
          </Button>
          {finding.owner_email && (
            <span className="text-xs text-muted-foreground ml-auto">
              Last touched by {finding.owner_email}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------- file body (annotated lines)

function AnnotatedFile({ source, findings }) {
  const lines = useMemo(() => (source || "").split("\n"), [source]);
  const findingsByLine = useMemo(() => {
    const map = new Map();
    findings.forEach((f) => {
      const ln = f.line_start || 1;
      if (!map.has(ln)) map.set(ln, []);
      map.get(ln).push(f);
    });
    return map;
  }, [findings]);

  if (!source) {
    return (
      <Card>
        <CardContent className="py-6 text-sm text-muted-foreground">
          File source not available — supply <code className="text-xs">repo_path</code> in the URL or
          ensure the repo is checked out at <code className="text-xs">/tmp/fortknoxx_repos/&lt;repo_id&gt;</code>.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Source</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <pre className="text-xs leading-5 overflow-x-auto">
          <code>
            {lines.map((line, idx) => {
              const lineNum = idx + 1;
              const hits = findingsByLine.get(lineNum);
              const cls = hits
                ? SEVERITY_COLOUR[hits.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0].severity]
                : "";
              return (
                <div key={lineNum} className={`flex ${cls} ${hits ? "border-l-4" : ""}`}>
                  <span className="select-none w-12 text-right pr-3 text-muted-foreground/70">{lineNum}</span>
                  <span className="flex-1 whitespace-pre">{line || " "}</span>
                  {hits && (
                    <span className="pr-3 text-[10px] uppercase tracking-wider opacity-70">
                      {hits[0].severity} ×{hits.length}
                    </span>
                  )}
                </div>
              );
            })}
          </code>
        </pre>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------- page

function computeQualityScore(findings) {
  // Sonar-style A–E grade. Simple weighted deduction.
  const w = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
  const deduction = findings.reduce((acc, f) => acc + (w[f.severity] || 0), 0);
  return Math.max(0, 100 - deduction);
}

export default function CodeReviewView() {
  const { repoId } = useParams();
  const [params] = useSearchParams();
  const filePath = params.get("path") || "";
  const navigate = useNavigate();

  const [findings, setFindings] = useState([]);
  const [source, setSource] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true); setError(null);
      try {
        const findingsRes = await axios.get(`${API}/findings`, {
          params: { repo_id: repoId, file_path: filePath },
        });
        // Source fetch is best-effort — the backend may or may not
        // expose a file-content endpoint; we degrade gracefully.
        let src = "";
        try {
          const srcRes = await axios.get(`${API}/repositories/${repoId}/file`, {
            params: { path: filePath },
          });
          src = srcRes.data?.content || srcRes.data || "";
        } catch (_) { /* ignored — viewer shows graceful empty state */ }

        if (cancelled) return;
        setFindings(findingsRes.data || []);
        setSource(typeof src === "string" ? src : "");
      } catch (e) {
        if (!cancelled) setError(e.message || "Failed to load file findings");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [repoId, filePath]);

  const qualityScore = useMemo(() => computeQualityScore(findings), [findings]);

  async function setVerdict(finding, verdict) {
    // Optimistic UI; backend persistence is via the triage_cache when
    // available, otherwise marks locally only.
    setFindings((prev) =>
      prev.map((f) =>
        (f.id || f.fingerprint) === (finding.id || finding.fingerprint)
          ? { ...f, triage: { ...(f.triage || {}), verdict } }
          : f
      ),
    );
    try {
      await axios.post(`${API}/findings/${finding.id || finding.fingerprint}/triage`, { verdict });
    } catch (_) {
      // Endpoint is optional during rollout — UI state still useful for triage walk-through.
    }
  }

  async function requestAutofix(finding) {
    try {
      const { data } = await axios.post(`${API}/autofix`, {
        vulnerability_id: finding.id || finding.fingerprint,
      });
      const tag = data.applies_cleanly ? "applies cleanly" : `does NOT apply: ${data.error}`;
      alert(`Autofix (${data.cached ? "cached" : "fresh"}) — ${tag}`);
    } catch (e) {
      alert(`Autofix failed: ${e.response?.data?.detail || e.message}`);
    }
  }

  if (!filePath) {
    return (
      <div className="container max-w-3xl mx-auto p-6">
        <Card><CardContent className="py-6 text-sm">
          Missing <code>?path=</code> query parameter. Open this view from a finding row.
        </CardContent></Card>
      </div>
    );
  }

  return (
    <div className="container max-w-7xl mx-auto p-6 space-y-4">
      <FileHeader
        filePath={filePath}
        findings={findings}
        qualityScore={qualityScore}
        onBack={() => navigate(-1)}
      />

      {error && (
        <Card className="border-red-500/40">
          <CardContent className="text-sm text-red-500 pt-6">{error}</CardContent>
        </Card>
      )}
      {loading && <div className="text-sm text-muted-foreground">Loading file…</div>}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-3">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" /> Hotspots ({findings.length})
          </h3>
          {findings.length === 0 ? (
            <Card><CardContent className="py-6 text-sm text-muted-foreground">
              No findings on this file. <Sparkles className="inline h-3 w-3" /> nicely done.
            </CardContent></Card>
          ) : (
            findings
              .sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0))
              .map((f) => (
                <HotspotCard
                  key={f.id || f.fingerprint}
                  finding={f}
                  onTriage={setVerdict}
                  onAutofix={requestAutofix}
                />
              ))
          )}
        </div>

        <div>
          <AnnotatedFile source={source} findings={findings} />
        </div>
      </div>

      <Separator />
      <div className="text-xs text-muted-foreground">
        Quality score is an A–E grade computed from severity-weighted findings, the same shape
        Sonar uses. Tune the deduction weights in <code>computeQualityScore</code>.
      </div>
    </div>
  );
}
