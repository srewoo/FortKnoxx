import React, { useState, useEffect } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Link, useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { Shield, Search, FileCode, Activity, AlertTriangle, CheckCircle, XCircle, Clock, TrendingUp, Database, GitBranch, Sparkles, Settings, Trash2, Key, Download, FileJson, FileText, Github, Link2, Plus, ExternalLink, RefreshCw, LayoutGrid, List, Lock, HelpCircle } from "lucide-react";

// OWASP Top 10 Categories mapping
const OWASP_CATEGORIES = {
  "A01": "Broken Access Control",
  "A02": "Cryptographic Failures",
  "A03": "Injection",
  "A04": "Insecure Design",
  "A05": "Security Misconfiguration",
  "A06": "Vulnerable and Outdated Components",
  "A07": "Identification and Authentication Failures",
  "A08": "Software and Data Integrity Failures",
  "A09": "Security Logging and Monitoring Failures",
  "A10": "Server-Side Request Forgery"
};

// Helper function to get full OWASP category name
const getOwaspCategoryName = (code) => {
  return OWASP_CATEGORIES[code] ? `${code}: ${OWASP_CATEGORIES[code]}` : code;
};

// Helper function to format scanner names
const formatScannerName = (scanner) => {
  const formattedNames = {
    "zero_day": "Zero-Day Detector (AI)",
    "business_logic": "Business Logic (AI)",
    "llm_security": "LLM Security (AI)",
    "auth_scanner": "Auth Scanner (AI)",
    "npm_audit": "NPM Audit",
    "pip_audit": "Pip Audit",
    "cargo_audit": "Cargo Audit"
  };

  return formattedNames[scanner] || scanner.split('_').map(word =>
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ');
};

// Helper function to truncate text
const truncateText = (text, maxLength) => {
  if (!text) return "";
  return text.length > maxLength ? text.substring(0, maxLength) + "..." : text;
};

// Helper function to extract error message from API response
const getErrorMessage = (error) => {
  const detail = error.response?.data?.detail;
  if (!detail) return error.message || "An error occurred";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // Pydantic validation errors are arrays of objects with {type, loc, msg}
    return detail.map(e => e.msg || JSON.stringify(e)).join(", ");
  }
  if (typeof detail === "object") return detail.msg || JSON.stringify(detail);
  return String(detail);
};

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [gitIntegrations, setGitIntegrations] = useState([]);
  const [connectedRepos, setConnectedRepos] = useState([]);
  const [aiStatus, setAiStatus] = useState({ configured: false, providers: [] });
  const [viewMode, setViewMode] = useState(() => {
    return localStorage.getItem("repoViewMode") || "grid";
  });
  const navigate = useNavigate();

  useEffect(() => {
    localStorage.setItem("repoViewMode", viewMode);
  }, [viewMode]);

  useEffect(() => {
    fetchRepositories();
    fetchGitIntegrations();
    fetchAiStatus();
  }, []);

  const fetchRepositories = async () => {
    try {
      const response = await axios.get(`${API}/repositories`);
      setRepositories(response.data);
    } catch (error) {
      console.error("Failed to fetch repositories:", error);
      toast.error(`Failed to fetch repositories: ${getErrorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchGitIntegrations = async () => {
    try {
      const [integrationsRes, reposRes] = await Promise.all([
        axios.get(`${API}/integrations/git`).catch(() => ({ data: { integrations: [] } })),
        axios.get(`${API}/repositories`).catch(() => ({ data: { repositories: [] } }))
      ]);
      setGitIntegrations(integrationsRes.data.integrations || []);
      setConnectedRepos(reposRes.data.repositories || []);
    } catch (error) {
      console.error("Failed to fetch git integrations:", error);
    }
  };

  const fetchAiStatus = async () => {
    try {
      const response = await axios.get(`${API}/settings`);
      const keys = response.data.llm_api_keys || {};
      const scannerSettings = response.data.ai_scanner_settings || {};

      const providers = [];
      if (keys.openai_api_key) providers.push("OpenAI");
      if (keys.anthropic_api_key) providers.push("Claude");
      if (keys.gemini_api_key) providers.push("Gemini");

      // AI Analysis is configured if ANY AI scanner is enabled (they work without API keys)
      const aiScannersEnabled =
        scannerSettings.enable_zero_day_detector !== false ||
        scannerSettings.enable_business_logic_scanner !== false ||
        scannerSettings.enable_llm_security_scanner !== false ||
        scannerSettings.enable_auth_scanner !== false;

      setAiStatus({
        configured: aiScannersEnabled,
        providers,
        scannerSettings,
        hasApiKeys: providers.length > 0,
        snykConfigured: !!keys.snyk_token
      });
    } catch (error) {
      console.error("Failed to fetch AI status:", error);
    }
  };

  const getSeverityColor = (status) => {
    switch (status) {
      case "completed": return "bg-emerald-500";
      case "scanning": return "bg-blue-500";
      case "failed": return "bg-red-500";
      default: return "bg-gray-500";
    }
  };

  const deleteRepository = async (e, repoId, repoName) => {
    e.stopPropagation();
    if (!window.confirm(`Are you sure you want to delete repository "${repoName}"? This will also delete all associated scans and vulnerabilities.`)) {
      return;
    }
    try {
      await axios.delete(`${API}/repositories/${repoId}`);
      toast.success(`Repository "${repoName}" deleted successfully!`);
      fetchRepositories();
    } catch (error) {
      console.error("Failed to delete repository:", error);
      toast.error(`Failed to delete repository: ${getErrorMessage(error)}`);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-4xl font-bold" data-testid="dashboard-title">Security Dashboard</h1>
          <p className="text-muted-foreground mt-2">Monitor and manage repository security scans</p>
        </div>
      </div>

      {/* Git Integrations Quick Status */}
      {gitIntegrations.length > 0 && (
        <Card className="bg-gradient-to-r from-primary/5 to-primary/10 border-primary/20">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Link2 className="h-5 w-5 text-primary" />
                  <span className="font-medium">Git Integrations</span>
                </div>
                <div className="flex gap-2">
                  {gitIntegrations.map((integration, idx) => (
                    <Badge key={idx} variant="outline" className="flex items-center gap-1">
                      {integration.provider === "github" ? (
                        <Github className="h-3 w-3" />
                      ) : (
                        <GitBranch className="h-3 w-3" />
                      )}
                      {integration.username || integration.name}
                      {integration.is_connected && (
                        <CheckCircle className="h-3 w-3 text-green-500" />
                      )}
                    </Badge>
                  ))}
                </div>
                {connectedRepos.length > 0 && (
                  <span className="text-sm text-muted-foreground">
                    {connectedRepos.length} repo{connectedRepos.length !== 1 ? 's' : ''} connected
                  </span>
                )}
              </div>
              <Button variant="ghost" size="sm" onClick={() => navigate("/settings")}>
                <Settings className="h-4 w-4 mr-1" />
                Manage
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Quick Setup Banner for New Users */}
      {gitIntegrations.length === 0 && repositories.length === 0 && !loading && (
        <Card className="border-dashed border-2 bg-muted/30">
          <CardContent className="py-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <Github className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold">Connect Your Git Provider</h3>
                  <p className="text-sm text-muted-foreground">
                    Connect GitHub or GitLab to easily scan your repositories
                  </p>
                </div>
              </div>
              <Button onClick={() => navigate("/settings")}>
                <Link2 className="h-4 w-4 mr-2" />
                Connect Now
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* AI-Powered Security Analysis Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className={`${aiStatus.configured ? 'bg-gradient-to-br from-purple-500/10 to-blue-500/10 border-purple-500/20' : 'bg-muted/30 border-dashed'}`}>
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-lg flex items-center justify-center ${aiStatus.configured ? 'bg-purple-500/20' : 'bg-muted'}`}>
                <Sparkles className={`h-5 w-5 ${aiStatus.configured ? 'text-purple-500' : 'text-muted-foreground'}`} />
              </div>
              <div>
                <div className="text-sm text-muted-foreground">AI Analysis</div>
                <div className="font-semibold flex items-center gap-2">
                  {aiStatus.configured ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      Active
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                      Not Configured
                    </>
                  )}
                </div>
              </div>
            </div>
            {aiStatus.providers.length > 0 && (
              <div className="mt-2 flex gap-1">
                {aiStatus.providers.map((p, i) => (
                  <Badge key={i} variant="secondary" className="text-xs">{p}</Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className={`bg-gradient-to-br from-amber-500/10 to-orange-500/10 ${
          aiStatus.scannerSettings?.enable_zero_day_detector !== false
            ? 'border-amber-500/20'
            : 'border-dashed border-muted opacity-60'
        }`}>
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                aiStatus.scannerSettings?.enable_zero_day_detector !== false
                  ? 'bg-amber-500/20'
                  : 'bg-muted'
              }`}>
                <AlertTriangle className={`h-5 w-5 ${
                  aiStatus.scannerSettings?.enable_zero_day_detector !== false
                    ? 'text-amber-500'
                    : 'text-muted-foreground'
                }`} />
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Zero-Day Detector</div>
                <div className="font-semibold flex items-center gap-2">
                  {aiStatus.scannerSettings?.enable_zero_day_detector !== false ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      AI-Powered
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                      Disabled
                    </>
                  )}
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">Detects unknown vulnerabilities using pattern analysis</p>
          </CardContent>
        </Card>

        <Card className={`bg-gradient-to-br from-blue-500/10 to-cyan-500/10 ${
          aiStatus.scannerSettings?.enable_business_logic_scanner !== false
            ? 'border-blue-500/20'
            : 'border-dashed border-muted opacity-60'
        }`}>
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                aiStatus.scannerSettings?.enable_business_logic_scanner !== false
                  ? 'bg-blue-500/20'
                  : 'bg-muted'
              }`}>
                <Shield className={`h-5 w-5 ${
                  aiStatus.scannerSettings?.enable_business_logic_scanner !== false
                    ? 'text-blue-500'
                    : 'text-muted-foreground'
                }`} />
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Business Logic</div>
                <div className="font-semibold flex items-center gap-2">
                  {aiStatus.scannerSettings?.enable_business_logic_scanner !== false ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      Active
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                      Disabled
                    </>
                  )}
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">Analyzes code for logic flaws & design issues</p>
          </CardContent>
        </Card>

        <Card className={`bg-gradient-to-br ${
          aiStatus.scannerSettings?.enable_llm_security_scanner !== false
            ? aiStatus.hasApiKeys
              ? 'from-emerald-500/10 to-green-500/10 border-emerald-500/20'
              : 'from-amber-500/10 to-yellow-500/10 border-amber-500/30 border-dashed'
            : 'from-gray-500/5 to-gray-500/5 border-dashed border-muted opacity-60'
        }`}>
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                aiStatus.scannerSettings?.enable_llm_security_scanner !== false
                  ? aiStatus.hasApiKeys ? 'bg-emerald-500/20' : 'bg-amber-500/20'
                  : 'bg-muted'
              }`}>
                <Activity className={`h-5 w-5 ${
                  aiStatus.scannerSettings?.enable_llm_security_scanner !== false
                    ? aiStatus.hasApiKeys ? 'text-emerald-500' : 'text-amber-500'
                    : 'text-muted-foreground'
                }`} />
              </div>
              <div>
                <div className="text-sm text-muted-foreground">LLM Security</div>
                <div className="font-semibold flex items-center gap-2">
                  {aiStatus.scannerSettings?.enable_llm_security_scanner !== false ? (
                    aiStatus.hasApiKeys ? (
                      <>
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        Active
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4 text-amber-500" />
                        <span className="text-amber-600">Needs API Key</span>
                      </>
                    )
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                      Disabled
                    </>
                  )}
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              {aiStatus.scannerSettings?.enable_llm_security_scanner !== false && !aiStatus.hasApiKeys
                ? "Requires OpenAI, Claude, or Gemini API key"
                : "Tests for prompt injection & AI vulnerabilities"}
            </p>
          </CardContent>
        </Card>

        <Card className={`bg-gradient-to-br from-rose-500/10 to-pink-500/10 ${
          aiStatus.scannerSettings?.enable_auth_scanner !== false
            ? 'border-rose-500/20'
            : 'border-dashed border-muted opacity-60'
        }`}>
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                aiStatus.scannerSettings?.enable_auth_scanner !== false
                  ? 'bg-rose-500/20'
                  : 'bg-muted'
              }`}>
                <Lock className={`h-5 w-5 ${
                  aiStatus.scannerSettings?.enable_auth_scanner !== false
                    ? 'text-rose-500'
                    : 'text-muted-foreground'
                }`} />
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Auth Scanner</div>
                <div className="font-semibold flex items-center gap-2">
                  {aiStatus.scannerSettings?.enable_auth_scanner !== false ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      Active
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                      Disabled
                    </>
                  )}
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">JWT, OAuth & session security testing</p>
          </CardContent>
        </Card>
      </div>

      {/* Configure AI Prompt - Show only when no scanners are enabled */}
      {!aiStatus.configured && (
        <Card className="border-dashed border-2 bg-gradient-to-r from-purple-500/5 to-blue-500/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <Sparkles className="h-8 w-8 text-purple-500" />
                <div>
                  <h3 className="font-semibold">Enable AI-Powered Scanners</h3>
                  <p className="text-sm text-muted-foreground">
                    Enable scanners in settings to activate Zero-Day Detection, Business Logic & Auth Scanning
                  </p>
                </div>
              </div>
              <Button variant="outline" onClick={() => navigate("/settings")}>
                <Settings className="h-4 w-4 mr-2" />
                Configure Scanners
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* API Keys Prompt - Show when scanners are enabled but no LLM keys configured */}
      {aiStatus.configured && !aiStatus.hasApiKeys && (
        <Card className="border-dashed border-2 bg-gradient-to-r from-amber-500/5 to-orange-500/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <Key className="h-8 w-8 text-amber-500" />
                <div>
                  <h3 className="font-semibold">Enhance with LLM API Keys (Optional)</h3>
                  <p className="text-sm text-muted-foreground">
                    Add OpenAI, Claude, or Gemini API keys to enable AI fix recommendations and enhanced LLM Security testing
                  </p>
                </div>
              </div>
              <Button variant="outline" onClick={() => navigate("/settings")}>
                <Key className="h-4 w-4 mr-2" />
                Add API Key
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Repositories Section Header */}
      {!loading && repositories.length > 0 && (
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold">Repositories ({repositories.length})</h2>
          <div className="flex items-center gap-2 bg-muted p-1 rounded-lg">
            <Button
              variant={viewMode === "grid" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode("grid")}
              className="h-8"
            >
              <LayoutGrid className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === "list" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode("list")}
              className="h-8"
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <Card key={i} className="animate-pulse">
              <CardHeader>
                <div className="h-6 bg-muted rounded w-3/4"></div>
                <div className="h-4 bg-muted rounded w-1/2 mt-2"></div>
              </CardHeader>
              <CardContent>
                <div className="h-20 bg-muted rounded"></div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : repositories.length === 0 ? (
        <Card className="border-dashed" data-testid="empty-state">
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Shield className="h-24 w-24 text-muted-foreground mb-4" />
            <h3 className="text-2xl font-semibold mb-2">No repositories yet</h3>
            <p className="text-muted-foreground mb-6">Add your first repository to start scanning</p>
            <Button onClick={() => navigate("/add-repository")} data-testid="empty-add-repo-btn">
              Add Repository
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className={viewMode === "grid" ? "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" : "space-y-4"}>
          {repositories.map((repo) => (
            <Card key={repo.id} className={`cursor-pointer border-2 hover:border-primary transition-all ${viewMode === "grid" ? "hover:shadow-lg hover:scale-105 duration-300" : "hover:shadow-md"}`} onClick={() => navigate(`/repository/${repo.id}`)} data-testid={`repo-card-${repo.id}`}>
              {viewMode === "list" ? (
                /* List View */
                <CardContent className="py-4">
                  <div className="flex items-center gap-6">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <GitBranch className="h-5 w-5 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="font-semibold truncate">{repo.name}</div>
                        <div className="text-sm text-muted-foreground truncate">{repo.url}</div>
                      </div>
                    </div>

                    {repo.security_score !== null && repo.security_score !== undefined ? (
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-muted-foreground">Score:</span>
                        <span className={`text-xl font-bold ${repo.security_score >= 90 ? 'text-green-500' : repo.security_score >= 70 ? 'text-amber-500' : 'text-red-500'}`}>
                          {repo.security_score}
                        </span>
                      </div>
                    ) : (
                      <span className="text-sm text-muted-foreground">No scan yet</span>
                    )}

                    {repo.critical_count > 0 && (
                      <span className="flex items-center gap-1 text-red-500 font-medium text-sm">
                        <span className="w-2 h-2 rounded-full bg-red-500" />
                        {repo.critical_count} Critical
                      </span>
                    )}

                    <div className="text-sm text-muted-foreground">
                      {repo.branch}
                    </div>

                    <Badge className={getSeverityColor(repo.scan_status)} data-testid={`repo-status-${repo.id}`}>
                      {repo.scan_status}
                    </Badge>

                    <Button
                      variant="ghost"
                      size="icon"
                      className="text-muted-foreground hover:text-destructive h-8 w-8 flex-shrink-0"
                      onClick={(e) => deleteRepository(e, repo.id, repo.name)}
                      data-testid={`delete-repo-${repo.id}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              ) : (
                /* Grid View */
                <>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <CardTitle className="flex items-center gap-2">
                          <GitBranch className="h-5 w-5" />
                          {truncateText(repo.name, 15)}
                        </CardTitle>
                        <CardDescription className="mt-1 truncate">{repo.url}</CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getSeverityColor(repo.scan_status)} data-testid={`repo-status-${repo.id}`}>
                          {repo.scan_status}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-muted-foreground hover:text-destructive h-8 w-8"
                          onClick={(e) => deleteRepository(e, repo.id, repo.name)}
                          data-testid={`delete-repo-${repo.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                <div className="space-y-3">
                  {/* Security Score Display */}
                  {repo.security_score !== null && repo.security_score !== undefined ? (
                    <div className="flex items-center justify-between p-3 rounded-lg" style={{
                      backgroundColor: repo.security_score >= 90 ? 'rgba(34, 197, 94, 0.1)' :
                        repo.security_score >= 70 ? 'rgba(245, 158, 11, 0.1)' :
                          'rgba(239, 68, 68, 0.1)'
                    }}>
                      <span className="text-sm font-medium">Security Score</span>
                      <div className="flex items-center gap-2">
                        <span className={`text-2xl font-bold ${repo.security_score >= 90 ? 'text-green-500' :
                          repo.security_score >= 70 ? 'text-amber-500' :
                            'text-red-500'
                          }`}>
                          {repo.security_score}
                        </span>
                        <div className={`w-3 h-3 rounded-full ${repo.security_score >= 90 ? 'bg-green-500' :
                          repo.security_score >= 70 ? 'bg-amber-500' :
                            'bg-red-500'
                          }`} />
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                      <span className="text-sm font-medium text-muted-foreground">Security Score</span>
                      <span className="text-sm text-muted-foreground">No scan yet</span>
                    </div>
                  )}

                  {/* Vulnerability Summary */}
                  {repo.security_score !== null && (
                    <div className="flex items-center gap-4 text-xs">
                      {repo.critical_count > 0 && (
                        <span className="flex items-center gap-1 text-red-500 font-medium">
                          <span className="w-2 h-2 rounded-full bg-red-500" />
                          {repo.critical_count} Critical
                        </span>
                      )}
                      {repo.high_count > 0 && (
                        <span className="flex items-center gap-1 text-orange-500 font-medium">
                          <span className="w-2 h-2 rounded-full bg-orange-500" />
                          {repo.high_count} High
                        </span>
                      )}
                      {repo.vulnerabilities_count > 0 && (
                        <span className="text-muted-foreground">
                          {repo.vulnerabilities_count} Total
                        </span>
                      )}
                    </div>
                  )}

                  <Separator />
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Branch</span>
                    <span className="font-medium">{repo.branch}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Last Scan</span>
                    <span className="font-medium">
                      {repo.last_scan ? new Date(repo.last_scan).toLocaleDateString() : "Never"}
                    </span>
                  </div>
                  <Separator />
                  <Button className="w-full" variant="outline" onClick={(e) => { e.stopPropagation(); navigate(`/repository/${repo.id}`); }} data-testid={`view-details-${repo.id}`}>
                    View Details
                  </Button>
                </div>
              </CardContent>
                </>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

const AddRepository = () => {
  const [formData, setFormData] = useState({
    name: "",
    url: "",
    access_token: "",
    branch: "main",
    is_public: false
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      // Determine provider from URL
      let provider = "github";
      if (formData.url.includes("gitlab")) {
        provider = "gitlab";
      }

      const requestData = {
        provider: provider,
        repo_url: formData.url,
        auto_scan: false,
        branch: formData.branch || "main",
        is_public: formData.is_public,
        access_token: formData.is_public ? null : formData.access_token
      };

      const response = await axios.post(`${API}/repositories`, requestData);
      toast.success("Repository added successfully!");

      // Navigate to dashboard or repository detail
      const repoId = response.data.repository?.repo_id;
      if (repoId) {
        navigate(`/repository/${repoId}`);
      } else {
        navigate("/");
      }
    } catch (error) {
      console.error("Failed to add repository:", error);
      toast.error(`Failed to add repository: ${getErrorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-4xl font-bold" data-testid="add-repo-title">Add Repository</h1>
        <p className="text-muted-foreground mt-2">Connect a repository to start security scanning</p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="url">Repository URL</Label>
              <Input
                id="url"
                data-testid="repo-url-input"
                placeholder="https://github.com/username/repository"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                required
              />
              <p className="text-xs text-muted-foreground">
                Enter the full URL of your GitHub or GitLab repository
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="is_public"
                data-testid="is-public-checkbox"
                checked={formData.is_public}
                onChange={(e) => setFormData({ ...formData, is_public: e.target.checked, access_token: e.target.checked ? "" : formData.access_token })}
                className="w-4 h-4 rounded border-gray-300"
              />
              <Label htmlFor="is_public" className="cursor-pointer font-normal">
                This is a public repository (no access token required)
              </Label>
            </div>

            {!formData.is_public && (
              <div className="space-y-2">
                <Label htmlFor="token">Access Token</Label>
                <Input
                  id="token"
                  data-testid="repo-token-input"
                  type="password"
                  placeholder="ghp_xxxxxxxxxxxx or glpat-xxxxxxxxxxxx"
                  value={formData.access_token}
                  onChange={(e) => setFormData({ ...formData, access_token: e.target.value })}
                  required={!formData.is_public}
                />
                <p className="text-xs text-muted-foreground">
                  Personal Access Token with repo access (required for private repositories)
                </p>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="branch">Branch (Optional)</Label>
              <Input
                id="branch"
                data-testid="repo-branch-input"
                placeholder="main"
                value={formData.branch}
                onChange={(e) => setFormData({ ...formData, branch: e.target.value })}
              />
              <p className="text-xs text-muted-foreground">
                Leave empty to use the default branch
              </p>
            </div>

            <div className="flex gap-4">
              <Button type="submit" className="flex-1" disabled={loading} data-testid="submit-repo-btn">
                {loading ? "Adding..." : "Add Repository"}
              </Button>
              <Button type="button" variant="outline" onClick={() => navigate("/")} data-testid="cancel-btn">
                Cancel
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

const RepositoryDetail = () => {
  const { repoId } = useParams();
  const [repository, setRepository] = useState(null);
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchRepositoryData();
  }, [repoId]);

  useEffect(() => {
    if (repository?.scan_status === "scanning") {
      const interval = setInterval(() => {
        fetchRepositoryData();
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [repository?.scan_status]);

  const fetchRepositoryData = async () => {
    try {
      const [repoRes, scansRes, statsRes] = await Promise.all([
        axios.get(`${API}/repositories/${repoId}`),
        axios.get(`${API}/scans/${repoId}`),
        axios.get(`${API}/stats/${repoId}`).catch(() => ({ data: null }))
      ]);
      setRepository(repoRes.data);
      setScans(scansRes.data);
      setStats(statsRes.data);

      // Reset scanning state when scan is no longer in progress
      if (repoRes.data.scan_status !== "scanning") {
        setScanning(false);
      }
    } catch (error) {
      console.error("Failed to fetch repository data:", error);
      toast.error(`Failed to fetch repository data: ${getErrorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const startScan = async () => {
    setScanning(true);
    try {
      await axios.post(`${API}/scans/${repoId}`);
      toast.success("Scan started successfully!");
      // Don't set scanning to false here - let it be controlled by scan_status from backend
      setTimeout(fetchRepositoryData, 2000);
    } catch (error) {
      console.error("Failed to start scan:", error);
      toast.error(`Failed to start scan: ${getErrorMessage(error)}`);
      // Only set scanning to false if the scan failed to start
      setScanning(false);
    }
  };

  const deleteScan = async (e, scanId) => {
    e.stopPropagation();
    if (!window.confirm("Are you sure you want to delete this scan? This will also delete all associated vulnerabilities.")) {
      return;
    }
    try {
      await axios.delete(`${API}/scans/${scanId}`);
      toast.success("Scan deleted successfully!");
      fetchRepositoryData();
    } catch (error) {
      console.error("Failed to delete scan:", error);
      toast.error(`Failed to delete scan: ${getErrorMessage(error)}`);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "medium": return "default";
      case "low": return "secondary";
      default: return "outline";
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen">Loading...</div>;
  }

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <Button variant="ghost" onClick={() => navigate("/")} className="mb-4" data-testid="back-btn">
            ← Back to Dashboard
          </Button>
          <h1 className="text-4xl font-bold" data-testid="repo-detail-title">{repository.name}</h1>
          <p className="text-muted-foreground mt-2">{repository.url}</p>
        </div>
        <div className="flex gap-3">
          <Button onClick={startScan} disabled={scanning || repository.scan_status === "scanning"} size="lg" data-testid="start-scan-btn">
            {scanning || repository.scan_status === "scanning" ? (
              <>
                <Clock className="mr-2 h-5 w-5 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="mr-2 h-5 w-5" />
                Start Scan
              </>
            )}
          </Button>
        </div>
      </div>

      {repository?.scan_status === "scanning" && (
        <Card className="border-blue-500 bg-blue-50 dark:bg-blue-950">
          <CardContent className="py-6">
            <div className="flex items-center gap-4">
              <Clock className="h-8 w-8 text-blue-500 animate-spin" />
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-blue-700 dark:text-blue-300">Security Scan in Progress</h3>
                <p className="text-sm text-blue-600 dark:text-blue-400">
                  Running comprehensive security analysis with 31 professional scanning tools across all code, dependencies, secrets, and infrastructure...
                </p>
                <Progress value={33} className="mt-2" />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="pb-3">
              <CardDescription>Security Score</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <div className="text-4xl font-bold" data-testid="security-score">{stats.security_score}</div>
                <Progress value={stats.security_score} className="flex-1" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardDescription>Total Vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold" data-testid="total-vulns">{stats.total_vulnerabilities}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardDescription>Critical Issues</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold text-red-500" data-testid="critical-count">{stats.severity_distribution?.critical || 0}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardDescription>Files Scanned</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-4xl font-bold" data-testid="files-scanned">{stats.total_files_scanned}</div>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs defaultValue="scans" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="scans" data-testid="scans-tab">Scan History</TabsTrigger>
          <TabsTrigger value="analysis" data-testid="analysis-tab">Security Analysis</TabsTrigger>
        </TabsList>

        <TabsContent value="scans" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Scan History</CardTitle>
              <CardDescription>View all security scans for this repository</CardDescription>
            </CardHeader>
            <CardContent>
              {scans.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground" data-testid="no-scans">
                  No scans yet. Click "Start Scan" to begin.
                </div>
              ) : (
                <div className="space-y-4">
                  {scans.map((scan) => (
                    <Card key={scan.id} className="cursor-pointer hover:shadow-lg hover:scale-[1.02] hover:border-primary transition-all border-2" onClick={() => navigate(`/scan/${scan.id}`)} data-testid={`scan-card-${scan.id}`}>
                      <CardContent className="pt-6">
                        <div className="flex items-center justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <Activity className="h-5 w-5" />
                              <span className="font-semibold">Scan ID: {scan.id.slice(0, 8)}</span>
                              <Badge variant={scan.status === "completed" ? "default" : scan.status === "scanning" ? "outline" : "secondary"} data-testid={`scan-status-${scan.id}`}>
                                {scan.status === "scanning" && <Clock className="h-3 w-3 mr-1 animate-spin" />}
                                {scan.status}
                              </Badge>
                            </div>
                            {scan.completed_at && (
                              <div className="text-sm text-muted-foreground mb-3">
                                <Clock className="h-3 w-3 inline mr-1" />
                                Completed: {new Date(scan.completed_at).toLocaleString('en-US', {
                                  month: 'short',
                                  day: 'numeric',
                                  year: 'numeric',
                                  hour: '2-digit',
                                  minute: '2-digit'
                                })}
                              </div>
                            )}
                            {!scan.completed_at && scan.started_at && (
                              <div className="text-sm text-muted-foreground mb-3">
                                <Clock className="h-3 w-3 inline mr-1" />
                                Started: {new Date(scan.started_at).toLocaleString('en-US', {
                                  month: 'short',
                                  day: 'numeric',
                                  year: 'numeric',
                                  hour: '2-digit',
                                  minute: '2-digit'
                                })}
                              </div>
                            )}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                              <div>
                                <div className="text-sm text-muted-foreground">Total Issues</div>
                                <div className="text-2xl font-bold">{scan.vulnerabilities_count}</div>
                              </div>
                              <div>
                                <div className="text-sm text-muted-foreground">Critical</div>
                                <div className="text-2xl font-bold text-red-500">{scan.critical_count}</div>
                              </div>
                              <div>
                                <div className="text-sm text-muted-foreground">High</div>
                                <div className="text-2xl font-bold text-orange-500">{scan.high_count}</div>
                              </div>
                              <div>
                                <div className="text-sm text-muted-foreground">Score</div>
                                <div className="text-2xl font-bold text-green-500">{scan?.security_score || 0}</div>
                              </div>
                            </div>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-muted-foreground hover:text-destructive"
                            onClick={(e) => deleteScan(e, scan.id)}
                            data-testid={`delete-scan-${scan.id}`}
                          >
                            <Trash2 className="h-5 w-5" />
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analysis">
          {stats ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Severity Distribution</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {Object.entries(stats.severity_distribution || {}).map(([severity, count]) => (
                    <div key={severity} className="space-y-2">
                      <div className="flex justify-between">
                        <span className="capitalize font-medium">{severity}</span>
                        <span className="font-bold">{count}</span>
                      </div>
                      <Progress value={stats.total_vulnerabilities > 0 ? (count / stats.total_vulnerabilities) * 100 : 0} />
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>OWASP Top 10 Distribution</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {Object.entries(stats.owasp_distribution || {}).map(([category, count]) => (
                    <div key={category} className="flex justify-between items-center">
                      <span className="text-sm font-medium">{getOwaspCategoryName(category)}</span>
                      <Badge>{count}</Badge>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No analysis data available. Run a scan first.
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

const ScanDetail = () => {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filteredVulns, setFilteredVulns] = useState([]);
  const [qualityIssues, setQualityIssues] = useState([]);
  const [complianceIssues, setComplianceIssues] = useState([]);
  const [activeTab, setActiveTab] = useState("security");
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [aiRecommendation, setAiRecommendation] = useState("");
  const [loadingAI, setLoadingAI] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState(() => {
    return localStorage.getItem("selectedProvider") || "anthropic";
  });
  const [selectedModel, setSelectedModel] = useState(() => {
    const storedModel = localStorage.getItem("selectedModel");
    // Migrate old model names to new ones
    const modelMigration = {
      "gpt-4o": "gpt-4o-mini",
      "gpt-4": "gpt-4o-mini",
      "gpt-4-turbo": "gpt-4o-mini",
      "claude-sonnet-4-20250514": "claude-3-7-sonnet-20250219",
      "claude-4-sonnet-20250514": "claude-3-7-sonnet-20250219",
      "gemini-2.0-flash-exp": "gemini-2.0-flash",
      "gemini-1.5-pro": "gemini-2.0-flash",
      "gemini-pro": "gemini-2.0-flash"
    };

    if (storedModel && modelMigration[storedModel]) {
      const newModel = modelMigration[storedModel];
      localStorage.setItem("selectedModel", newModel);
      return newModel;
    }

    return storedModel || "claude-3-7-sonnet-20250219";
  });
  const [filterSeverity, setFilterSeverity] = useState(() => {
    return localStorage.getItem("filterSeverity") || "all";
  });
  const [filterOwasp, setFilterOwasp] = useState(() => {
    return localStorage.getItem("filterOwasp") || "all";
  });
  const [filterScanner, setFilterScanner] = useState(() => {
    const saved = localStorage.getItem("filterScanner");
    return saved ? JSON.parse(saved) : [];
  });
  const navigate = useNavigate();

  useEffect(() => {
    fetchScanData();
  }, [scanId]);

  useEffect(() => {
    applyFilters();
  }, [vulnerabilities, qualityIssues, complianceIssues, filterSeverity, filterOwasp, filterScanner]);

  useEffect(() => {
    localStorage.setItem("selectedProvider", selectedProvider);
  }, [selectedProvider]);

  useEffect(() => {
    localStorage.setItem("selectedModel", selectedModel);
  }, [selectedModel]);

  useEffect(() => {
    localStorage.setItem("filterSeverity", filterSeverity);
  }, [filterSeverity]);

  useEffect(() => {
    localStorage.setItem("filterOwasp", filterOwasp);
  }, [filterOwasp]);

  useEffect(() => {
    localStorage.setItem("filterScanner", JSON.stringify(filterScanner));
  }, [filterScanner]);

  const fetchScanData = async () => {
    try {
      const [scanRes, vulnsRes, qualityRes, complianceRes] = await Promise.all([
        axios.get(`${API}/scans/detail/${scanId}`),
        axios.get(`${API}/vulnerabilities/${scanId}`),
        axios.get(`${API}/quality/${scanId}`).catch(() => ({ data: [] })),
        axios.get(`${API}/compliance/${scanId}`).catch(() => ({ data: [] }))
      ]);
      setScan(scanRes.data);
      setVulnerabilities(vulnsRes.data);
      setFilteredVulns(vulnsRes.data);
      setQualityIssues(qualityRes.data || []);
      setComplianceIssues(complianceRes.data || []);
    } catch (error) {
      console.error("Failed to fetch scan data:", error);
      toast.error(`Failed to fetch scan data: ${getErrorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  };

  // Helper function to normalize scanner names for comparison
  const normalizeScannerName = (name) => {
    if (!name) return '';
    // Remove spaces, hyphens, underscores and convert to lowercase
    return name.toLowerCase().replace(/[\s\-_]/g, '');
  };

  const applyFilters = () => {
    // Combine all issues from all collections
    let allIssues = [
      ...vulnerabilities,
      ...qualityIssues.map(q => ({ ...q, issue_type: 'quality' })),
      ...complianceIssues.map(c => ({ ...c, issue_type: 'compliance' }))
    ];

    if (filterSeverity !== "all") {
      allIssues = allIssues.filter(v => v.severity === filterSeverity);
    }

    if (filterOwasp !== "all") {
      allIssues = allIssues.filter(v => v.owasp_category === filterOwasp);
    }

    if (filterScanner.length > 0) {
      allIssues = allIssues.filter(v => {
        // Check both detected_by (single scanner) and detected_by_scanners (array from deduplication)
        const scannersToCheck = [];

        if (v.detected_by) {
          scannersToCheck.push(v.detected_by);
        }

        if (v.detected_by_scanners && Array.isArray(v.detected_by_scanners)) {
          scannersToCheck.push(...v.detected_by_scanners);
        }

        if (scannersToCheck.length === 0) return false;

        // Check if any of the selected scanners match any of the issue's scanners
        return filterScanner.some(selectedScanner => {
          const normalizedSelected = normalizeScannerName(selectedScanner);
          return scannersToCheck.some(issueScanner => {
            const normalizedIssue = normalizeScannerName(issueScanner);
            return normalizedIssue === normalizedSelected ||
                   normalizedIssue.includes(normalizedSelected) ||
                   normalizedSelected.includes(normalizedIssue);
          });
        });
      });
    }

    setFilteredVulns(allIssues);
  };

  const getAIRecommendation = async (vuln) => {
    setSelectedVuln(vuln);
    setLoadingAI(true);
    setAiRecommendation("");

    try {
      const response = await axios.post(`${API}/ai/fix-recommendation`, {
        vulnerability_id: vuln.id,
        provider: selectedProvider,
        model: selectedModel
      });
      setAiRecommendation(response.data.recommendation);
      toast.success("AI recommendation generated!");
    } catch (error) {
      console.error("Failed to generate AI recommendation:", error);
      toast.error(`Failed to generate AI recommendation: ${getErrorMessage(error)}`);
    } finally {
      setLoadingAI(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "medium": return "default";
      case "low": return "secondary";
      default: return "outline";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return <XCircle className="h-5 w-5 text-red-500" />;
      case "high": return <AlertTriangle className="h-5 w-5 text-orange-500" />;
      case "medium": return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case "low": return <CheckCircle className="h-5 w-5 text-blue-500" />;
      default: return null;
    }
  };

  const exportToCSV = () => {
    const headers = ["Title", "Severity", "OWASP Category", "File Path", "Line", "Detected By", "Description", "CWE", "Issue Type"];
    const rows = filteredVulns.map(vuln => [
      vuln.title || "",
      vuln.severity || "",
      vuln.owasp_category || "",
      vuln.file_path || "",
      vuln.line_start || "",
      vuln.detected_by || "",
      vuln.description || "",
      vuln.cwe || "",
      vuln.issue_type || "security"
    ]);

    const csvContent = [
      headers.join(","),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(","))
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `scan_${scanId}_export_${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    toast.success("CSV file downloaded!");
  };

  const exportToJSON = () => {
    const exportData = {
      scan_id: scanId,
      export_date: new Date().toISOString(),
      filters: {
        severity: filterSeverity,
        owasp: filterOwasp,
        scanners: filterScanner
      },
      total_issues: filteredVulns.length,
      issues: filteredVulns
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `scan_${scanId}_export_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    toast.success("JSON file downloaded!");
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen">Loading...</div>;
  }

  return (
    <div className="space-y-8">
      <div>
        <Button variant="ghost" onClick={() => navigate(-1)} className="mb-4" data-testid="back-to-repo-btn">
          ← Back
        </Button>
        <h1 className="text-4xl font-bold" data-testid="scan-detail-title">Scan Results</h1>
        <p className="text-muted-foreground mt-2">Detailed vulnerability analysis</p>
      </div>

      {/* Grouped Scan Results Display */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Health Scores Group */}
        <Card className="border-2">
          <CardHeader className="pb-3 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950 rounded-t-lg">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Activity className="h-5 w-5 text-blue-600" />
              Health Scores
            </CardTitle>
            <CardDescription>Overall health metrics (0-100, higher is better)</CardDescription>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div className="text-xs text-muted-foreground mb-1 font-medium">Security</div>
                <div className={`text-2xl font-bold ${(scan?.security_score || 0) >= 70 ? 'text-green-500' : (scan?.security_score || 0) >= 40 ? 'text-yellow-500' : 'text-red-500'}`} data-testid="scan-security-score">
                  {scan?.security_score || 0}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {(scan?.security_score || 0) >= 70 ? '✓ Good' : (scan?.security_score || 0) >= 40 ? '⚠ Fair' : '✗ Poor'}
                </div>
              </div>
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div className="text-xs text-muted-foreground mb-1 font-medium">Quality</div>
                <div className={`text-2xl font-bold ${(scan?.quality_score || 100) >= 70 ? 'text-green-500' : (scan?.quality_score || 100) >= 40 ? 'text-yellow-500' : 'text-red-500'}`}>
                  {scan?.quality_score || 100}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {(scan?.quality_score || 100) >= 70 ? '✓ Good' : (scan?.quality_score || 100) >= 40 ? '⚠ Fair' : '✗ Poor'}
                </div>
              </div>
              <div className="text-center p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div className="text-xs text-muted-foreground mb-1 font-medium">Compliance</div>
                <div className={`text-2xl font-bold ${(scan?.compliance_score || 100) >= 70 ? 'text-green-500' : (scan?.compliance_score || 100) >= 40 ? 'text-yellow-500' : 'text-red-500'}`}>
                  {scan?.compliance_score || 100}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {(scan?.compliance_score || 100) >= 70 ? '✓ Good' : (scan?.compliance_score || 100) >= 40 ? '⚠ Fair' : '✗ Poor'}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Security Issues Group */}
        <Card className="border-2">
          <CardHeader className="pb-3 bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-950 dark:to-orange-950 rounded-t-lg">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-5 w-5 text-red-600" />
              Security Vulnerabilities
            </CardTitle>
            <CardDescription>Issues found that may pose security risks</CardDescription>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm text-muted-foreground">Total Issues Found</span>
              <span className="text-3xl font-bold" data-testid="scan-total-issues">{scan?.vulnerabilities_count || 0}</span>
            </div>
            <div className="grid grid-cols-4 gap-2">
              <div className="text-center p-2 bg-red-50 dark:bg-red-950 rounded-lg border border-red-200 dark:border-red-800">
                <div className="text-xs text-red-600 dark:text-red-400 font-medium">Critical</div>
                <div className="text-xl font-bold text-red-600" data-testid="scan-critical">{scan?.critical_count || 0}</div>
              </div>
              <div className="text-center p-2 bg-orange-50 dark:bg-orange-950 rounded-lg border border-orange-200 dark:border-orange-800">
                <div className="text-xs text-orange-600 dark:text-orange-400 font-medium">High</div>
                <div className="text-xl font-bold text-orange-500" data-testid="scan-high">{scan?.high_count || 0}</div>
              </div>
              <div className="text-center p-2 bg-yellow-50 dark:bg-yellow-950 rounded-lg border border-yellow-200 dark:border-yellow-800">
                <div className="text-xs text-yellow-600 dark:text-yellow-400 font-medium">Medium</div>
                <div className="text-xl font-bold text-yellow-500">{scan?.medium_count || 0}</div>
              </div>
              <div className="text-center p-2 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
                <div className="text-xs text-blue-600 dark:text-blue-400 font-medium">Low</div>
                <div className="text-xl font-bold text-blue-500">{scan?.low_count || 0}</div>
              </div>
            </div>
            {(scan?.critical_count > 0 || scan?.high_count > 0) && (
              <div className="mt-3 p-2 bg-red-100 dark:bg-red-900 rounded text-xs text-red-700 dark:text-red-300 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                {scan?.critical_count > 0 ? 'Critical issues require immediate attention!' : 'High severity issues should be addressed soon.'}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Code Quality Group */}
        <Card className="border-2">
          <CardHeader className="pb-3 bg-gradient-to-r from-purple-50 to-pink-50 dark:from-purple-950 dark:to-pink-950 rounded-t-lg">
            <CardTitle className="flex items-center gap-2 text-lg">
              <FileCode className="h-5 w-5 text-purple-600" />
              Code Quality
            </CardTitle>
            <CardDescription>Code style, maintainability & best practices</CardDescription>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm text-muted-foreground">Quality Issues</span>
              <span className="text-3xl font-bold text-purple-600">{scan?.quality_issues_count ?? qualityIssues.length}</span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between items-center text-sm">
                <span className="text-muted-foreground">Compliance Issues</span>
                <span className="font-medium">{scan?.compliance_issues_count || 0}</span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-muted-foreground">Files Scanned</span>
                <span className="font-medium">{scan?.total_files || 0}</span>
              </div>
              {scan?.repo_stats?.languages && scan.repo_stats.languages.length > 0 && (
                <div className="flex justify-between items-center text-sm">
                  <span className="text-muted-foreground">Languages</span>
                  <span className="font-medium">{scan.repo_stats.languages.join(', ')}</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {scan?.scan_results && Object.keys(scan.scan_results).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Scanner Results
            </CardTitle>
            <CardDescription>Issues found by each security scanner</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(scan.scan_results).map(([scanner, count]) => {
                const isSelected = filterScanner.includes(scanner);
                return (
                  <div
                    key={scanner}
                    className={`flex items-center justify-between p-3 border-2 rounded-lg transition-all ${count > 0 ? 'cursor-pointer hover:border-primary hover:shadow-md' : 'opacity-50'
                      } ${isSelected ? 'border-primary bg-primary/10' : ''}`}
                    onClick={() => {
                      if (count > 0) {
                        setFilterScanner(prev =>
                          isSelected
                            ? prev.filter(s => s !== scanner)
                            : [...prev, scanner]
                        );
                      }
                    }}
                  >
                    <div className="font-medium">{formatScannerName(scanner)}</div>
                    <Badge variant={count > 0 ? "default" : "secondary"}>{count}</Badge>
                  </div>
                );
              })}
            </div>
            {filterScanner.length > 0 && (
              <div className="mt-4 flex items-center gap-2 flex-wrap">
                <span className="text-sm text-muted-foreground">Filtered by:</span>
                {filterScanner.map(scanner => (
                  <Badge key={scanner} variant="outline" className="text-sm">
                    {formatScannerName(scanner)}
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setFilterScanner(prev => prev.filter(s => s !== scanner));
                      }}
                      className="ml-1 hover:text-destructive"
                    >
                      ×
                    </button>
                  </Badge>
                ))}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setFilterScanner([])}
                  className="h-6 px-2 text-xs"
                >
                  Clear all
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <div className="flex gap-4 items-center flex-wrap">
        <Select value={filterSeverity} onValueChange={setFilterSeverity}>
          <SelectTrigger className="w-48" data-testid="filter-severity">
            <SelectValue placeholder="Filter by severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Select value={filterOwasp} onValueChange={setFilterOwasp}>
          <SelectTrigger className="w-64" data-testid="filter-owasp">
            <SelectValue placeholder="Filter by OWASP" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All OWASP Categories</SelectItem>
            <SelectItem value="A01">A01: Broken Access Control</SelectItem>
            <SelectItem value="A02">A02: Cryptographic Failures</SelectItem>
            <SelectItem value="A03">A03: Injection</SelectItem>
            <SelectItem value="A04">A04: Insecure Design</SelectItem>
            <SelectItem value="A05">A05: Security Misconfiguration</SelectItem>
            <SelectItem value="A06">A06: Vulnerable Components</SelectItem>
            <SelectItem value="A07">A07: Auth Failures</SelectItem>
            <SelectItem value="A08">A08: Data Integrity Failures</SelectItem>
            <SelectItem value="A09">A09: Logging Failures</SelectItem>
            <SelectItem value="A10">A10: SSRF</SelectItem>
          </SelectContent>
        </Select>

        <div className="ml-auto flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={exportToCSV}
            className="flex items-center gap-2"
          >
            <FileText className="h-4 w-4" />
            Export CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={exportToJSON}
            className="flex items-center gap-2"
          >
            <FileJson className="h-4 w-4" />
            Export JSON
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Issues ({filteredVulns.length})</CardTitle>
          <CardDescription>Security vulnerabilities, quality issues, and compliance findings</CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            {filteredVulns.map((vuln) => (
              <AccordionItem key={vuln.id} value={vuln.id} data-testid={`vuln-item-${vuln.id}`}>
                <AccordionTrigger>
                  <div className="flex items-center gap-4 w-full">
                    {getSeverityIcon(vuln.severity)}
                    <div className="flex-1 text-left">
                      <div className="font-semibold">{vuln.title}</div>
                      <div className="text-sm text-muted-foreground">{vuln.file_path}:{vuln.line_start}</div>
                    </div>
                    <Badge variant={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                    <Badge variant="outline">{getOwaspCategoryName(vuln.owasp_category)}</Badge>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-4 pt-4">
                    <div>
                      <div className="text-sm font-semibold mb-2">Description</div>
                      <p className="text-sm text-muted-foreground">{vuln.description}</p>
                    </div>

                    <Separator />

                    <div>
                      <div className="text-sm font-semibold mb-2">Code Snippet</div>
                      <pre className="bg-muted p-4 rounded-lg text-xs overflow-x-auto">
                        <code>{vuln.code_snippet}</code>
                      </pre>
                    </div>

                    <Separator />

                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Detected by:</span>
                        <span className="ml-2 font-medium">{vuln.detected_by}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">OWASP:</span>
                        <span className="ml-2 font-medium">{getOwaspCategoryName(vuln.owasp_category)}</span>
                      </div>
                      {vuln.cwe && (
                        <div>
                          <span className="text-muted-foreground">CWE:</span>
                          <span className="ml-2 font-medium">{vuln.cwe}</span>
                        </div>
                      )}
                      {vuln.cvss_score && (
                        <div>
                          <span className="text-muted-foreground">CVSS:</span>
                          <span className="ml-2 font-medium">{vuln.cvss_score}</span>
                        </div>
                      )}
                    </div>

                    <Separator />

                    <div className="space-y-3">
                      <div className="flex gap-3">
                        <Select value={selectedProvider} onValueChange={setSelectedProvider}>
                          <SelectTrigger className="w-40" data-testid="ai-provider-select">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="openai">OpenAI</SelectItem>
                            <SelectItem value="anthropic">Claude</SelectItem>
                            <SelectItem value="gemini">Gemini</SelectItem>
                          </SelectContent>
                        </Select>

                        <Select value={selectedModel} onValueChange={setSelectedModel}>
                          <SelectTrigger className="w-48" data-testid="ai-model-select">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {selectedProvider === "openai" && (
                              <>
                                <SelectItem value="gpt-4o-mini">GPT-4o Mini</SelectItem>
                              </>
                            )}
                            {selectedProvider === "anthropic" && (
                              <>
                                <SelectItem value="claude-3-7-sonnet-20250219">Claude Sonnet 3.7</SelectItem>
                              </>
                            )}
                            {selectedProvider === "gemini" && (
                              <>
                                <SelectItem value="gemini-2.0-flash">Gemini 2.0 Flash</SelectItem>
                              </>
                            )}
                          </SelectContent>
                        </Select>

                        <Button
                          onClick={() => getAIRecommendation(vuln)}
                          disabled={loadingAI}
                          data-testid={`ai-fix-btn-${vuln.id}`}
                        >
                          {loadingAI ? (
                            <Clock className="mr-2 h-4 w-4 animate-spin" />
                          ) : (
                            <Sparkles className="mr-2 h-4 w-4" />
                          )}
                          Get AI Fix
                        </Button>
                      </div>

                      {selectedVuln?.id === vuln.id && aiRecommendation && (
                        <Card className="bg-muted/50">
                          <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                              <Sparkles className="h-5 w-5" />
                              AI-Powered Fix Recommendation
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="prose prose-sm max-w-none" data-testid="ai-recommendation">
                              <pre className="whitespace-pre-wrap text-sm">{aiRecommendation}</pre>
                            </div>
                          </CardContent>
                        </Card>
                      )}
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>
    </div>
  );
};

const SettingsPage = () => {
  const [apiKeys, setApiKeys] = useState({
    openai_api_key: "",
    anthropic_api_key: "",
    gemini_api_key: "",
    github_token: "",
    snyk_token: ""
  });
  const [apiKeyStatus, setApiKeyStatus] = useState({});
  const [aiScannerSettings, setAiScannerSettings] = useState({
    enable_zero_day_detector: true,
    enable_business_logic_scanner: true,
    enable_llm_security_scanner: true,
    enable_auth_scanner: true
  });
  const [scanners, setScanners] = useState({});
  const [scannerConfig, setScannerConfig] = useState(() => {
    const saved = localStorage.getItem("scannerConfig");
    return saved ? JSON.parse(saved) : {};
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingAiSettings, setSavingAiSettings] = useState(false);

  // Git Integrations State
  const [gitIntegrations, setGitIntegrations] = useState([]);
  const [showConnectModal, setShowConnectModal] = useState(false);
  const [connectingProvider, setConnectingProvider] = useState(null);
  const [newIntegration, setNewIntegration] = useState({
    provider: "github",
    name: "",
    access_token: "",
    base_url: ""
  });
  const [connectedRepos, setConnectedRepos] = useState([]);
  const [remoteRepos, setRemoteRepos] = useState([]);
  const [remoteReposProvider, setRemoteReposProvider] = useState(null);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [repoSearchQuery, setRepoSearchQuery] = useState("");

  useEffect(() => {
    fetchSettings();
  }, []);

  useEffect(() => {
    localStorage.setItem("scannerConfig", JSON.stringify(scannerConfig));
  }, [scannerConfig]);

  const fetchSettings = async () => {
    try {
      const [settingsRes, scannersRes, aiScannersRes, integrationsRes, reposRes] = await Promise.all([
        axios.get(`${API}/settings`),
        axios.get(`${API}/settings/scanners`),
        axios.get(`${API}/settings/ai-scanners`).catch(() => ({ data: {
          enable_zero_day_detector: true,
          enable_business_logic_scanner: true,
          enable_llm_security_scanner: true,
          enable_auth_scanner: false
        }})),
        axios.get(`${API}/integrations/git`).catch(() => ({ data: { integrations: [] } })),
        axios.get(`${API}/repositories`).catch(() => ({ data: { repositories: [] } }))
      ]);
      setApiKeyStatus(settingsRes.data.llm_api_keys || {});
      setAiScannerSettings(aiScannersRes.data);
      setScanners(scannersRes.data);
      setGitIntegrations(integrationsRes.data.integrations || []);
      setConnectedRepos(reposRes.data.repositories || []);

      // Load scanner enabled/disabled state from backend scanner_settings
      const backendScannerSettings = settingsRes.data.scanner_settings || {};

      // Merge backend settings with scanner list (backend settings take precedence)
      const initialConfig = {};
      Object.keys(scannersRes.data).forEach(key => {
        // Use backend setting if available, otherwise default to true
        if (backendScannerSettings[key] !== undefined) {
          initialConfig[key] = backendScannerSettings[key];
        } else {
          initialConfig[key] = true; // Default enabled if not set in backend
        }
      });
      setScannerConfig(initialConfig);
    } catch (error) {
      console.error("Failed to fetch settings:", error);
      toast.error("Failed to load settings");
    } finally {
      setLoading(false);
    }
  };

  // Git Integration Functions
  const connectGitProvider = async () => {
    if (!newIntegration.name || !newIntegration.access_token) {
      toast.error("Please provide a name and access token");
      return;
    }

    setConnectingProvider(newIntegration.provider);
    try {
      await axios.post(`${API}/integrations/git/connect`, {
        provider: newIntegration.provider,
        name: newIntegration.name,
        access_token: newIntegration.access_token,
        base_url: newIntegration.base_url || null
      });
      toast.success(`Connected to ${newIntegration.provider}!`);
      setShowConnectModal(false);
      setNewIntegration({ provider: "github", name: "", access_token: "", base_url: "" });
      fetchSettings();
    } catch (error) {
      toast.error(getErrorMessage(error) || "Failed to connect");
    } finally {
      setConnectingProvider(null);
    }
  };

  const disconnectGitProvider = async (provider, name) => {
    if (!window.confirm(`Disconnect ${provider}? This will remove all associated repositories.`)) return;

    try {
      await axios.delete(`${API}/integrations/git/${provider}?name=${encodeURIComponent(name)}`);
      toast.success(`Disconnected from ${provider}`);
      fetchSettings();
    } catch (error) {
      toast.error(getErrorMessage(error) || "Failed to disconnect");
    }
  };

  const fetchRemoteRepos = async (provider) => {
    setLoadingRepos(true);
    try {
      const res = await axios.get(`${API}/integrations/git/${provider}/repositories`);
      setRemoteRepos(res.data.repositories || []);
      setRemoteReposProvider(provider);
    } catch (error) {
      toast.error("Failed to fetch repositories");
    } finally {
      setLoadingRepos(false);
    }
  };

  const addRepository = async (provider, repoUrl, isPrivate = false) => {
    try {
      await axios.post(`${API}/repositories`, {
        provider,
        repo_url: repoUrl,
        auto_scan: false,
        is_public: !isPrivate
      });
      toast.success("Repository added!");
      fetchSettings();
    } catch (error) {
      toast.error(getErrorMessage(error) || "Failed to add repository");
    }
  };

  const removeRepository = async (repoId) => {
    if (!window.confirm("Remove this repository?")) return;

    try {
      await axios.delete(`${API}/repositories/${repoId}`);
      toast.success("Repository removed");
      fetchSettings();
    } catch (error) {
      toast.error("Failed to remove repository");
    }
  };

  const toggleScanner = async (scannerKey) => {
    const newValue = !scannerConfig[scannerKey];

    // Optimistically update the UI
    setScannerConfig(prev => ({
      ...prev,
      [scannerKey]: newValue
    }));

    try {
      // Save to backend
      await axios.put(`${API}/settings/scanners`, {
        [scannerKey]: newValue
      });
      toast.success(`Scanner ${newValue ? 'enabled' : 'disabled'}`);
    } catch (error) {
      // Revert on error
      setScannerConfig(prev => ({
        ...prev,
        [scannerKey]: !newValue
      }));
      toast.error(`Failed to update scanner setting: ${getErrorMessage(error)}`);
    }
  };

  const toggleAllScanners = async (enable) => {
    const newConfig = {};
    const updatePayload = {};

    Object.keys(scanners).forEach(key => {
      if (scanners[key].installed) {
        newConfig[key] = enable;
        updatePayload[key] = enable;
      } else {
        newConfig[key] = scannerConfig[key] || false; // Keep non-installed scanners as-is
      }
    });

    // Optimistically update the UI
    setScannerConfig(newConfig);

    try {
      // Save to backend
      await axios.put(`${API}/settings/scanners`, updatePayload);
      toast.success(`All installed scanners ${enable ? 'enabled' : 'disabled'}`);
    } catch (error) {
      // Revert on error - refetch settings
      fetchSettings();
      toast.error(`Failed to update scanner settings: ${getErrorMessage(error)}`);
    }
  };

  // Check if all installed scanners are enabled
  const allEnabled = Object.keys(scanners).every(key =>
    !scanners[key].installed || scannerConfig[key]
  );

  const saveApiKeys = async () => {
    setSaving(true);
    try {
      const keysToUpdate = {};
      if (apiKeys.openai_api_key) keysToUpdate.openai_api_key = apiKeys.openai_api_key;
      if (apiKeys.anthropic_api_key) keysToUpdate.anthropic_api_key = apiKeys.anthropic_api_key;
      if (apiKeys.gemini_api_key) keysToUpdate.gemini_api_key = apiKeys.gemini_api_key;
      if (apiKeys.github_token) keysToUpdate.github_token = apiKeys.github_token;
      if (apiKeys.snyk_token) keysToUpdate.snyk_token = apiKeys.snyk_token;

      if (Object.keys(keysToUpdate).length === 0) {
        toast.error("Please enter at least one API key or token");
        return;
      }

      await axios.post(`${API}/settings/api-keys`, keysToUpdate);

      toast.success("API keys saved successfully!");
      setApiKeys({
        openai_api_key: "",
        anthropic_api_key: "",
        gemini_api_key: "",
        github_token: "",
        snyk_token: ""
      });
      fetchSettings();
    } catch (error) {
      console.error("Failed to save API keys:", error);
      toast.error(`Failed to save API keys: ${getErrorMessage(error)}`);
    } finally {
      setSaving(false);
    }
  };

  const deleteApiKey = async (keyName) => {
    if (!window.confirm(`Are you sure you want to delete this ${keyName.replace('_', ' ')}?`)) {
      return;
    }
    try {
      // Send empty string to delete the key
      const deletePayload = {};
      deletePayload[keyName] = "";
      await axios.post(`${API}/settings/api-keys`, deletePayload);

      toast.success(`${keyName.replace('_', ' ')} deleted!`);
      fetchSettings();
    } catch (error) {
      console.error("Failed to delete API key:", error);
      toast.error(`Failed to delete API key: ${getErrorMessage(error)}`);
    }
  };

  const saveAiScannerSettings = async () => {
    setSavingAiSettings(true);
    try {
      await axios.post(`${API}/settings/ai-scanners`, aiScannerSettings);
      toast.success("AI scanner settings saved successfully!");
      fetchSettings();
    } catch (error) {
      console.error("Failed to save AI scanner settings:", error);
      toast.error(`Failed to save AI scanner settings: ${getErrorMessage(error)}`);
    } finally {
      setSavingAiSettings(false);
    }
  };

  const toggleAiScanner = (scannerKey) => {
    setAiScannerSettings(prev => ({
      ...prev,
      [scannerKey]: !prev[scannerKey]
    }));
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen">Loading settings...</div>;
  }

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div>
        <h1 className="text-4xl font-bold" data-testid="settings-title">Settings</h1>
        <p className="text-muted-foreground mt-2">Configure API keys and view scanner status</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            API Keys & Tokens
          </CardTitle>
          <CardDescription>
            Configure API keys for AI-powered features and scanner integrations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="font-semibold text-sm text-muted-foreground">LLM API Keys</div>

            <div className="space-y-2">
              <Label htmlFor="openai">OpenAI API Key</Label>
              <div className="flex gap-2">
                <Input
                  id="openai"
                  type="password"
                  placeholder={apiKeyStatus.openai_api_key ? "••••••••••••••••" : "sk-..."}
                  value={apiKeys.openai_api_key}
                  onChange={(e) => setApiKeys({ ...apiKeys, openai_api_key: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.openai_api_key && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("openai_api_key")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.openai_api_key ? (
                  <><CheckCircle className="h-4 w-4 text-green-500" /> Configured</>
                ) : (
                  <><XCircle className="h-4 w-4 text-red-500" /> Not configured</>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="anthropic">Anthropic (Claude) API Key</Label>
              <div className="flex gap-2">
                <Input
                  id="anthropic"
                  type="password"
                  placeholder={apiKeyStatus.anthropic_api_key ? "••••••••••••••••" : "sk-ant-..."}
                  value={apiKeys.anthropic_api_key}
                  onChange={(e) => setApiKeys({ ...apiKeys, anthropic_api_key: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.anthropic_api_key && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("anthropic_api_key")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.anthropic_api_key ? (
                  <><CheckCircle className="h-4 w-4 text-green-500" /> Configured</>
                ) : (
                  <><XCircle className="h-4 w-4 text-red-500" /> Not configured</>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="gemini">Google Gemini API Key</Label>
              <div className="flex gap-2">
                <Input
                  id="gemini"
                  type="password"
                  placeholder={apiKeyStatus.gemini_api_key ? "••••••••••••••••" : "AIza..."}
                  value={apiKeys.gemini_api_key}
                  onChange={(e) => setApiKeys({ ...apiKeys, gemini_api_key: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.gemini_api_key && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("gemini_api_key")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.gemini_api_key ? (
                  <><CheckCircle className="h-4 w-4 text-green-500" /> Configured</>
                ) : (
                  <><XCircle className="h-4 w-4 text-red-500" /> Not configured</>
                )}
              </div>
            </div>

            <Separator className="my-4" />
            <div className="font-semibold text-sm text-muted-foreground">Scanner Tokens</div>

            <div className="space-y-2">
              <Label htmlFor="snyk">Snyk Token</Label>
              <div className="flex gap-2">
                <Input
                  id="snyk"
                  type="password"
                  placeholder={apiKeyStatus.snyk_token ? "••••••••••••••••" : "Enter Snyk token..."}
                  value={apiKeys.snyk_token}
                  onChange={(e) => setApiKeys({ ...apiKeys, snyk_token: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.snyk_token && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("snyk_token")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.snyk_token ? (
                  <><CheckCircle className="h-4 w-4 text-green-500" /> Configured</>
                ) : (
                  <><XCircle className="h-4 w-4 text-gray-400" /> Optional - for Snyk scanner</>
                )}
              </div>
            </div>
          </div>

          <Button onClick={saveApiKeys} disabled={saving} className="w-full">
            {saving ? "Saving..." : "Save API Keys"}
          </Button>
        </CardContent>
      </Card>

      {/* AI Scanner Settings Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5" />
            AI-Powered Scanners
          </CardTitle>
          <CardDescription>
            Enable or disable AI-powered security scanners
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex-1">
                <div className="font-medium">Zero-Day Detector</div>
                <div className="text-sm text-muted-foreground">
                  ML-based anomaly detection for unknown vulnerabilities
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={aiScannerSettings.enable_zero_day_detector ? "default" : "secondary"}>
                  {aiScannerSettings.enable_zero_day_detector ? "Enabled" : "Disabled"}
                </Badge>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => toggleAiScanner("enable_zero_day_detector")}
                >
                  {aiScannerSettings.enable_zero_day_detector ? "Disable" : "Enable"}
                </Button>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex-1">
                <div className="font-medium">Business Logic Scanner</div>
                <div className="text-sm text-muted-foreground">
                  Detects IDOR, workflow bypasses, race conditions, and logic flaws
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={aiScannerSettings.enable_business_logic_scanner ? "default" : "secondary"}>
                  {aiScannerSettings.enable_business_logic_scanner ? "Enabled" : "Disabled"}
                </Badge>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => toggleAiScanner("enable_business_logic_scanner")}
                >
                  {aiScannerSettings.enable_business_logic_scanner ? "Disable" : "Enable"}
                </Button>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex-1">
                <div className="font-medium">LLM Security Scanner</div>
                <div className="text-sm text-muted-foreground">
                  Tests for prompt injection, jailbreaks, and AI security vulnerabilities
                </div>
                {(!apiKeyStatus.openai_api_key && !apiKeyStatus.anthropic_api_key && !apiKeyStatus.gemini_api_key) && (
                  <div className="text-xs text-yellow-600 mt-1">
                    ⚠️ Requires at least one LLM API key configured above
                  </div>
                )}
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={
                  aiScannerSettings.enable_llm_security_scanner
                    ? (apiKeyStatus.openai_api_key || apiKeyStatus.anthropic_api_key || apiKeyStatus.gemini_api_key)
                      ? "default"
                      : "outline"
                    : "secondary"
                } className={
                  aiScannerSettings.enable_llm_security_scanner &&
                  !(apiKeyStatus.openai_api_key || apiKeyStatus.anthropic_api_key || apiKeyStatus.gemini_api_key)
                    ? "border-amber-500 text-amber-600"
                    : ""
                }>
                  {aiScannerSettings.enable_llm_security_scanner
                    ? (apiKeyStatus.openai_api_key || apiKeyStatus.anthropic_api_key || apiKeyStatus.gemini_api_key)
                      ? "Enabled"
                      : "Needs API Key"
                    : "Disabled"}
                </Badge>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => toggleAiScanner("enable_llm_security_scanner")}
                >
                  {aiScannerSettings.enable_llm_security_scanner ? "Disable" : "Enable"}
                </Button>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex-1">
                <div className="font-medium">Auth Scanner</div>
                <div className="text-sm text-muted-foreground">
                  Detects authentication and authorization vulnerabilities
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={aiScannerSettings.enable_auth_scanner ? "default" : "secondary"}>
                  {aiScannerSettings.enable_auth_scanner ? "Enabled" : "Disabled"}
                </Badge>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => toggleAiScanner("enable_auth_scanner")}
                >
                  {aiScannerSettings.enable_auth_scanner ? "Disable" : "Enable"}
                </Button>
              </div>
            </div>
          </div>

          <Button onClick={saveAiScannerSettings} disabled={savingAiSettings} className="w-full">
            {savingAiSettings ? "Saving..." : "Save AI Scanner Settings"}
          </Button>
        </CardContent>
      </Card>

      {/* Git Integrations Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-5 w-5" />
            Git Integrations
          </CardTitle>
          <CardDescription>
            Connect GitHub or GitLab to scan repositories directly from your account
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Connected Integrations */}
          <div className="space-y-4">
            <div className="font-semibold text-sm text-muted-foreground">Connected Providers</div>

            {gitIntegrations.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground border-2 border-dashed rounded-lg">
                <Github className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No Git providers connected</p>
                <p className="text-sm">Connect GitHub or GitLab to scan your repositories</p>
              </div>
            ) : (
              <div className="space-y-3">
                {gitIntegrations.map((integration, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                        {integration.provider === "github" ? (
                          <Github className="h-5 w-5" />
                        ) : (
                          <GitBranch className="h-5 w-5" />
                        )}
                      </div>
                      <div>
                        <div className="font-medium">{integration.name}</div>
                        <div className="text-sm text-muted-foreground flex items-center gap-2">
                          <span className="capitalize">{integration.provider}</span>
                          {integration.username && (
                            <>
                              <span>•</span>
                              <span>@{integration.username}</span>
                            </>
                          )}
                          {integration.is_connected && (
                            <Badge variant="outline" className="text-green-600 border-green-600">
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Connected
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => fetchRemoteRepos(integration.provider)}
                      >
                        <RefreshCw className={`h-4 w-4 mr-1 ${loadingRepos ? 'animate-spin' : ''}`} />
                        Repos
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => disconnectGitProvider(integration.provider, integration.name)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Connect New Provider Buttons */}
            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => {
                  setNewIntegration({ ...newIntegration, provider: "github", name: "My GitHub" });
                  setShowConnectModal(true);
                }}
                disabled={gitIntegrations.some(i => i.provider === "github")}
              >
                <Github className="h-4 w-4 mr-2" />
                Connect GitHub
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setNewIntegration({ ...newIntegration, provider: "gitlab", name: "My GitLab" });
                  setShowConnectModal(true);
                }}
                disabled={gitIntegrations.some(i => i.provider === "gitlab")}
              >
                <GitBranch className="h-4 w-4 mr-2" />
                Connect GitLab
              </Button>
            </div>
          </div>

          {/* Connect Modal */}
          {showConnectModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <Card className="w-full max-w-md">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {newIntegration.provider === "github" ? <Github className="h-5 w-5" /> : <GitBranch className="h-5 w-5" />}
                    Connect {newIntegration.provider === "github" ? "GitHub" : "GitLab"}
                  </CardTitle>
                  <CardDescription>
                    Enter your personal access token to connect
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="int-name">Integration Name</Label>
                    <Input
                      id="int-name"
                      placeholder="My GitHub Account"
                      value={newIntegration.name}
                      onChange={(e) => setNewIntegration({ ...newIntegration, name: e.target.value })}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="int-token">Personal Access Token</Label>
                    <Input
                      id="int-token"
                      type="password"
                      placeholder={newIntegration.provider === "github" ? "ghp_..." : "glpat-..."}
                      value={newIntegration.access_token}
                      onChange={(e) => setNewIntegration({ ...newIntegration, access_token: e.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">
                      {newIntegration.provider === "github" ? (
                        <>Generate at <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer" className="text-primary underline">GitHub Settings → Tokens</a></>
                      ) : (
                        <>Generate at <a href="https://gitlab.com/-/profile/personal_access_tokens" target="_blank" rel="noopener noreferrer" className="text-primary underline">GitLab Settings → Access Tokens</a></>
                      )}
                    </p>
                  </div>

                  {newIntegration.provider === "gitlab" && (
                    <div className="space-y-2">
                      <Label htmlFor="int-url">GitLab URL (optional, for self-hosted)</Label>
                      <Input
                        id="int-url"
                        placeholder="https://gitlab.company.com"
                        value={newIntegration.base_url}
                        onChange={(e) => setNewIntegration({ ...newIntegration, base_url: e.target.value })}
                      />
                    </div>
                  )}

                  <div className="flex gap-3 pt-4">
                    <Button variant="outline" className="flex-1" onClick={() => setShowConnectModal(false)}>
                      Cancel
                    </Button>
                    <Button
                      className="flex-1"
                      onClick={connectGitProvider}
                      disabled={connectingProvider}
                    >
                      {connectingProvider ? "Connecting..." : "Connect"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          <Separator />

          {/* Connected Repositories */}
          <div className="space-y-4">
            <div className="font-semibold text-sm text-muted-foreground">Connected Repositories</div>

            {connectedRepos.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No repositories connected. Use the "Repos" button above to browse and add repositories.
              </p>
            ) : (
              <div className="space-y-2">
                {connectedRepos.map((repo, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <GitBranch className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <div className="font-medium">{repo.full_name}</div>
                        <div className="text-xs text-muted-foreground">
                          {repo.default_branch} • {repo.private ? "Private" : "Public"}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" asChild>
                        <a href={repo.clone_url.replace('.git', '')} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                      <Button variant="destructive" size="sm" onClick={() => removeRepository(repo.repo_id)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Remote Repositories Browser */}
          {remoteRepos.length > 0 && (
            <>
              <Separator />
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-sm text-muted-foreground">
                    Available {remoteReposProvider === "gitlab" ? "GitLab" : "GitHub"} Repositories ({remoteRepos.length})
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => { setRemoteRepos([]); setRepoSearchQuery(""); setRemoteReposProvider(null); }}>
                    <XCircle className="h-4 w-4 mr-1" /> Close
                  </Button>
                </div>
                {/* Search Input */}
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search repositories..."
                    value={repoSearchQuery}
                    onChange={(e) => setRepoSearchQuery(e.target.value)}
                    className="pl-9"
                  />
                </div>
                <div className="max-h-64 overflow-y-auto space-y-2">
                  {remoteRepos
                    .filter(repo =>
                      repoSearchQuery === "" ||
                      repo.full_name.toLowerCase().includes(repoSearchQuery.toLowerCase()) ||
                      (repo.language && repo.language.toLowerCase().includes(repoSearchQuery.toLowerCase()))
                    )
                    .map((repo, idx) => (
                    <div key={idx} className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50">
                      <div>
                        <div className="font-medium">{repo.full_name}</div>
                        <div className="text-xs text-muted-foreground">
                          {repo.language || "Unknown"} • {repo.private ? "Private" : "Public"}
                        </div>
                      </div>
                      <Button
                        size="sm"
                        onClick={() => addRepository(
                          remoteReposProvider || "github",
                          repo.clone_url || (remoteReposProvider === "gitlab"
                            ? `https://gitlab.com/${repo.full_name}`
                            : `https://github.com/${repo.full_name}`),
                          repo.private
                        )}
                        disabled={connectedRepos.some(r => r.full_name === repo.full_name)}
                      >
                        {connectedRepos.some(r => r.full_name === repo.full_name) ? (
                          <CheckCircle className="h-4 w-4" />
                        ) : (
                          <>
                            <Plus className="h-4 w-4 mr-1" /> Add
                          </>
                        )}
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security Scanners
          </CardTitle>
          <CardDescription>
            Status of installed security scanning tools - Enable or disable scanners for your scans
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Master Enable/Disable Toggle */}
          <div className="flex items-center justify-between p-4 bg-primary/5 border-2 border-primary/20 rounded-lg">
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <div className="font-semibold text-lg">Master Control</div>
                <Badge variant="outline" className="text-xs">
                  {Object.keys(scanners).filter(k => scanners[k].installed).length} Installed
                </Badge>
              </div>
              <div className="text-sm text-muted-foreground mt-1">
                Enable or disable all installed scanners at once
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium">
                {allEnabled ? "All Enabled" : "Some Disabled"}
              </span>
              <Switch
                checked={allEnabled}
                onCheckedChange={toggleAllScanners}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {Object.entries(scanners).map(([key, scanner]) => (
              <div key={key} className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <div className="font-medium">{scanner.name}</div>
                    <Badge variant={scanner.installed ? "default" : "destructive"} className="text-xs">
                      {scanner.installed ? "Installed" : "Not Installed"}
                    </Badge>
                  </div>
                  <div className="text-sm text-muted-foreground mt-1">{scanner.type}</div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm text-muted-foreground">
                    {scannerConfig[key] ? "Enabled" : "Disabled"}
                  </span>
                  <Switch
                    checked={scannerConfig[key] || false}
                    onCheckedChange={() => toggleScanner(key)}
                    disabled={!scanner.installed}
                  />
                </div>
              </div>
            ))}
          </div>
          <p className="text-sm text-muted-foreground">
            <strong>Note:</strong> Only enabled and installed scanners will be used during security scans.
            Disabled scanners will be skipped. Check the README for installation instructions.
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

const Layout = ({ children }) => {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b sticky top-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2" data-testid="logo-link">
              <img src="/fortKnoxx.png" alt="FortKnoxx Logo" className="h-13 w-13" style={{ height: '64px', width: '64px' }} />
              <span className="flex items-baseline gap-1">
                <span className="font-bold" style={{ fontSize: '35px' }}>FortKnoxx</span>
                <span className="italic font-normal" style={{ fontSize: '24px' }}>- Security Intelligence Platform</span>
              </span>
            </Link>
            <nav className="flex items-center gap-6">
              <Link to="/" className="text-sm font-medium hover:text-primary transition-colors" data-testid="nav-dashboard">
                Dashboard
              </Link>
              <Link to="/add-repository" className="text-sm font-medium hover:text-primary transition-colors" data-testid="nav-add-repo">
                Add Repository
              </Link>
              <a href="/help.html" target="_blank" rel="noopener noreferrer" className="text-sm font-medium hover:text-primary transition-colors flex items-center gap-1" data-testid="nav-help">
                <HelpCircle className="h-5 w-5" />
                Help
              </a>
              <a href={`${process.env.REACT_APP_BACKEND_URL}/docs`} target="_blank" rel="noopener noreferrer" className="text-sm font-medium hover:text-primary transition-colors flex items-center gap-1" data-testid="nav-api-docs">
                <FileCode className="h-5 w-5" />
                API Docs
              </a>
              <Link to="/settings" className="text-sm font-medium hover:text-primary transition-colors" data-testid="nav-settings">
                <Settings className="h-5 w-5" />
              </Link>
            </nav>
          </div>
        </div>
      </header>
      <main className="container mx-auto px-6 py-8">
        {children}
      </main>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <Toaster position="top-right" />
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/add-repository" element={<AddRepository />} />
            <Route path="/repository/:repoId" element={<RepositoryDetail />} />
            <Route path="/scan/:scanId" element={<ScanDetail />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </div>
  );
}

export default App;
