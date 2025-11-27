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
import { Shield, Search, FileCode, Activity, AlertTriangle, CheckCircle, XCircle, Clock, TrendingUp, Database, GitBranch, Sparkles, Settings, Trash2, Key, Download, FileJson, FileText } from "lucide-react";

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

// Helper function to truncate text
const truncateText = (text, maxLength) => {
  if (!text) return "";
  return text.length > maxLength ? text.substring(0, maxLength) + "..." : text;
};

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchRepositories();
  }, []);

  const fetchRepositories = async () => {
    try {
      const response = await axios.get(`${API}/repositories`);
      setRepositories(response.data);
    } catch (error) {
      console.error("Failed to fetch repositories:", error);
      toast.error(`Failed to fetch repositories: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
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
      toast.error(`Failed to delete repository: ${error.response?.data?.detail || error.message}`);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-4xl font-bold" data-testid="dashboard-title">Security Dashboard</h1>
          <p className="text-muted-foreground mt-2">Monitor and manage repository security scans</p>
        </div>
        <Button onClick={() => navigate("/add-repository")} size="lg" data-testid="add-repo-btn">
          <Database className="mr-2 h-5 w-5" />
          Add Repository
        </Button>
      </div>

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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {repositories.map((repo) => (
            <Card key={repo.id} className="hover:shadow-lg hover:scale-105 transition-all duration-300 cursor-pointer border-2 hover:border-primary" onClick={() => navigate(`/repository/${repo.id}`)} data-testid={`repo-card-${repo.id}`}>
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
    branch: "main"
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API}/repositories`, formData);
      toast.success("Repository added successfully!");
      navigate(`/repository/${response.data.id}`);
    } catch (error) {
      console.error("Failed to add repository:", error);
      toast.error(`Failed to add repository: ${error.response?.data?.detail || error.message}`);
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
              <Label htmlFor="name">Repository Name</Label>
              <Input
                id="name"
                data-testid="repo-name-input"
                placeholder="my-awesome-project"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
              />
            </div>

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
            </div>

            <div className="space-y-2">
              <Label htmlFor="token">Access Token</Label>
              <Input
                id="token"
                data-testid="repo-token-input"
                type="password"
                placeholder="ghp_xxxxxxxxxxxx"
                value={formData.access_token}
                onChange={(e) => setFormData({ ...formData, access_token: e.target.value })}
                required
              />
              <p className="text-xs text-muted-foreground">Personal Access Token with repo access</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="branch">Branch</Label>
              <Input
                id="branch"
                data-testid="repo-branch-input"
                placeholder="main"
                value={formData.branch}
                onChange={(e) => setFormData({ ...formData, branch: e.target.value })}
              />
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
    } catch (error) {
      console.error("Failed to fetch repository data:", error);
      toast.error(`Failed to fetch repository data: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const startScan = async () => {
    setScanning(true);
    try {
      await axios.post(`${API}/scans/${repoId}`);
      toast.success("Scan started successfully!");
      setTimeout(fetchRepositoryData, 2000);
    } catch (error) {
      console.error("Failed to start scan:", error);
      toast.error(`Failed to start scan: ${error.response?.data?.detail || error.message}`);
    } finally {
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
      toast.error(`Failed to delete scan: ${error.response?.data?.detail || error.message}`);
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
                  Running comprehensive security analysis with 26 professional scanning tools across all code, dependencies, secrets, and infrastructure...
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
      "gemini-2.5-pro": "gemini-2.0-flash"
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
  }, [vulnerabilities, filterSeverity, filterOwasp, filterScanner]);

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
      toast.error(`Failed to fetch scan data: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
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
      allIssues = allIssues.filter(v =>
        filterScanner.some(scanner => v.detected_by?.toLowerCase() === scanner.toLowerCase())
      );
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
      toast.error(`Failed to generate AI recommendation: ${error.response?.data?.detail || error.message}`);
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

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Security</CardDescription>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${(scan?.security_score || 0) >= 70 ? 'text-green-500' : (scan?.security_score || 0) >= 40 ? 'text-yellow-500' : 'text-red-500'}`} data-testid="scan-security-score">
              {scan?.security_score || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Quality</CardDescription>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${(scan.quality_score || 100) >= 70 ? 'text-green-500' : (scan.quality_score || 100) >= 40 ? 'text-yellow-500' : 'text-red-500'}`}>
              {scan.quality_score || 100}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Compliance</CardDescription>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${(scan.compliance_score || 100) >= 70 ? 'text-green-500' : (scan.compliance_score || 100) >= 40 ? 'text-yellow-500' : 'text-red-500'}`}>
              {scan.compliance_score || 100}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Vulnerabilities</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="scan-total-issues">{scan.vulnerabilities_count}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Critical</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500" data-testid="scan-critical">{scan.critical_count}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>High</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500" data-testid="scan-high">{scan.high_count}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Quality Issues</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-500">{scan.quality_issues_count || qualityIssues.length}</div>
          </CardContent>
        </Card>
      </div>

      {scan.scan_results && Object.keys(scan.scan_results).length > 0 && (
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
                    <div className="capitalize font-medium">{scanner}</div>
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
                    {scanner}
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
          <CardTitle>Vulnerabilities ({filteredVulns.length})</CardTitle>
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
                                <SelectItem value="gemini-2.0-flash">Gemini 2.5 Flash</SelectItem>
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
    openai_key: "",
    anthropic_key: "",
    gemini_key: ""
  });
  const [apiKeyStatus, setApiKeyStatus] = useState({});
  const [scanners, setScanners] = useState({});
  const [scannerConfig, setScannerConfig] = useState(() => {
    const saved = localStorage.getItem("scannerConfig");
    return saved ? JSON.parse(saved) : {};
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchSettings();
  }, []);

  useEffect(() => {
    localStorage.setItem("scannerConfig", JSON.stringify(scannerConfig));
  }, [scannerConfig]);

  const fetchSettings = async () => {
    try {
      const [keysRes, scannersRes] = await Promise.all([
        axios.get(`${API}/settings/api-keys`),
        axios.get(`${API}/settings/scanners`)
      ]);
      setApiKeyStatus(keysRes.data);
      setScanners(scannersRes.data);

      // Initialize scanner config if not already set
      const savedConfig = localStorage.getItem("scannerConfig");
      if (!savedConfig || Object.keys(JSON.parse(savedConfig)).length === 0) {
        const initialConfig = {};
        Object.keys(scannersRes.data).forEach(key => {
          initialConfig[key] = true; // All enabled by default
        });
        setScannerConfig(initialConfig);
      }
    } catch (error) {
      console.error("Failed to fetch settings:", error);
      toast.error("Failed to load settings");
    } finally {
      setLoading(false);
    }
  };

  const toggleScanner = (scannerKey) => {
    setScannerConfig(prev => ({
      ...prev,
      [scannerKey]: !prev[scannerKey]
    }));
    toast.success(`Scanner ${scannerConfig[scannerKey] ? 'disabled' : 'enabled'}`);
  };

  const toggleAllScanners = (enable) => {
    const newConfig = {};
    Object.keys(scanners).forEach(key => {
      if (scanners[key].installed) {
        newConfig[key] = enable;
      } else {
        newConfig[key] = scannerConfig[key] || false; // Keep non-installed scanners as-is
      }
    });
    setScannerConfig(newConfig);
    toast.success(`All installed scanners ${enable ? 'enabled' : 'disabled'}`);
  };

  // Check if all installed scanners are enabled
  const allEnabled = Object.keys(scanners).every(key =>
    !scanners[key].installed || scannerConfig[key]
  );

  const saveApiKeys = async () => {
    setSaving(true);
    try {
      const keysToUpdate = {};
      if (apiKeys.openai_key) keysToUpdate.openai_key = apiKeys.openai_key;
      if (apiKeys.anthropic_key) keysToUpdate.anthropic_key = apiKeys.anthropic_key;
      if (apiKeys.gemini_key) keysToUpdate.gemini_key = apiKeys.gemini_key;

      if (Object.keys(keysToUpdate).length === 0) {
        toast.error("Please enter at least one API key");
        return;
      }

      await axios.post(`${API}/settings/api-keys`, keysToUpdate);

      // Also save to localStorage for persistence
      Object.entries(keysToUpdate).forEach(([key, value]) => {
        if (value) {
          localStorage.setItem(key, value);
        }
      });

      toast.success("API keys saved successfully!");
      setApiKeys({ openai_key: "", anthropic_key: "", gemini_key: "" });
      fetchSettings();
    } catch (error) {
      console.error("Failed to save API keys:", error);
      toast.error(`Failed to save API keys: ${error.response?.data?.detail || error.message}`);
    } finally {
      setSaving(false);
    }
  };

  const deleteApiKey = async (provider) => {
    if (!window.confirm(`Are you sure you want to delete the ${provider} API key?`)) {
      return;
    }
    try {
      await axios.delete(`${API}/settings/api-keys/${provider}`);

      // Also remove from localStorage
      localStorage.removeItem(`${provider}_key`);

      toast.success(`${provider} API key deleted!`);
      fetchSettings();
    } catch (error) {
      console.error("Failed to delete API key:", error);
      toast.error(`Failed to delete API key: ${error.response?.data?.detail || error.message}`);
    }
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
            LLM API Keys
          </CardTitle>
          <CardDescription>
            Configure API keys for AI-powered vulnerability fix recommendations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="openai">OpenAI API Key</Label>
              <div className="flex gap-2">
                <Input
                  id="openai"
                  type="password"
                  placeholder={apiKeyStatus.openai?.configured ? "••••••••••••••••" : "sk-..."}
                  value={apiKeys.openai_key}
                  onChange={(e) => setApiKeys({ ...apiKeys, openai_key: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.openai?.configured && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("openai")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.openai?.configured ? (
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
                  placeholder={apiKeyStatus.anthropic?.configured ? "••••••••••••••••" : "sk-ant-..."}
                  value={apiKeys.anthropic_key}
                  onChange={(e) => setApiKeys({ ...apiKeys, anthropic_key: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.anthropic?.configured && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("anthropic")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.anthropic?.configured ? (
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
                  placeholder={apiKeyStatus.gemini?.configured ? "••••••••••••••••" : "AIza..."}
                  value={apiKeys.gemini_key}
                  onChange={(e) => setApiKeys({ ...apiKeys, gemini_key: e.target.value })}
                  className="flex-1"
                />
                {apiKeyStatus.gemini?.configured && (
                  <Button variant="destructive" size="icon" onClick={() => deleteApiKey("gemini")}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {apiKeyStatus.gemini?.configured ? (
                  <><CheckCircle className="h-4 w-4 text-green-500" /> Configured</>
                ) : (
                  <><XCircle className="h-4 w-4 text-red-500" /> Not configured</>
                )}
              </div>
            </div>
          </div>

          <Button onClick={saveApiKeys} disabled={saving} className="w-full">
            {saving ? "Saving..." : "Save API Keys"}
          </Button>
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
