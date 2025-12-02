import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Alert, AlertDescription } from './ui/alert';
import { Progress } from './ui/progress';
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Shield,
  Code,
  Lock,
  MessageSquare,
  Container,
  Cloud,
  GitBranch
} from 'lucide-react';

const ScannerIcon = ({ type }) => {
  const icons = {
    zero_day: <Code className="h-4 w-4" />,
    business_logic: <Activity className="h-4 w-4" />,
    llm_security: <MessageSquare className="h-4 w-4" />,
    auth_scanner: <Lock className="h-4 w-4" />,
    codeql: <GitBranch className="h-4 w-4" />,
    docker: <Container className="h-4 w-4" />,
    iac: <Cloud className="h-4 w-4" />
  };
  return icons[type] || <Shield className="h-4 w-4" />;
};

const SeverityBadge = ({ severity, count }) => {
  const variants = {
    critical: 'destructive',
    high: 'destructive',
    medium: 'default',
    low: 'secondary'
  };

  const colors = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500'
  };

  return (
    <Badge variant={variants[severity]} className={colors[severity]}>
      {severity.toUpperCase()}: {count}
    </Badge>
  );
};

const RiskScoreGauge = ({ score }) => {
  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'CRITICAL', color: 'text-red-600', bgColor: 'bg-red-100' };
    if (score >= 60) return { level: 'HIGH', color: 'text-orange-600', bgColor: 'bg-orange-100' };
    if (score >= 40) return { level: 'MEDIUM', color: 'text-yellow-600', bgColor: 'bg-yellow-100' };
    if (score >= 20) return { level: 'LOW', color: 'text-blue-600', bgColor: 'bg-blue-100' };
    return { level: 'MINIMAL', color: 'text-green-600', bgColor: 'bg-green-100' };
  };

  const risk = getRiskLevel(score);

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <span className="text-sm font-medium">Risk Score</span>
        <span className={`text-2xl font-bold ${risk.color}`}>{score}/100</span>
      </div>
      <Progress value={score} className="h-3" />
      <div className={`text-center py-2 px-4 rounded-lg ${risk.bgColor}`}>
        <span className={`font-semibold ${risk.color}`}>{risk.level} RISK</span>
      </div>
    </div>
  );
};

const ScannerResultCard = ({ scannerType, findings, status }) => {
  const scannerNames = {
    zero_day: 'Zero-Day Detector (AI)',
    business_logic: 'Business Logic Scanner',
    llm_security: 'LLM Security Scanner',
    auth_scanner: 'Authentication Scanner',
    codeql: 'CodeQL Analysis',
    docker: 'Container Security',
    iac: 'Infrastructure as Code'
  };

  const scannerDescriptions = {
    zero_day: 'Graph Neural Networks + CodeBERT for novel vulnerability detection',
    business_logic: 'Runtime API testing, fuzzing, and race condition detection',
    llm_security: 'Adversarial testing with real LLM API calls',
    auth_scanner: 'JWT, OAuth, and session security testing',
    codeql: 'Semantic code analysis with 1000+ security queries',
    docker: 'CVE scanning, Dockerfile linting, CIS benchmarks',
    iac: 'Terraform, Kubernetes, CloudFormation security validation'
  };

  return (
    <Card className="hover:shadow-lg transition-shadow">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ScannerIcon type={scannerType} />
            <CardTitle className="text-lg">{scannerNames[scannerType]}</CardTitle>
          </div>
          {status === 'completed' ? (
            <CheckCircle className="h-5 w-5 text-green-500" />
          ) : status === 'failed' ? (
            <XCircle className="h-5 w-5 text-red-500" />
          ) : (
            <Activity className="h-5 w-5 text-blue-500 animate-pulse" />
          )}
        </div>
        <p className="text-sm text-muted-foreground mt-1">
          {scannerDescriptions[scannerType]}
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="text-2xl font-bold">
            {findings?.length || 0}
            <span className="text-sm text-muted-foreground ml-2">findings</span>
          </div>
          {findings?.length > 0 && (
            <Badge variant="outline" className="text-orange-600 border-orange-600">
              Requires Review
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

const RecommendationsList = ({ recommendations }) => {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5" />
          Top Security Recommendations
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {recommendations.map((rec, index) => (
            <li key={index} className="flex items-start gap-2">
              <span className="text-orange-600 font-bold">{index + 1}.</span>
              <span className="text-sm">{rec}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
};

const UnifiedScanResults = ({ scanResults }) => {
  if (!scanResults) {
    return (
      <Alert>
        <AlertDescription>No scan results available. Run a scan to see results.</AlertDescription>
      </Alert>
    );
  }

  const { scan_metadata, summary, findings_by_scanner, risk_score, recommendations } = scanResults;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Security Scan Results</h1>
          <p className="text-muted-foreground mt-1">
            Scanned: {scan_metadata?.repository} | Duration: {scan_metadata?.scan_duration_seconds?.toFixed(2)}s
          </p>
        </div>
        {scan_metadata?.runtime_testing_enabled && (
          <Badge variant="outline" className="text-green-600 border-green-600">
            ✓ Runtime Testing Enabled
          </Badge>
        )}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{summary?.total_vulnerabilities || 0}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Scanners Run
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{scan_metadata?.scanners_run?.length || 0}/7</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Failed Scanners
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">
              {scan_metadata?.scanners_failed?.length || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Scan Duration
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {scan_metadata?.scan_duration_seconds?.toFixed(1) || 0}s
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Score */}
      <Card>
        <CardHeader>
          <CardTitle>Security Risk Assessment</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <RiskScoreGauge score={risk_score || 0} />
            <div className="space-y-2">
              <h3 className="font-semibold mb-3">Vulnerability Breakdown</h3>
              <div className="flex flex-wrap gap-2">
                <SeverityBadge severity="critical" count={summary?.by_severity?.critical || 0} />
                <SeverityBadge severity="high" count={summary?.by_severity?.high || 0} />
                <SeverityBadge severity="medium" count={summary?.by_severity?.medium || 0} />
                <SeverityBadge severity="low" count={summary?.by_severity?.low || 0} />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Scanner Results Grid */}
      <div>
        <h2 className="text-2xl font-bold mb-4">Scanner Results</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(findings_by_scanner || {}).map(([scannerType, findingsCount]) => (
            <ScannerResultCard
              key={scannerType}
              scannerType={scannerType}
              findings={{ length: findingsCount }}
              status={scan_metadata?.scanners_run?.includes(scannerType) ? 'completed' : 'failed'}
            />
          ))}
        </div>
      </div>

      {/* Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <RecommendationsList recommendations={recommendations} />
      )}

      {/* Failed Scanners Alert */}
      {scan_metadata?.scanners_failed?.length > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            The following scanners failed: {scan_metadata.scanners_failed.join(', ')}
            <br />
            Check logs for details.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};

export default UnifiedScanResults;
