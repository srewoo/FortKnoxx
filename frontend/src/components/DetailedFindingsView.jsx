import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { ChevronDown, ChevronRight, Copy, ExternalLink } from 'lucide-react';

const SeverityBadge = ({ severity }) => {
  const variants = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white'
  };

  return (
    <Badge className={variants[severity?.toLowerCase()] || 'bg-gray-500'}>
      {severity}
    </Badge>
  );
};

const FindingCard = ({ finding, scannerType }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <Card className="mb-4">
      <CardHeader
        className="cursor-pointer hover:bg-gray-50"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              <CardTitle className="text-lg">{finding.title || finding.rule_name || 'Vulnerability'}</CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              {finding.confidence && (
                <Badge variant="outline">
                  Confidence: {(finding.confidence * 100).toFixed(0)}%
                </Badge>
              )}
              {finding.cwe_ids && finding.cwe_ids.length > 0 && (
                <Badge variant="outline">{finding.cwe_ids[0]}</Badge>
              )}
            </div>
          </div>
        </div>
      </CardHeader>

      {isExpanded && (
        <CardContent className="space-y-4">
          {/* Description */}
          <div>
            <h4 className="font-semibold mb-2">Description</h4>
            <p className="text-sm text-gray-700">{finding.description || finding.message}</p>
          </div>

          {/* Location */}
          <div>
            <h4 className="font-semibold mb-2">Location</h4>
            <div className="bg-gray-50 p-3 rounded text-sm font-mono">
              {finding.file_path || finding.endpoint_file}
              {finding.start_line && `:${finding.start_line}`}
              {finding.line_number && `:${finding.line_number}`}
            </div>
          </div>

          {/* Code Snippet */}
          {finding.code_snippet && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-semibold">Code Snippet</h4>
                <button
                  onClick={() => copyToClipboard(finding.code_snippet)}
                  className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1"
                >
                  <Copy className="h-3 w-3" />
                  Copy
                </button>
              </div>
              <pre className="bg-gray-900 text-gray-100 p-4 rounded overflow-x-auto text-xs">
                {finding.code_snippet}
              </pre>
            </div>
          )}

          {/* Attack Payload (for runtime tests) */}
          {finding.attack_payload && (
            <div>
              <h4 className="font-semibold mb-2">Attack Payload</h4>
              <pre className="bg-red-50 border border-red-200 p-3 rounded text-xs overflow-x-auto">
                {finding.attack_payload}
              </pre>
            </div>
          )}

          {/* Model Response (for LLM findings) */}
          {finding.model_response && (
            <div>
              <h4 className="font-semibold mb-2">Model Response</h4>
              <div className="bg-yellow-50 border border-yellow-200 p-3 rounded text-sm">
                {finding.model_response}
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <h4 className="font-semibold mb-2">Remediation</h4>
              <div className="bg-green-50 border border-green-200 p-3 rounded text-sm whitespace-pre-line">
                {finding.remediation}
              </div>
            </div>
          )}

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">References</h4>
              <ul className="space-y-1">
                {finding.references.map((ref, idx) => (
                  <li key={idx}>
                    <a
                      href={ref.startsWith('http') ? ref : `https://cwe.mitre.org/data/definitions/${ref.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-blue-600 hover:underline flex items-center gap-1"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* AI-specific metadata */}
          {finding.anomaly_score && (
            <div>
              <h4 className="font-semibold mb-2">AI Detection Metadata</h4>
              <div className="bg-purple-50 border border-purple-200 p-3 rounded text-sm">
                <p><strong>Anomaly Score:</strong> {(finding.anomaly_score * 100).toFixed(1)}%</p>
                {finding.jailbreak_risk > 0 && (
                  <p><strong>Jailbreak Risk:</strong> {(finding.jailbreak_risk * 100).toFixed(1)}%</p>
                )}
                {finding.data_leak_probability > 0 && (
                  <p><strong>Data Leak Probability:</strong> {(finding.data_leak_probability * 100).toFixed(1)}%</p>
                )}
              </div>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
};

const DetailedFindingsView = ({ scanResults }) => {
  if (!scanResults) return null;

  const {
    zero_day_findings = [],
    business_logic_findings = [],
    llm_findings = [],
    auth_findings = [],
    codeql_findings = [],
    docker_findings = [],
    iac_findings = []
  } = scanResults;

  const tabs = [
    { key: 'all', label: 'All Findings', findings: [
      ...zero_day_findings,
      ...business_logic_findings,
      ...llm_findings,
      ...auth_findings,
      ...codeql_findings,
      ...docker_findings,
      ...iac_findings
    ]},
    { key: 'zero_day', label: `Zero-Day (${zero_day_findings.length})`, findings: zero_day_findings, type: 'zero_day' },
    { key: 'business_logic', label: `Business Logic (${business_logic_findings.length})`, findings: business_logic_findings, type: 'business_logic' },
    { key: 'llm', label: `LLM Security (${llm_findings.length})`, findings: llm_findings, type: 'llm' },
    { key: 'auth', label: `Auth (${auth_findings.length})`, findings: auth_findings, type: 'auth' },
    { key: 'codeql', label: `CodeQL (${codeql_findings.length})`, findings: codeql_findings, type: 'codeql' },
    { key: 'docker', label: `Docker (${docker_findings.length})`, findings: docker_findings, type: 'docker' },
    { key: 'iac', label: `IaC (${iac_findings.length})`, findings: iac_findings, type: 'iac' }
  ];

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-4">Detailed Findings</h2>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-4 flex-wrap h-auto">
          {tabs.map(tab => (
            <TabsTrigger
              key={tab.key}
              value={tab.key}
              disabled={tab.findings.length === 0}
            >
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {tabs.map(tab => (
          <TabsContent key={tab.key} value={tab.key}>
            {tab.findings.length === 0 ? (
              <Card>
                <CardContent className="py-8 text-center text-gray-500">
                  No findings in this category
                </CardContent>
              </Card>
            ) : (
              <div>
                <p className="text-sm text-gray-600 mb-4">
                  Showing {tab.findings.length} finding(s)
                </p>
                {tab.findings.map((finding, idx) => (
                  <FindingCard
                    key={idx}
                    finding={finding}
                    scannerType={tab.type}
                  />
                ))}
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
};

export default DetailedFindingsView;
