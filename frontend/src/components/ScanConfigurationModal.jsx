import React, { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from './ui/dialog';
import { Button } from './ui/button';
import { Label } from './ui/label';
import { Switch } from './ui/switch';
import { Input } from './ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import {
  Shield,
  Code,
  Activity,
  Lock,
  MessageSquare,
  Container,
  Cloud,
  GitBranch,
  Settings,
  Zap
} from 'lucide-react';

const ScannerOption = ({ icon: Icon, name, description, enabled, onToggle, isPro = false }) => (
  <Card className={`mb-3 ${enabled ? 'border-blue-500' : ''}`}>
    <CardHeader className="pb-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Icon className="h-5 w-5 text-blue-600" />
          <div>
            <div className="flex items-center gap-2">
              <CardTitle className="text-base">{name}</CardTitle>
              {isPro && <Badge variant="secondary">Pro</Badge>}
            </div>
            <CardDescription className="text-sm mt-1">{description}</CardDescription>
          </div>
        </div>
        <Switch checked={enabled} onCheckedChange={onToggle} />
      </div>
    </CardHeader>
  </Card>
);

const ScanConfigurationModal = ({ open, onClose, onStartScan, repository }) => {
  const [config, setConfig] = useState({
    // Scanner toggles
    enable_zero_day: true,
    enable_business_logic: true,
    enable_llm_security: true,
    enable_auth_scanner: true,
    enable_codeql: true,
    enable_docker: false,
    enable_iac: false,

    // Runtime testing
    enable_runtime_testing: false,
    base_url: '',
    auth_token: '',

    // LLM API keys
    openai_api_key: '',
    anthropic_api_key: '',

    // Docker images
    docker_images: '',

    // IaC directories
    terraform_dirs: '',
    kubernetes_dirs: '',
  });

  const handleToggle = (key) => {
    setConfig({ ...config, [key]: !config[key] });
  };

  const handleInputChange = (key, value) => {
    setConfig({ ...config, [key]: value });
  };

  const handleStartScan = () => {
    // Parse comma-separated values
    const finalConfig = {
      ...config,
      docker_images: config.docker_images.split(',').map(s => s.trim()).filter(Boolean),
      terraform_dirs: config.terraform_dirs.split(',').map(s => s.trim()).filter(Boolean),
      kubernetes_dirs: config.kubernetes_dirs.split(',').map(s => s.trim()).filter(Boolean),
    };

    onStartScan(finalConfig);
  };

  const allScannerCount = 7;
  const enabledScannerCount = [
    config.enable_zero_day,
    config.enable_business_logic,
    config.enable_llm_security,
    config.enable_auth_scanner,
    config.enable_codeql,
    config.enable_docker,
    config.enable_iac,
  ].filter(Boolean).length;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Configure Security Scan
          </DialogTitle>
          <DialogDescription>
            Customize which scanners to run and configure runtime testing options
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="scanners" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="scanners">
              Scanners ({enabledScannerCount}/{allScannerCount})
            </TabsTrigger>
            <TabsTrigger value="runtime">Runtime Testing</TabsTrigger>
            <TabsTrigger value="advanced">Advanced</TabsTrigger>
          </TabsList>

          <TabsContent value="scanners" className="space-y-4 mt-4">
            <ScannerOption
              icon={Code}
              name="Zero-Day Detector (AI)"
              description="Graph Neural Networks + CodeBERT for novel vulnerability detection"
              enabled={config.enable_zero_day}
              onToggle={() => handleToggle('enable_zero_day')}
              isPro
            />

            <ScannerOption
              icon={Activity}
              name="Business Logic Scanner"
              description="Runtime API testing, fuzzing, and race condition detection"
              enabled={config.enable_business_logic}
              onToggle={() => handleToggle('enable_business_logic')}
              isPro
            />

            <ScannerOption
              icon={MessageSquare}
              name="LLM Security Scanner"
              description="Adversarial testing for prompt injection, jailbreaks, and data leaks"
              enabled={config.enable_llm_security}
              onToggle={() => handleToggle('enable_llm_security')}
              isPro
            />

            <ScannerOption
              icon={Lock}
              name="Authentication Scanner"
              description="JWT, OAuth, and session security testing"
              enabled={config.enable_auth_scanner}
              onToggle={() => handleToggle('enable_auth_scanner')}
              isPro
            />

            <ScannerOption
              icon={GitBranch}
              name="CodeQL Analysis"
              description="Semantic code analysis with 1000+ security queries"
              enabled={config.enable_codeql}
              onToggle={() => handleToggle('enable_codeql')}
            />

            <ScannerOption
              icon={Container}
              name="Container Security"
              description="CVE scanning, Dockerfile linting, CIS benchmarks"
              enabled={config.enable_docker}
              onToggle={() => handleToggle('enable_docker')}
            />

            <ScannerOption
              icon={Cloud}
              name="Infrastructure as Code"
              description="Terraform, Kubernetes, CloudFormation security validation"
              enabled={config.enable_iac}
              onToggle={() => handleToggle('enable_iac')}
            />
          </TabsContent>

          <TabsContent value="runtime" className="space-y-4 mt-4">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Enable Runtime Testing</CardTitle>
                    <CardDescription>
                      Actually test endpoints with real HTTP requests to confirm exploitability
                    </CardDescription>
                  </div>
                  <Switch
                    checked={config.enable_runtime_testing}
                    onCheckedChange={() => handleToggle('enable_runtime_testing')}
                  />
                </div>
              </CardHeader>

              {config.enable_runtime_testing && (
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="base_url">Base URL</Label>
                    <Input
                      id="base_url"
                      placeholder="https://api.example.com"
                      value={config.base_url}
                      onChange={(e) => handleInputChange('base_url', e.target.value)}
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      The base URL of your running application
                    </p>
                  </div>

                  <div>
                    <Label htmlFor="auth_token">Authorization Token (Optional)</Label>
                    <Input
                      id="auth_token"
                      type="password"
                      placeholder="Bearer token or API key"
                      value={config.auth_token}
                      onChange={(e) => handleInputChange('auth_token', e.target.value)}
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Authentication token for protected endpoints
                    </p>
                  </div>
                </CardContent>
              )}
            </Card>

            {config.enable_llm_security && (
              <Card>
                <CardHeader>
                  <CardTitle>LLM API Keys</CardTitle>
                  <CardDescription>
                    Required for real adversarial testing of LLM integrations
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="openai_key">OpenAI API Key (Optional)</Label>
                    <Input
                      id="openai_key"
                      type="password"
                      placeholder="sk-..."
                      value={config.openai_api_key}
                      onChange={(e) => handleInputChange('openai_api_key', e.target.value)}
                    />
                  </div>

                  <div>
                    <Label htmlFor="anthropic_key">Anthropic API Key (Optional)</Label>
                    <Input
                      id="anthropic_key"
                      type="password"
                      placeholder="sk-ant-..."
                      value={config.anthropic_api_key}
                      onChange={(e) => handleInputChange('anthropic_api_key', e.target.value)}
                    />
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="advanced" className="space-y-4 mt-4">
            {config.enable_docker && (
              <Card>
                <CardHeader>
                  <CardTitle>Docker Images</CardTitle>
                  <CardDescription>
                    Comma-separated list of Docker images to scan
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Input
                    placeholder="nginx:latest, myapp:1.0.0"
                    value={config.docker_images}
                    onChange={(e) => handleInputChange('docker_images', e.target.value)}
                  />
                </CardContent>
              </Card>
            )}

            {config.enable_iac && (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle>Terraform Directories</CardTitle>
                    <CardDescription>
                      Comma-separated paths to Terraform configurations
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Input
                      placeholder="./terraform, ./infrastructure/terraform"
                      value={config.terraform_dirs}
                      onChange={(e) => handleInputChange('terraform_dirs', e.target.value)}
                    />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Kubernetes Directories</CardTitle>
                    <CardDescription>
                      Comma-separated paths to Kubernetes manifests
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Input
                      placeholder="./k8s, ./deployments"
                      value={config.kubernetes_dirs}
                      onChange={(e) => handleInputChange('kubernetes_dirs', e.target.value)}
                    />
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleStartScan} className="gap-2">
            <Zap className="h-4 w-4" />
            Start Scan ({enabledScannerCount} scanners)
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default ScanConfigurationModal;
