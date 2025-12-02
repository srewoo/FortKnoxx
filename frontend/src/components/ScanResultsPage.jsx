import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import UnifiedScanResults from './UnifiedScanResults';
import DetailedFindingsView from './DetailedFindingsView';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Alert, AlertDescription } from './ui/alert';
import { Button } from './ui/button';
import { Download, RefreshCw, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ScanResultsPage = () => {
  const { id } = useParams();
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchScanResults();
  }, [id]);

  const fetchScanResults = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API}/repos/${id}/latest-scan`);
      setScanResults(response.data);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load scan results');
      toast.error('Failed to load scan results');
    } finally {
      setLoading(false);
    }
  };

  const exportResults = async (format) => {
    try {
      const response = await axios.get(
        `${API}/repos/${id}/export?format=${format}`,
        { responseType: 'blob' }
      );

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan-results.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();

      toast.success(`Exported scan results as ${format.toUpperCase()}`);
    } catch (err) {
      toast.error(`Failed to export results: ${err.message}`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive" className="m-6">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header with export options */}
      <div className="bg-white border-b">
        <div className="px-6 py-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">Security Scan Results</h1>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportResults('json')}
            >
              <Download className="h-4 w-4 mr-2" />
              Export JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportResults('sarif')}
            >
              <Download className="h-4 w-4 mr-2" />
              Export SARIF
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportResults('pdf')}
            >
              <Download className="h-4 w-4 mr-2" />
              Export PDF
            </Button>
            <Button
              size="sm"
              onClick={fetchScanResults}
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <Tabs defaultValue="overview" className="w-full">
        <div className="bg-white border-b">
          <TabsList className="px-6">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="detailed">Detailed Findings</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="overview">
          <UnifiedScanResults scanResults={scanResults} />
        </TabsContent>

        <TabsContent value="detailed">
          <DetailedFindingsView scanResults={scanResults} />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ScanResultsPage;
