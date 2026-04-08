import { Code2, FileDown, Server, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { API_BASE_URL } from "@/lib/api";

const endpoints = [
  {
    method: "GET",
    path: "/api/health",
    description: "Returns API health and model load state.",
  },
  {
    method: "POST",
    path: "/api/standard/inference",
    description: "Runs the standard model against an uploaded CSV and returns a CSV download.",
  },
  {
    method: "POST",
    path: "/api/proprietary/inference",
    description: "Runs the proprietary model against an uploaded CSV and returns a CSV download.",
  },
];

const curlExample = `curl -X POST "${API_BASE_URL}/api/standard/inference" ^
  -F "file=@datasets/Standard/standard_test_dataset.csv" ^
  -o standard_results.csv`;

const pythonExample = `import requests

with open("datasets/Proprietary/proprietary_data_test.csv", "rb") as handle:
    response = requests.post(
        "${API_BASE_URL}/api/proprietary/inference",
        files={"file": handle},
    )
    response.raise_for_status()

with open("proprietary_results.csv", "wb") as output:
    output.write(response.content)`;

const tsExample = `const formData = new FormData();
formData.append("file", file);

const response = await fetch("${API_BASE_URL}/api/standard/inference", {
  method: "POST",
  body: formData,
});

if (!response.ok) {
  throw new Error("Inference failed");
}

const blob = await response.blob();`;

const ApiIntegration = () => {
  return (
    <div className="space-y-8">
      <div className="enterprise-card p-6">
        <h1 className="text-3xl font-inter font-semibold">API Integration</h1>
        <p className="text-muted-foreground mt-2">
          The frontend talks to a local Flask API. The current implementation is designed for local use and demo workflows.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Server className="h-5 w-5 text-primary" />
              Base URL
            </CardTitle>
          </CardHeader>
          <CardContent>
            <code className="text-sm">{API_BASE_URL}</code>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <FileDown className="h-5 w-5 text-primary" />
              Response Format
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Inference endpoints return downloadable CSV files.
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <ShieldAlert className="h-5 w-5 text-primary" />
              Security Status
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            No API key or auth layer is implemented in the local demo server.
          </CardContent>
        </Card>
      </div>

      <Card className="enterprise-card">
        <CardHeader>
          <CardTitle>Available Endpoints</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {endpoints.map((endpoint) => (
            <div key={endpoint.path} className="rounded-lg border border-border p-4">
              <div className="flex items-center gap-3 mb-2">
                <Badge className="enterprise-badge-primary">{endpoint.method}</Badge>
                <code>{endpoint.path}</code>
              </div>
              <p className="text-sm text-muted-foreground">{endpoint.description}</p>
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code2 className="h-5 w-5" />
              cURL
            </CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-sm whitespace-pre-wrap break-all">{curlExample}</pre>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code2 className="h-5 w-5" />
              Python
            </CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-sm whitespace-pre-wrap break-all">{pythonExample}</pre>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code2 className="h-5 w-5" />
              TypeScript
            </CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-sm whitespace-pre-wrap break-all">{tsExample}</pre>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ApiIntegration;
