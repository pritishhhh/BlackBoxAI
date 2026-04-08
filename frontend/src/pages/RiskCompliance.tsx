import { useState } from "react";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Download, 
  FileText,
  TrendingUp,
  TrendingDown,
  Info,
  ExternalLink
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

// Sample compliance data
const complianceMatrix = [
  {
    algorithm: "AES-128",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "AES-192",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "AES-256",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "RSA-1024",
    nistApproved: false,
    fips1403: false,
    deprecated: true,
    inUse: true,
    riskLevel: "High"
  },
  {
    algorithm: "RSA-2048",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "RSA-3072",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: false,
    riskLevel: "Low"
  },
  {
    algorithm: "ECC-256",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "ECC-384",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "SHA-1",
    nistApproved: false,
    fips1403: false,
    deprecated: true,
    inUse: true,
    riskLevel: "High"
  },
  {
    algorithm: "SHA-256",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "SHA-512",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  },
  {
    algorithm: "MD5",
    nistApproved: false,
    fips1403: false,
    deprecated: true,
    inUse: true,
    riskLevel: "High"
  },
  {
    algorithm: "ChaCha20",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: false,
    riskLevel: "Low"
  },
  {
    algorithm: "Poly1305",
    nistApproved: true,
    fips1403: true,
    deprecated: false,
    inUse: true,
    riskLevel: "Low"
  }
];

const riskBreakdown = [
  { category: "Confidentiality", low: 45, medium: 30, high: 25 },
  { category: "Integrity", low: 60, medium: 25, high: 15 },
  { category: "Authentication", low: 40, medium: 35, high: 25 },
  { category: "Randomness", low: 35, medium: 40, high: 25 }
];

const recommendations = [
  {
    id: 1,
    rule: "Replace SHA-1 with SHA-256",
    priority: "High",
    impact: "Critical",
    description: "SHA-1 is cryptographically broken and should be replaced with SHA-256 or SHA-3."
  },
  {
    id: 2,
    rule: "Migrate RSA-1024 to RSA-2048",
    priority: "High",
    impact: "High",
    description: "RSA-1024 provides insufficient security for modern applications."
  },
  {
    id: 3,
    rule: "Avoid XOR for confidentiality",
    priority: "Medium",
    impact: "Medium",
    description: "XOR encryption alone is not secure and should be replaced with AES."
  },
  {
    id: 4,
    rule: "Ensure CSPRNG source",
    priority: "Medium",
    impact: "Medium",
    description: "Use system entropy sources instead of LCG for cryptographic randomness."
  },
  {
    id: 5,
    rule: "Implement proper key management",
    priority: "Low",
    impact: "High",
    description: "Establish secure key generation, storage, and rotation procedures."
  }
];

const getStatusIcon = (status: boolean) => {
  return status ? (
    <CheckCircle className="h-4 w-4 text-success" />
  ) : (
    <XCircle className="h-4 w-4 text-destructive" />
  );
};

const getRiskBadge = (risk: string) => {
  switch (risk) {
    case "High": return "enterprise-badge-danger";
    case "Medium": return "enterprise-badge-warning";
    case "Low": return "enterprise-badge-success";
    default: return "enterprise-badge-primary";
  }
};

const getPriorityBadge = (priority: string) => {
  switch (priority) {
    case "High": return "enterprise-badge-danger";
    case "Medium": return "enterprise-badge-warning";
    case "Low": return "enterprise-badge-success";
    default: return "enterprise-badge-primary";
  }
};

const RiskCompliance = () => {
  const [includeEvidence, setIncludeEvidence] = useState(false);

  const overallRiskScore = 72;
  const compliancePassRate = 68;
  const algorithmsAtRisk = 3;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="enterprise-card p-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-inter font-semibold">Risk & Compliance</h1>
          <div className="flex items-center gap-4">
            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export PDF Report
            </Button>
            <Button variant="outline">
              <FileText className="h-4 w-4 mr-2" />
              Export JSON
            </Button>
          </div>
        </div>
      </div>

      {/* Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="enterprise-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Overall Risk Score</p>
                <p className="text-3xl font-semibold mt-1">{overallRiskScore}</p>
                <div className="mt-2">
                  <Progress value={overallRiskScore} className="w-full" />
                </div>
              </div>
              <Shield className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Compliance Pass Rate</p>
                <p className="text-3xl font-semibold mt-1">{compliancePassRate}%</p>
                <div className="mt-2">
                  <Progress value={compliancePassRate} className="w-full" />
                </div>
              </div>
              <CheckCircle className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Algorithms at Risk</p>
                <p className="text-3xl font-semibold mt-1">{algorithmsAtRisk}</p>
                <p className="text-xs text-muted-foreground mt-1">Requires immediate attention</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Compliance Matrix */}
      <Card className="enterprise-card">
        <CardHeader>
          <CardTitle>Compliance Matrix</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Algorithm</TableHead>
                <TableHead>NIST Approved</TableHead>
                <TableHead>FIPS 140-3 Ready</TableHead>
                <TableHead>Deprecated</TableHead>
                <TableHead>In Use</TableHead>
                <TableHead>Risk Level</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {complianceMatrix.map((item, index) => (
                <TableRow key={index}>
                  <TableCell className="font-medium">{item.algorithm}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(item.nistApproved)}
                      <span className="text-sm">{item.nistApproved ? "Yes" : "No"}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(item.fips1403)}
                      <span className="text-sm">{item.fips1403 ? "Yes" : "No"}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(item.deprecated)}
                      <span className="text-sm">{item.deprecated ? "Yes" : "No"}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(item.inUse)}
                      <span className="text-sm">{item.inUse ? "Yes" : "No"}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge className={getRiskBadge(item.riskLevel)}>
                      {item.riskLevel}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Risk Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle>Risk Breakdown by Category</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {riskBreakdown.map((category, index) => (
                <div key={index}>
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-medium">{category.category}</span>
                    <span className="text-sm text-muted-foreground">
                      {category.low + category.medium + category.high}% total
                    </span>
                  </div>
                  <div className="flex h-6 rounded-lg overflow-hidden">
                    <div 
                      className="bg-success" 
                      style={{ width: `${category.low}%` }}
                      title={`Low: ${category.low}%`}
                    />
                    <div 
                      className="bg-warning" 
                      style={{ width: `${category.medium}%` }}
                      title={`Medium: ${category.medium}%`}
                    />
                    <div 
                      className="bg-destructive" 
                      style={{ width: `${category.high}%` }}
                      title={`High: ${category.high}%`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Recommendations Panel */}
        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle>Security Recommendations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recommendations.map((rec) => (
                <div key={rec.id} className="p-4 border border-border rounded-lg">
                  <div className="flex items-start justify-between mb-2">
                    <div className="font-medium">{rec.rule}</div>
                    <Badge className={getPriorityBadge(rec.priority)}>
                      {rec.priority}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mb-2">{rec.description}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Impact:</span>
                    <Badge variant="outline" className="text-xs">
                      {rec.impact}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Export & Share */}
      <Card className="enterprise-card">
        <CardHeader>
          <CardTitle>Export & Share</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button>
                <Download className="h-4 w-4 mr-2" />
                Export PDF Compliance Report
              </Button>
              <Button variant="outline">
                <FileText className="h-4 w-4 mr-2" />
                Export JSON Policy Diff
              </Button>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="include-evidence"
                checked={includeEvidence}
                onChange={(e) => setIncludeEvidence(e.target.checked)}
                className="rounded"
              />
              <label htmlFor="include-evidence" className="text-sm">
                Include raw evidence appendix
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Sample content note */}
      <Card className="enterprise-card">
        <CardContent className="p-6">
          <div className="flex items-center gap-3">
            <Info className="h-5 w-5 text-primary" />
            <div>
              <div className="font-medium">Sample Compliance Analysis</div>
              <div className="text-sm text-muted-foreground">
                This demonstrates failing SHA-1 and RSA-1024 examples with security recommendations and risk assessment.
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RiskCompliance;
