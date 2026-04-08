import { useState } from "react";
import { 
  Search, 
  Calendar, 
  Download, 
  Eye, 
  FileText, 
  AlertTriangle,
  CheckCircle,
  Clock,
  XCircle,
  ExternalLink
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle } from "@/components/ui/drawer";

// Sample data
const sampleResults = [
  {
    id: 1,
    fileName: "router_firmware_v2.1.4.bin",
    architecture: "ARM",
    size: "2.4 MB",
    uploadedAt: "2024-01-15 14:30",
    riskScore: 72,
    status: "Completed",
    detections: {
      aes: { present: true, confidence: 0.92 },
      rsa: { present: false, confidence: 0.34 },
      sha: { present: true, variant: "SHA-256", confidence: 0.88 },
      ecc: { present: true, curve: "P-256", confidence: 0.81 },
      prng: { present: true, type: "CSPRNG", confidence: 0.76 },
      proprietary: { present: true, notes: "non-standard S-Box pattern" }
    }
  },
  {
    id: 2,
    fileName: "iot_device_v1.0.bin",
    architecture: "MIPS",
    size: "1.8 MB",
    uploadedAt: "2024-01-15 11:22",
    riskScore: 45,
    status: "Completed",
    detections: {
      aes: { present: true, confidence: 0.78 },
      rsa: { present: true, confidence: 0.65 },
      sha: { present: true, variant: "SHA-1", confidence: 0.82 },
      ecc: { present: false, confidence: 0.12 },
      prng: { present: true, type: "LCG", confidence: 0.45 },
      proprietary: { present: false, notes: "" }
    }
  },
  {
    id: 3,
    fileName: "embedded_system_v3.2.bin",
    architecture: "RISC-V",
    size: "3.1 MB",
    uploadedAt: "2024-01-14 16:45",
    riskScore: 89,
    status: "Completed",
    detections: {
      aes: { present: true, confidence: 0.95 },
      rsa: { present: true, confidence: 0.88 },
      sha: { present: true, variant: "SHA-256", confidence: 0.91 },
      ecc: { present: true, curve: "P-384", confidence: 0.89 },
      prng: { present: true, type: "CSPRNG", confidence: 0.82 },
      proprietary: { present: true, notes: "custom key derivation" }
    }
  },
  {
    id: 4,
    fileName: "legacy_device.bin",
    architecture: "AVR",
    size: "512 KB",
    uploadedAt: "2024-01-14 09:15",
    riskScore: 95,
    status: "Completed",
    detections: {
      aes: { present: false, confidence: 0.05 },
      rsa: { present: true, confidence: 0.45 },
      sha: { present: true, variant: "MD5", confidence: 0.78 },
      ecc: { present: false, confidence: 0.02 },
      prng: { present: true, type: "XOR", confidence: 0.23 },
      proprietary: { present: true, notes: "weak encryption" }
    }
  },
  {
    id: 5,
    fileName: "security_module_v1.5.bin",
    architecture: "ARM",
    size: "1.2 MB",
    uploadedAt: "2024-01-13 20:30",
    riskScore: 28,
    status: "Completed",
    detections: {
      aes: { present: true, confidence: 0.98 },
      rsa: { present: true, confidence: 0.92 },
      sha: { present: true, variant: "SHA-256", confidence: 0.95 },
      ecc: { present: true, curve: "P-256", confidence: 0.91 },
      prng: { present: true, type: "CSPRNG", confidence: 0.88 },
      proprietary: { present: false, notes: "" }
    }
  },
  {
    id: 6,
    fileName: "network_appliance.bin",
    architecture: "MIPS",
    size: "4.2 MB",
    uploadedAt: "2024-01-13 15:20",
    riskScore: 67,
    status: "Queued",
    detections: null
  }
];

const kpiData = [
  { title: "Firmware Analyzed Today", value: "24", icon: FileText, trend: "+3 from yesterday" },
  { title: "Average Detection Confidence", value: "87.3%", icon: CheckCircle, trend: "+2.1% improvement" },
  { title: "Weak or Legacy Crypto Flags", value: "12", icon: AlertTriangle, trend: "↑ 4 this week" },
  { title: "Proprietary Algorithm Findings", value: "8", icon: FileText, trend: "3 new patterns" }
];

const getRiskBadge = (score: number) => {
  if (score >= 80) return "enterprise-badge-danger";
  if (score >= 60) return "enterprise-badge-warning";
  if (score >= 40) return "enterprise-badge-primary";
  return "enterprise-badge-success";
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case "Completed": return <CheckCircle className="h-4 w-4 text-success" />;
    case "Queued": return <Clock className="h-4 w-4 text-warning" />;
    case "Failed": return <XCircle className="h-4 w-4 text-destructive" />;
    default: return <Clock className="h-4 w-4 text-muted-foreground" />;
  }
};

const ReportDrawer = ({ result, isOpen, onClose }: { result: any; isOpen: boolean; onClose: () => void }) => {
  if (!result) return null;

  return (
    <Drawer open={isOpen} onOpenChange={onClose}>
      <DrawerContent className="max-h-[80vh]">
        <DrawerHeader>
          <DrawerTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Analysis Report: {result.fileName}
          </DrawerTitle>
        </DrawerHeader>
        <div className="px-4 pb-4">
          <Tabs defaultValue="overview" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="functions">Detected Functions</TabsTrigger>
              <TabsTrigger value="logs">Heuristics Logs</TabsTrigger>
              <TabsTrigger value="download">Download</TabsTrigger>
            </TabsList>
            
            <TabsContent value="overview" className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Detection Results</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {Object.entries(result.detections || {}).map(([key, detection]: [string, any]) => (
                      <div key={key} className="flex items-center justify-between">
                        <span className="text-sm font-medium capitalize">{key}</span>
                        <div className="flex items-center gap-2">
                          <Progress value={detection.confidence * 100} className="w-20" />
                          <span className="text-xs text-muted-foreground">
                            {Math.round(detection.confidence * 100)}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">File Metadata</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Architecture:</span>
                      <span>{result.architecture}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Size:</span>
                      <span>{result.size}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Uploaded:</span>
                      <span>{result.uploadedAt}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Risk Score:</span>
                      <Badge className={getRiskBadge(result.riskScore)}>
                        {result.riskScore}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="functions">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Detected Cryptographic Functions</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Offset</TableHead>
                        <TableHead>Primitive Type</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Section</TableHead>
                        <TableHead>Heuristics</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      <TableRow>
                        <TableCell>.text+0x14A0</TableCell>
                        <TableCell>AES-256</TableCell>
                        <TableCell>92%</TableCell>
                        <TableCell>.text</TableCell>
                        <TableCell>Opcode signature</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>.text+0x2B40</TableCell>
                        <TableCell>SHA-256</TableCell>
                        <TableCell>88%</TableCell>
                        <TableCell>.text</TableCell>
                        <TableCell>CFG shape</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="logs">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Analysis Logs</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm font-mono">
                    <div className="p-2 bg-muted/30 rounded">
                      [14:30:15] Starting disassembly analysis...
                    </div>
                    <div className="p-2 bg-muted/30 rounded">
                      [14:30:18] Detected ARM architecture patterns
                    </div>
                    <div className="p-2 bg-muted/30 rounded">
                      [14:30:22] Found cryptographic constants at 0x14A0
                    </div>
                    <div className="p-2 bg-muted/30 rounded">
                      [14:30:25] Extracting entropy measurements...
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="download">
              <div className="space-y-4">
                <Button className="w-full">
                  <Download className="h-4 w-4 mr-2" />
                  Export JSON Report
                </Button>
                <Button variant="outline" className="w-full">
                  <Download className="h-4 w-4 mr-2" />
                  Export PDF Report
                </Button>
                <Button variant="outline" className="w-full">
                  <Download className="h-4 w-4 mr-2" />
                  Download Raw Logs
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </DrawerContent>
    </Drawer>
  );
};

const AnalysisResults = () => {
  const [selectedResult, setSelectedResult] = useState<any>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const handleRowClick = (result: any) => {
    setSelectedResult(result);
    setIsDrawerOpen(true);
  };

  return (
    <div className="space-y-8">
      {/* Hero Bar */}
      <div className="enterprise-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-inter font-semibold">Analysis Results</h1>
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Search by file name..." 
                className="pl-10 w-64"
              />
            </div>
            <Select>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filter by architecture" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Architectures</SelectItem>
                <SelectItem value="arm">ARM</SelectItem>
                <SelectItem value="mips">MIPS</SelectItem>
                <SelectItem value="risc-v">RISC-V</SelectItem>
                <SelectItem value="avr">AVR</SelectItem>
              </SelectContent>
            </Select>
            <Select>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Levels</SelectItem>
                <SelectItem value="low">Low (0-39)</SelectItem>
                <SelectItem value="medium">Medium (40-79)</SelectItem>
                <SelectItem value="high">High (80+)</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline">
              <Calendar className="h-4 w-4 mr-2" />
              Date Range
            </Button>
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {kpiData.map((kpi, index) => (
          <Card key={index} className="enterprise-card">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{kpi.title}</p>
                  <p className="text-2xl font-semibold mt-1">{kpi.value}</p>
                  <p className="text-xs text-muted-foreground mt-1">{kpi.trend}</p>
                </div>
                <kpi.icon className="h-8 w-8 text-primary" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Results Table */}
      <Card className="enterprise-card">
        <CardHeader>
          <CardTitle>Analysis Results</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File Name</TableHead>
                <TableHead>Architecture</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Uploaded At</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sampleResults.map((result) => (
                <TableRow 
                  key={result.id} 
                  className="cursor-pointer hover:bg-muted/30"
                  onClick={() => handleRowClick(result)}
                >
                  <TableCell className="font-medium">{result.fileName}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{result.architecture}</Badge>
                  </TableCell>
                  <TableCell>{result.size}</TableCell>
                  <TableCell>{result.uploadedAt}</TableCell>
                  <TableCell>
                    <Badge className={getRiskBadge(result.riskScore)}>
                      {result.riskScore}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(result.status)}
                      <span className="text-sm">{result.status}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Button 
                      variant="ghost" 
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRowClick(result);
                      }}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Empty State */}
      {sampleResults.length === 0 && (
        <Card className="enterprise-card">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No analysis results found</h3>
            <p className="text-muted-foreground mb-4">
              Upload firmware files to start analyzing cryptographic implementations.
            </p>
            <Button>
              <ExternalLink className="h-4 w-4 mr-2" />
              Upload Firmware
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Report Drawer */}
      <ReportDrawer 
        result={selectedResult} 
        isOpen={isDrawerOpen} 
        onClose={() => setIsDrawerOpen(false)} 
      />
    </div>
  );
};

export default AnalysisResults;
