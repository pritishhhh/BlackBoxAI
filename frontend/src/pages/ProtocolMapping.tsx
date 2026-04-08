import { useState } from "react";
import { 
  Network, 
  Filter, 
  Download, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw,
  ExternalLink,
  Eye,
  Clock,
  Shield,
  Key,
  Lock,
  CheckCircle
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

// Sample protocol data
const protocolData = {
  tls: {
    name: "TLS-like Protocol",
    anomalyScore: 0.14,
    nodes: [
      { id: "keygen", label: "KeyGen", offsets: [".text+0x14A0"], confidence: 0.83, primitive: "ECDH P-256" },
      { id: "kex", label: "Key Exchange", offsets: [".text+0x1B20"], confidence: 0.86, primitive: "ECDH P-256" },
      { id: "enc", label: "Encrypt", offsets: [".text+0x2C40"], confidence: 0.91, primitive: "AES-256-GCM" },
      { id: "mac", label: "Authenticate", offsets: [".text+0x3A80"], confidence: 0.88, primitive: "Poly1305" },
      { id: "ver", label: "Verify", offsets: [".text+0x4B20"], confidence: 0.84, primitive: "ECDSA P-256" }
    ],
    edges: [
      { from: "keygen", to: "kex" },
      { from: "kex", to: "enc" },
      { from: "enc", to: "mac" },
      { from: "mac", to: "ver" }
    ],
    sequence: [
      { step: 1, offset: ".text+0x14A0", primitive: "KeyGen", keyLength: "256", confidence: 0.83, timestamp: "14:30:15" },
      { step: 2, offset: ".text+0x1B20", primitive: "Key Exchange", keyLength: "256", confidence: 0.86, timestamp: "14:30:18" },
      { step: 3, offset: ".text+0x2C40", primitive: "AES-256-GCM", keyLength: "256", confidence: 0.91, timestamp: "14:30:22" },
      { step: 4, offset: ".text+0x3A80", primitive: "Poly1305 MAC", keyLength: "128", confidence: 0.88, timestamp: "14:30:25" },
      { step: 5, offset: ".text+0x4B20", primitive: "ECDSA Verify", keyLength: "256", confidence: 0.84, timestamp: "14:30:28" }
    ]
  },
  custom: {
    name: "Custom Protocol",
    anomalyScore: 0.67,
    nodes: [
      { id: "keygen", label: "KeyGen", offsets: [".text+0x1000"], confidence: 0.45, primitive: "Custom PRNG" },
      { id: "enc", label: "Encrypt", offsets: [".text+0x2000"], confidence: 0.72, primitive: "XOR Cipher" },
      { id: "hash", label: "Hash", offsets: [".text+0x3000"], confidence: 0.38, primitive: "MD5" }
    ],
    edges: [
      { from: "keygen", to: "enc" },
      { from: "enc", to: "hash" }
    ],
    sequence: [
      { step: 1, offset: ".text+0x1000", primitive: "Custom KeyGen", keyLength: "64", confidence: 0.45, timestamp: "14:25:10" },
      { step: 2, offset: ".text+0x2000", primitive: "XOR Encryption", keyLength: "64", confidence: 0.72, timestamp: "14:25:12" },
      { step: 3, offset: ".text+0x3000", primitive: "MD5 Hash", keyLength: "128", confidence: 0.38, timestamp: "14:25:15" }
    ]
  }
};

const ProtocolNode = ({ node, isSelected, onClick }: { node: any; isSelected: boolean; onClick: () => void }) => {
  const getNodeColor = (confidence: number) => {
    if (confidence >= 0.8) return "bg-success";
    if (confidence >= 0.6) return "bg-warning";
    return "bg-destructive";
  };

  return (
    <div
      className={`relative p-4 rounded-xl border-2 cursor-pointer transition-all ${
        isSelected 
          ? "border-primary bg-primary/10" 
          : "border-border hover:border-primary/50"
      }`}
      onClick={onClick}
    >
      <div className="flex items-center gap-2 mb-2">
        <div className={`w-3 h-3 rounded-full ${getNodeColor(node.confidence)}`} />
        <span className="font-medium">{node.label}</span>
        <Badge variant="outline" className="text-xs">
          {Math.round(node.confidence * 100)}%
        </Badge>
      </div>
      <div className="text-sm text-muted-foreground">
        {node.primitive}
      </div>
      <div className="text-xs text-muted-foreground mt-1">
        {node.offsets.join(", ")}
      </div>
    </div>
  );
};

const ProtocolGraph = ({ data }: { data: any }) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  return (
    <div className="h-96 bg-muted/20 rounded-xl p-4 relative overflow-hidden">
      <div className="absolute top-4 right-4 flex gap-2">
        <Button variant="outline" size="sm">
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button variant="outline" size="sm">
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button variant="outline" size="sm">
          <RotateCcw className="h-4 w-4" />
        </Button>
      </div>
      
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 h-full">
        {data.nodes.map((node: any) => (
          <ProtocolNode
            key={node.id}
            node={node}
            isSelected={selectedNode === node.id}
            onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
          />
        ))}
      </div>
    </div>
  );
};

const SequenceTimeline = ({ data }: { data: any }) => {
  return (
    <div className="space-y-4">
      {data.sequence.map((step: any, index: number) => (
        <Card key={index} className="enterprise-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-medium">
                  {step.step}
                </div>
                <div>
                  <div className="font-medium">{step.primitive}</div>
                  <div className="text-sm text-muted-foreground">{step.offset}</div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-sm font-medium">{step.keyLength}-bit</div>
                  <div className="text-xs text-muted-foreground">{step.timestamp}</div>
                </div>
                <Badge className={step.confidence >= 0.8 ? "enterprise-badge-success" : step.confidence >= 0.6 ? "enterprise-badge-warning" : "enterprise-badge-danger"}>
                  {Math.round(step.confidence * 100)}%
                </Badge>
                <Button variant="ghost" size="sm">
                  <Eye className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

const ProtocolMapping = () => {
  const [selectedProtocol, setSelectedProtocol] = useState("tls");
  const [showHighConfidence, setShowHighConfidence] = useState(false);
  const [showProprietary, setShowProprietary] = useState(true);

  const currentData = protocolData[selectedProtocol as keyof typeof protocolData];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="enterprise-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-3xl font-inter font-semibold">Protocol Mapping</h1>
          <div className="flex items-center gap-4">
            <Select value={selectedProtocol} onValueChange={setSelectedProtocol}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Select architecture" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="tls">TLS-like Protocol</SelectItem>
                <SelectItem value="custom">Custom Protocol</SelectItem>
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2">
              <Switch
                id="high-confidence"
                checked={showHighConfidence}
                onCheckedChange={setShowHighConfidence}
              />
              <Label htmlFor="high-confidence" className="text-sm">
                High Confidence Only
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="proprietary"
                checked={showProprietary}
                onCheckedChange={setShowProprietary}
              />
              <Label htmlFor="proprietary" className="text-sm">
                Show Proprietary
              </Label>
            </div>
            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export PNG
            </Button>
          </div>
        </div>
      </div>

      {/* Two-pane layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left: Interactive Graph */}
        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-5 w-5" />
              Interactive Protocol Graph
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ProtocolGraph data={currentData} />
          </CardContent>
        </Card>

        {/* Right: Sequence Timeline */}
        <Card className="enterprise-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Sequence Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <SequenceTimeline data={currentData} />
          </CardContent>
        </Card>
      </div>

      {/* Bottom insights strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="enterprise-card">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <div className="font-medium">Protocol Family</div>
                <Badge className="enterprise-badge-primary mt-1">
                  {currentData.name}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <Key className="h-8 w-8 text-warning" />
              <div>
                <div className="font-medium">Anomaly Score</div>
                <Badge className={currentData.anomalyScore > 0.5 ? "enterprise-badge-danger" : "enterprise-badge-success"} mt-1>
                  {Math.round(currentData.anomalyScore * 100)}%
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="enterprise-card">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <Lock className="h-8 w-8 text-success" />
              <div>
                <div className="font-medium">Security Level</div>
                <Badge className={`${currentData.anomalyScore > 0.5 ? "enterprise-badge-danger" : "enterprise-badge-success"} mt-1`}>
                  {currentData.anomalyScore > 0.5 ? "High Risk" : "Secure"}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sample content note */}
      <Card className="enterprise-card">
        <CardContent className="p-6">
          <div className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 text-success" />
            <div>
              <div className="font-medium">Sample Protocol Analysis</div>
              <div className="text-sm text-muted-foreground">
                This demonstrates both TLS-like and custom protocol detection with confidence scores and anomaly analysis.
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ProtocolMapping;
