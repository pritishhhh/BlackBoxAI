import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const recentActivity = [
  { 
    name: "iot_device_v3.2.bin", 
    arch: "ARM Cortex-M4", 
    date: "2025-01-15", 
    risk: 85, 
    status: "Critical" 
  },
  { 
    name: "router_firmware.elf", 
    arch: "MIPS", 
    date: "2025-01-15", 
    risk: 42, 
    status: "Medium" 
  },
  { 
    name: "smart_camera.hex", 
    arch: "ARM Cortex-A53", 
    date: "2025-01-14", 
    risk: 23, 
    status: "Low" 
  },
  { 
    name: "industrial_plc.bin", 
    arch: "x86-64", 
    date: "2025-01-14", 
    risk: 91, 
    status: "Critical" 
  },
  { 
    name: "wearable_fw.bin", 
    arch: "RISC-V", 
    date: "2025-01-13", 
    risk: 15, 
    status: "Low" 
  },
];

const getRiskColor = (risk: number) => {
  if (risk >= 70) return "destructive";
  if (risk >= 40) return "secondary";
  return "outline";
};

export const ActivityTable = () => {
  return (
    <div className="cyber-card">
      <div className="p-6 border-b border-border">
        <h3 className="text-xl font-orbitron font-bold">Recent Firmware Activity</h3>
      </div>
      <Table>
        <TableHeader>
          <TableRow className="border-border hover:bg-transparent">
            <TableHead className="text-muted-foreground">File Name</TableHead>
            <TableHead className="text-muted-foreground">Architecture</TableHead>
            <TableHead className="text-muted-foreground">Date</TableHead>
            <TableHead className="text-muted-foreground">Risk Score</TableHead>
            <TableHead className="text-muted-foreground">Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {recentActivity.map((item, i) => (
            <TableRow key={i} className="border-border hover:bg-muted/50">
              <TableCell className="font-medium terminal-text">{item.name}</TableCell>
              <TableCell>{item.arch}</TableCell>
              <TableCell className="text-muted-foreground">{item.date}</TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-gradient-to-r from-success via-secondary to-destructive"
                      style={{ width: `${item.risk}%` }}
                    />
                  </div>
                  <span className="text-sm font-bold w-8">{item.risk}</span>
                </div>
              </TableCell>
              <TableCell>
                <Badge variant={getRiskColor(item.risk)}>
                  {item.status}
                </Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};
