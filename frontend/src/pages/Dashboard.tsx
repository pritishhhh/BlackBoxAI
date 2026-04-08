import { Activity, AlertTriangle, CheckCircle, FileSearch } from "lucide-react";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { UploadCard } from "@/components/dashboard/UploadCard";
import { ActivityTable } from "@/components/dashboard/ActivityTable";

const Dashboard = () => {
  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <div className="enterprise-card p-8">
        <h1 className="text-4xl font-inter font-semibold mb-2">
          Cryptographic Intelligence Engine
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced firmware analysis and threat detection platform
        </p>
      </div>

      {/* Upload Section */}
      <UploadCard />

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Firmware Analyzed"
          value="1,247"
          icon={FileSearch}
          trend="+12% this month"
          trendUp={true}
        />
        <MetricCard
          title="Detection Accuracy"
          value="98.7%"
          icon={CheckCircle}
          trend="+2.3% improvement"
          trendUp={true}
        />
        <MetricCard
          title="Weak Crypto Detected"
          value="34"
          icon={AlertTriangle}
          trend="↑ 8 this week"
          trendUp={false}
        />
        <MetricCard
          title="Active Scans"
          value="12"
          icon={Activity}
          trend="Live monitoring"
        />
      </div>

      {/* Crypto Heatmap */}
      <div className="enterprise-card p-6">
        <h3 className="text-xl font-inter font-semibold mb-6">
          Cryptographic Primitives Detection
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
          {[
            { name: "AES", count: 423, color: "bg-success" },
            { name: "RSA", count: 187, color: "bg-primary" },
            { name: "ECC", count: 156, color: "bg-secondary" },
            { name: "SHA-256", count: 312, color: "bg-success" },
            { name: "SHA-1", count: 89, color: "bg-destructive" },
            { name: "MD5", count: 45, color: "bg-destructive" },
            { name: "PRNG", count: 234, color: "bg-accent" },
            { name: "XOR", count: 67, color: "bg-secondary" },
          ].map((crypto) => (
            <div
              key={crypto.name}
              className="enterprise-card p-4 text-center hover:scale-105 transition-transform cursor-pointer"
            >
              <div className={`w-12 h-12 rounded-lg ${crypto.color} mx-auto mb-2 flex items-center justify-center text-lg font-bold`}>
                {crypto.count}
              </div>
              <p className="text-sm font-medium">{crypto.name}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Activity Table */}
      <ActivityTable />
    </div>
  );
};

export default Dashboard;
