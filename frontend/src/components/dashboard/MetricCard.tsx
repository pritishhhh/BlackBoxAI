import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  trendUp?: boolean;
  className?: string;
}

export const MetricCard = ({ 
  title, 
  value, 
  icon: Icon, 
  trend, 
  trendUp,
  className 
}: MetricCardProps) => {
  return (
    <div className={cn("cyber-card p-6 hover:border-primary/50 transition-all", className)}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted-foreground mb-1">{title}</p>
          <h3 className="text-3xl font-bold font-orbitron text-foreground">{value}</h3>
          {trend && (
            <p className={cn(
              "text-sm mt-2",
              trendUp ? "text-success" : "text-destructive"
            )}>
              {trend}
            </p>
          )}
        </div>
        <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
          <Icon className="h-6 w-6 text-primary" />
        </div>
      </div>
    </div>
  );
};
