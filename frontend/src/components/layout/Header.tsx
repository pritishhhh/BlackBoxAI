import { Bell, Search, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export const Header = () => {
  return (
    <header className="fixed top-0 right-0 left-64 h-16 bg-card/50 backdrop-blur-md border-b border-border z-40 px-6">
      <div className="flex items-center justify-between h-full">
        {/* Search */}
        <div className="flex-1 max-w-xl">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input 
              placeholder="Search firmware, protocols, or analysis..." 
              className="pl-10 bg-input border-border focus:border-primary"
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" className="relative hover:bg-muted">
            <Bell className="h-5 w-5" />
            <span className="absolute top-1 right-1 h-2 w-2 bg-destructive rounded-full"></span>
          </Button>
          
          <div className="flex items-center gap-3 pl-4 border-l border-border">
            <div className="text-right">
              <p className="text-sm font-medium">Security Admin</p>
              <p className="text-xs text-muted-foreground">admin@blackbox.ai</p>
            </div>
            <Button variant="ghost" size="icon" className="rounded-full bg-primary/10 hover:bg-primary/20">
              <User className="h-5 w-5 text-primary" />
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
};
