import { Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export const UploadCard = () => {
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      toast.success(`Processing ${files[0].name}...`, {
        description: "Firmware analysis started"
      });
    }
  };

  return (
    <div className="cyber-card p-8 text-center border-dashed border-2 hover:border-primary/50 transition-all cursor-pointer group">
      <input 
        type="file" 
        id="firmware-upload" 
        className="hidden" 
        accept=".bin,.elf,.hex"
        onChange={handleFileUpload}
      />
      <label htmlFor="firmware-upload" className="cursor-pointer">
        <div className="flex flex-col items-center gap-4">
          <div className="p-6 rounded-full bg-primary/10 border-2 border-primary/30 group-hover:border-primary group-hover:bg-primary/20 transition-all">
            <Upload className="h-12 w-12 text-primary" />
          </div>
          <div>
            <h3 className="text-xl font-orbitron font-bold mb-2">Upload Firmware</h3>
            <p className="text-muted-foreground mb-4">
              Drag & drop or click to browse
            </p>
            <p className="text-sm text-muted-foreground">
              Supports .bin, .elf, .hex files
            </p>
          </div>
          <Button className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold">
            Select File
          </Button>
        </div>
      </label>
    </div>
  );
};
