import { useEffect, useState } from "react";
import { AlertCircle, CheckCircle, Download, Loader2, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { API_BASE_URL, checkHealth, runProprietaryInference, runStandardInference } from "@/lib/api";

type ModelType = "proprietary" | "standard";
type ApiStatus = "checking" | "ready" | "error";

export const ModelInference = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [modelType, setModelType] = useState<ModelType>("proprietary");
  const [processing, setProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");

  useEffect(() => {
    let mounted = true;

    checkHealth()
      .then((health) => {
        if (!mounted) {
          return;
        }
        setApiStatus(health.status === "ok" ? "ready" : "error");
      })
      .catch(() => {
        if (mounted) {
          setApiStatus("error");
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] || null;

    if (!file) {
      setSelectedFile(null);
      return;
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
      toast.error("Please select a CSV file.");
      event.target.value = "";
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleInference = async () => {
    if (!selectedFile) {
      toast.error("Please select a CSV file first.");
      return;
    }

    setProcessing(true);
    setProgress(0);

    const progressInterval = window.setInterval(() => {
      setProgress((previous) => {
        if (previous >= 90) {
          window.clearInterval(progressInterval);
          return 90;
        }
        return previous + 10;
      });
    }, 400);

    try {
      if (modelType === "proprietary") {
        await runProprietaryInference(selectedFile);
      } else {
        await runStandardInference(selectedFile);
      }

      setProgress(100);
      toast.success("Analysis complete. CSV download started.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Analysis failed.");
      setProgress(0);
    } finally {
      window.clearInterval(progressInterval);
      window.setTimeout(() => {
        setProcessing(false);
        setProgress(0);
      }, 800);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-2xl font-semibold mb-2">Run Model Inference</h2>
        <p className="text-muted-foreground">
          Upload a CSV dataset and download the model output as a CSV file.
        </p>
        <p className="text-sm text-muted-foreground mt-2">
          Backend: <code>{API_BASE_URL}</code>
        </p>
      </div>

      {apiStatus === "checking" && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Checking API connection...
        </div>
      )}

      {apiStatus === "ready" && (
        <div className="flex items-center gap-2 text-sm text-emerald-500">
          <CheckCircle className="h-4 w-4" />
          API server is reachable.
        </div>
      )}

      {apiStatus === "error" && (
        <div className="flex items-center gap-2 text-sm text-destructive">
          <AlertCircle className="h-4 w-4" />
          API server is not reachable. Start <code>api_server.py</code> first.
        </div>
      )}

      <div className="flex gap-4">
        <Button
          variant={modelType === "proprietary" ? "default" : "outline"}
          onClick={() => setModelType("proprietary")}
          disabled={processing}
        >
          Proprietary Model
        </Button>
        <Button
          variant={modelType === "standard" ? "default" : "outline"}
          onClick={() => setModelType("standard")}
          disabled={processing}
        >
          Standard Model
        </Button>
      </div>

      <div className="border-2 border-dashed rounded-lg p-8 text-center">
        <input
          id="csv-upload"
          type="file"
          accept=".csv"
          onChange={handleFileSelect}
          disabled={processing}
          className="hidden"
        />
        <label htmlFor="csv-upload">
          <div className="flex flex-col items-center gap-4 cursor-pointer">
            <Upload className="h-12 w-12 text-muted-foreground" />
            <div>
              <p className="font-medium">
                {selectedFile ? selectedFile.name : "Select a CSV file"}
              </p>
              <p className="text-sm text-muted-foreground">
                {selectedFile ? `${(selectedFile.size / 1024).toFixed(2)} KB` : "Click to browse"}
              </p>
            </div>
          </div>
        </label>
      </div>

      {processing && (
        <div className="space-y-2">
          <Progress value={progress} />
          <p className="text-sm text-muted-foreground">Processing... {progress}%</p>
        </div>
      )}

      <Button
        onClick={handleInference}
        disabled={!selectedFile || processing || apiStatus !== "ready"}
        className="w-full"
        size="lg"
      >
        {processing ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Processing...
          </>
        ) : (
          <>
            <Download className="mr-2 h-4 w-4" />
            Run Analysis and Download CSV
          </>
        )}
      </Button>
    </div>
  );
};
