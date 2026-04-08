export const API_BASE_URL = (import.meta.env.VITE_API_URL || "http://localhost:5000").replace(/\/$/, "");

export interface HealthResponse {
  status: string;
  proprietary_loaded: boolean;
  standard_loaded: boolean;
}

async function downloadCsv(endpoint: string, file: File, prefix: string): Promise<void> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${prefix}_results_${Date.now()}.csv`;
  document.body.appendChild(anchor);
  anchor.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(anchor);
}

export function runProprietaryInference(file: File): Promise<void> {
  return downloadCsv("/api/proprietary/inference", file, "proprietary");
}

export function runStandardInference(file: File): Promise<void> {
  return downloadCsv("/api/standard/inference", file, "standard");
}

export async function checkHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/health`);
  if (!response.ok) {
    throw new Error("API health check failed");
  }
  return response.json();
}
