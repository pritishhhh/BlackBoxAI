import { Database, Download, FileSpreadsheet } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ModelInference } from "@/components/ModelInference";

const cards = [
  {
    title: "Input Format",
    icon: FileSpreadsheet,
    description: "Upload a CSV file. The local API expects CSV input and returns CSV outputs.",
  },
  {
    title: "Processing",
    icon: Database,
    description: "Choose the standard or proprietary model and run local inference through the Flask backend.",
  },
  {
    title: "Output",
    icon: Download,
    description: "A results CSV is downloaded automatically when the selected model finishes processing.",
  },
];

const Upload = () => {
  return (
    <div className="space-y-8">
      <div className="enterprise-card p-6">
        <h1 className="text-3xl font-inter font-semibold">Dataset Upload</h1>
        <p className="text-muted-foreground mt-2">
          Run local model inference against CSV inputs using the backend in this repository.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {cards.map((card) => (
          <Card key={card.title} className="enterprise-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <card.icon className="h-5 w-5 text-primary" />
                {card.title}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">{card.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <ModelInference />

      <Card className="enterprise-card">
        <CardHeader>
          <CardTitle>CSV Conventions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>The backend can infer defaults when optional fields are missing.</p>
          <p>Recognized identifiers include <code>fileId</code>, <code>file_id</code>, <code>id</code>, and <code>ID</code>.</p>
          <p>Recognized size columns include <code>codeSize</code>, <code>code_size</code>, <code>size</code>, and <code>fileSize</code>.</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default Upload;
