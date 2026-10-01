"use client";

import { useState } from "react";
import { FileDown } from "lucide-react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { clientApiDownload } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";

const FORMATS = [
  { value: "markdown", label: "Markdown" },
  { value: "html", label: "HTML" },
  { value: "pdf", label: "PDF" },
  { value: "json", label: "JSON" },
  { value: "sarif", label: "SARIF" },
  { value: "csv", label: "CSV" },
] as const;

const TEMPLATES = [
  { value: "technical", label: "Technical" },
  { value: "executive", label: "Executive" },
  { value: "developer", label: "Developer" },
  { value: "compliance", label: "Compliance" },
] as const;

export function ReportDownload({
  organizationId,
  runId,
}: {
  organizationId: string;
  runId: string;
}) {
  const [format, setFormat] = useState<string>("markdown");
  const [template, setTemplate] = useState<string>("technical");
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onDownload() {
    setIsDownloading(true);
    setError(null);
    try {
      const { blob, filename } = await clientApiDownload(
        `/organizations/${organizationId}/runs/${runId}/report?report_format=${format}&template=${template}`,
      );
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (thrown) {
      if (thrown instanceof ApiError && thrown.status === 501) {
        setError("PDF rendering isn't available on this deployment. Try another format.");
      } else if (thrown instanceof ApiError) {
        setError(thrown.message);
      } else {
        setError("Could not download the report. Try again.");
      }
    } finally {
      setIsDownloading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <FileDown className="h-4 w-4 text-muted-foreground" aria-hidden />
          <CardTitle>Report</CardTitle>
        </div>
        <CardDescription>
          The same findings, in the format and audience template you need — executive PDF and
          the SARIF upload are built from the same underlying report.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="report-format">Format</Label>
            <Select
              id="report-format"
              value={format}
              onChange={(event) => setFormat(event.target.value)}
            >
              {FORMATS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="report-template">Audience</Label>
            <Select
              id="report-template"
              value={template}
              onChange={(event) => setTemplate(event.target.value)}
            >
              {TEMPLATES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </div>
        </div>
        {error && <Alert tone="destructive">{error}</Alert>}
        <Button type="button" size="sm" onClick={onDownload} isLoading={isDownloading} className="self-start">
          {isDownloading ? "Preparing..." : "Download report"}
        </Button>
      </CardContent>
    </Card>
  );
}
