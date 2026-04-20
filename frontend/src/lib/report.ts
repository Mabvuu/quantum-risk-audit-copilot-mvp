import { jsPDF } from "jspdf";
import type { ScanResponse } from "@/types/scan";

function getRepoSlug(repoUrl: string): string {
  try {
    const parsed = new URL(repoUrl);
    const parts = parsed.pathname.split("/").filter(Boolean);

    if (parts.length >= 2) {
      return `${parts[0]}-${parts[1]}`;
    }

    return "quantum-risk-audit-report";
  } catch {
    return "quantum-risk-audit-report";
  }
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9-_]/gi, "-").toLowerCase();
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
}

export function downloadJsonReport(result: ScanResponse) {
  const baseName = safeFileName(getRepoSlug(result.repoUrl));
  const blob = new Blob([JSON.stringify(result, null, 2)], {
    type: "application/json",
  });

  downloadBlob(`${baseName}-audit-report.json`, blob);
}

export function downloadPdfReport(result: ScanResponse) {
  const doc = new jsPDF({
    unit: "pt",
    format: "a4",
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  function ensureSpace(heightNeeded: number) {
    if (y + heightNeeded > pageHeight - margin) {
      doc.addPage();
      y = margin;
    }
  }

  function addText(
    text: string,
    options?: {
      size?: number;
      bold?: boolean;
      gapAfter?: number;
    }
  ) {
    const size = options?.size ?? 11;
    const bold = options?.bold ?? false;
    const gapAfter = options?.gapAfter ?? 8;

    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setFontSize(size);

    const lines = doc.splitTextToSize(text, contentWidth);
    const lineHeight = size + 4;
    const blockHeight = lines.length * lineHeight;

    ensureSpace(blockHeight + gapAfter);
    doc.text(lines, margin, y);
    y += blockHeight + gapAfter;
  }

  function addSection(title: string) {
    y += 6;
    addText(title, { size: 14, bold: true, gapAfter: 10 });
  }

  function addList(items: string[]) {
    if (items.length === 0) {
      addText("None.");
      return;
    }

    items.forEach((item) => {
      addText(`- ${item}`, { size: 11, gapAfter: 6 });
    });
  }

  const reportDate = new Date().toLocaleString();
  const baseName = safeFileName(getRepoSlug(result.repoUrl));

  addText("Quantum Risk Audit Report", {
    size: 20,
    bold: true,
    gapAfter: 14,
  });

  addText(`Repository: ${result.repoUrl}`);
  addText(`Branch: ${result.branchScanned || "unknown"}`);
  addText(`Generated: ${reportDate}`);
  addText(`Overall Risk: ${result.overallRisk.toUpperCase()}`);
  addText(`Score: ${result.score}/100`);
  addText(`Confidence: ${result.confidence.toUpperCase()}`);
  addText(result.summary || "No summary available.");

  addSection("Scan Stats");
  addText(`Files Scanned: ${result.filesScanned}`);
  addText(`Touchpoints Found: ${result.touchpoints.length}`);
  addText(`Flagged Findings: ${result.findings.length}`);
  addText(`Affected Files: ${result.affectedFiles.length}`);
  addText(`Affected Modules: ${result.moduleSummaries.length}`);

  addSection("Finding Breakdown");
  addText(`Total Findings: ${result.counts.totalFindings}`);
  addText(`Quantum Findings: ${result.counts.quantumFindings}`);
  addText(`Weak Crypto Findings: ${result.counts.weakCryptoFindings}`);
  addText(`Key Material Findings: ${result.counts.keyMaterialFindings}`);
  addText(`PKI Findings: ${result.counts.pkiFindings}`);
  addText(`Blockchain Findings: ${result.counts.blockchainFindings}`);

  addSection("Migration Plan");
  if (result.migrationPlan.length === 0) {
    addText("No migration plan items generated.");
  } else {
    result.migrationPlan.forEach((item, index) => {
      addText(
        `${index + 1}. ${item.title} (${item.priority.toUpperCase()})`,
        {
          size: 12,
          bold: true,
          gapAfter: 6,
        }
      );
      addText(`Current State: ${item.currentState}`, { gapAfter: 6 });
      addText(`Why Risky: ${item.whyRisky}`, { gapAfter: 6 });
      addText(`Recommended Target: ${item.recommendedTarget}`, {
        gapAfter: 6,
      });
      addText(`Scope: ${item.scope}`, { gapAfter: 6 });
      addText(`Notes: ${item.notes}`, { gapAfter: 10 });
    });
  }

  addSection("Module Risk Map");
  if (result.moduleSummaries.length === 0) {
    addText("No affected modules found.");
  } else {
    result.moduleSummaries.forEach((moduleItem, index) => {
      addText(
        `${index + 1}. ${moduleItem.module} (${moduleItem.overallRisk.toUpperCase()})`,
        {
          size: 12,
          bold: true,
          gapAfter: 6,
        }
      );
      addText(
        `Score: ${moduleItem.score} | Confidence: ${moduleItem.confidence.toUpperCase()}`,
        { gapAfter: 6 }
      );
      addText(
        `Affected Files: ${moduleItem.affectedFiles} | Findings: ${moduleItem.findings}`,
        { gapAfter: 6 }
      );
      addText(
        `Quantum Findings: ${moduleItem.quantumFindings} | Weak Crypto Findings: ${moduleItem.weakCryptoFindings}`,
        { gapAfter: 6 }
      );
      addText(`Touchpoints: ${moduleItem.touchpoints.join(", ") || "None"}`, {
        gapAfter: 6,
      });
      addText(`Examples: ${moduleItem.sampleFiles.join(", ") || "None"}`, {
        gapAfter: 10,
      });
    });
  }

  addSection("Migration Actions");
  addList(result.migrationActions);

  addSection("Crypto Touchpoints");
  addList(result.touchpoints);

  addSection("Affected Files");
  addList(result.affectedFiles);

  addSection("Findings");

  if (result.findings.length === 0) {
    addText("No flagged findings in this scan.");
  } else {
    result.findings.forEach((finding, index) => {
      addText(
        `${index + 1}. ${finding.title} (${finding.severity.toUpperCase()})`,
        {
          size: 12,
          bold: true,
          gapAfter: 6,
        }
      );

      addText(
        `Category: ${finding.category} | Confidence: ${finding.confidence.toUpperCase()}`,
        { gapAfter: 6 }
      );

      if (finding.file) {
        addText(
          `File: ${finding.file}${finding.line ? ` | Line: ${finding.line}` : ""}`,
          { gapAfter: 6 }
        );
      }

      addText(`Description: ${finding.description}`, { gapAfter: 6 });
      addText(`Why Flagged: ${finding.rationale}`, { gapAfter: 6 });
      addText(`Recommendation: ${finding.recommendation}`, { gapAfter: 6 });

      if (finding.snippet) {
        addText(`Snippet: ${finding.snippet}`, { gapAfter: 10 });
      }
    });
  }

  addSection("Fetched Files Preview");
  addList(result.sampleFiles);

  doc.save(`${baseName}-audit-report.pdf`);
}