"use client";

import { useState } from "react";
import { scanRepository } from "@/lib/api";
import { downloadJsonReport, downloadPdfReport } from "@/lib/report";
import type {
  Confidence,
  MigrationPlanItem,
  ModuleRiskSummary,
  RiskLevel,
  ScanResponse,
  Severity,
} from "@/types/scan";

function severityLabel(severity: Severity) {
  if (severity === "high") return "HIGH";
  if (severity === "medium") return "MEDIUM";
  return "LOW";
}

function riskLabel(risk: RiskLevel) {
  if (risk === "high") return "HIGH";
  if (risk === "medium") return "MEDIUM";
  if (risk === "low") return "LOW";
  return "NONE";
}

function confidenceLabel(confidence: Confidence) {
  if (confidence === "high") return "HIGH";
  if (confidence === "medium") return "MEDIUM";
  return "LOW";
}

function priorityLabel(priority: MigrationPlanItem["priority"]) {
  if (priority === "now") return "NOW";
  if (priority === "next") return "NEXT";
  return "LATER";
}

function normalizeModuleSummary(
  item: Partial<ModuleRiskSummary>
): ModuleRiskSummary {
  return {
    module: item.module ?? "unknown",
    overallRisk: item.overallRisk ?? "none",
    score: item.score ?? 0,
    confidence: item.confidence ?? "low",
    affectedFiles: item.affectedFiles ?? 0,
    findings: item.findings ?? 0,
    quantumFindings: item.quantumFindings ?? 0,
    weakCryptoFindings: item.weakCryptoFindings ?? 0,
    touchpoints: Array.isArray(item.touchpoints) ? item.touchpoints : [],
    sampleFiles: Array.isArray(item.sampleFiles) ? item.sampleFiles : [],
  };
}

function normalizeMigrationPlanItem(
  item: Partial<MigrationPlanItem>
): MigrationPlanItem {
  return {
    id: item.id ?? crypto.randomUUID(),
    title: item.title ?? "Untitled migration item",
    priority: item.priority ?? "later",
    currentState: item.currentState ?? "",
    whyRisky: item.whyRisky ?? "",
    recommendedTarget: item.recommendedTarget ?? "",
    scope: item.scope ?? "",
    notes: item.notes ?? "",
  };
}

function normalizeScanResponse(data: Partial<ScanResponse>): ScanResponse {
  return {
    ok: data.ok ?? false,
    repoUrl: data.repoUrl ?? "",
    branchScanned: data.branchScanned ?? "",
    message: data.message ?? "",
    summary: data.summary ?? "",
    overallRisk: data.overallRisk ?? "none",
    score: data.score ?? 0,
    confidence: data.confidence ?? "low",
    filesScanned: data.filesScanned ?? 0,
    sampleFiles: Array.isArray(data.sampleFiles) ? data.sampleFiles : [],
    affectedFiles: Array.isArray(data.affectedFiles) ? data.affectedFiles : [],
    touchpoints: Array.isArray(data.touchpoints) ? data.touchpoints : [],
    migrationActions: Array.isArray(data.migrationActions)
      ? data.migrationActions
      : [],
    migrationPlan: Array.isArray(data.migrationPlan)
      ? data.migrationPlan.map((item) => normalizeMigrationPlanItem(item))
      : [],
    findings: Array.isArray(data.findings) ? data.findings : [],
    moduleSummaries: Array.isArray(data.moduleSummaries)
      ? data.moduleSummaries.map((item) => normalizeModuleSummary(item))
      : [],
    counts: {
      totalFindings: data.counts?.totalFindings ?? 0,
      quantumFindings: data.counts?.quantumFindings ?? 0,
      weakCryptoFindings: data.counts?.weakCryptoFindings ?? 0,
      keyMaterialFindings: data.counts?.keyMaterialFindings ?? 0,
      pkiFindings: data.counts?.pkiFindings ?? 0,
      blockchainFindings: data.counts?.blockchainFindings ?? 0,
    },
  };
}

export default function HomePage() {
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await scanRepository(
        repoUrl,
        githubToken.trim() ? githubToken.trim() : undefined,
        branch.trim() ? branch.trim() : undefined
      );
      setResult(normalizeScanResponse(data));
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Something went wrong";
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  const affectedFiles = Array.isArray(result?.affectedFiles)
    ? result.affectedFiles
    : [];
  const migrationActions = Array.isArray(result?.migrationActions)
    ? result.migrationActions
    : [];
  const migrationPlan = Array.isArray(result?.migrationPlan)
    ? result.migrationPlan
    : [];
  const touchpoints = Array.isArray(result?.touchpoints)
    ? result.touchpoints
    : [];
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const sampleFiles = Array.isArray(result?.sampleFiles)
    ? result.sampleFiles
    : [];
  const moduleSummaries = Array.isArray(result?.moduleSummaries)
    ? result.moduleSummaries
    : [];

  return (
    <main className="min-h-screen bg-black text-white">
      <div className="mx-auto flex min-h-screen max-w-6xl flex-col px-6 py-10">
        <header className="mb-10 border-b border-white/10 pb-6">
          <p className="mb-3 text-xs uppercase tracking-[0.3em] text-zinc-500">
            Quantum Risk Audit MVP
          </p>

          <h1 className="max-w-3xl text-4xl font-semibold tracking-tight sm:text-5xl">
            Audit GitHub repositories for quantum-vulnerable cryptography
          </h1>

          <p className="mt-4 max-w-2xl text-sm leading-6 text-zinc-400">
            Paste a GitHub repository link. The system will fetch files, look for
            cryptographic touchpoints, flag risky usage, and prepare a simple
            migration-focused audit view.
          </p>
        </header>

        <section className="grid gap-6 lg:grid-cols-[1.4fr_0.6fr]">
          <div className="rounded-2xl border border-white/10 bg-zinc-950 p-6">
            <div className="mb-5">
              <h2 className="text-xl font-medium">Start a repository audit</h2>
              <p className="mt-2 text-sm text-zinc-400">
                This step supports public repos, private repos with a token,
                branch-specific scans, better risk scoring, and a migration plan.
              </p>
            </div>

            <form
              onSubmit={handleSubmit}
              className="space-y-4"
              autoComplete="off"
            >
              <input
                type="text"
                name="fake-username"
                autoComplete="username"
                tabIndex={-1}
                className="hidden"
                aria-hidden="true"
              />
              <input
                type="password"
                name="fake-password"
                autoComplete="new-password"
                tabIndex={-1}
                className="hidden"
                aria-hidden="true"
              />

              <div>
                <label
                  htmlFor="repoUrl"
                  className="mb-2 block text-sm text-zinc-300"
                >
                  GitHub repository link
                </label>

                <input
                  id="repoUrl"
                  name="repository-link"
                  type="url"
                  inputMode="url"
                  placeholder="https://github.com/owner/repository"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  data-lpignore="true"
                  data-1p-ignore="true"
                  className="w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-sm text-white outline-none transition focus:border-white/30"
                />
              </div>

              <div>
                <label
                  htmlFor="branch"
                  className="mb-2 block text-sm text-zinc-300"
                >
                  Branch (optional)
                </label>

                <input
                  id="branch"
                  name="branch-name"
                  type="text"
                  placeholder="Leave empty to use the repo default branch"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  className="w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-sm text-white outline-none transition focus:border-white/30"
                />
              </div>

              <div>
                <label
                  htmlFor="githubToken"
                  className="mb-2 block text-sm text-zinc-300"
                >
                  GitHub token (optional)
                </label>

                <input
                  id="githubToken"
                  name="github-token"
                  type="password"
                  placeholder="Only needed for private repos or higher rate limits"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  autoComplete="new-password"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  data-lpignore="true"
                  data-1p-ignore="true"
                  className="w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-sm text-white outline-none transition focus:border-white/30"
                />

                <p className="mt-2 text-xs text-zinc-500">
                  This token is only sent with the scan request. It is not shown
                  in the report output.
                </p>
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  type="submit"
                  disabled={loading}
                  className="rounded-xl border border-white bg-white px-5 py-3 text-sm font-medium text-black transition hover:bg-zinc-200 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? "Scanning..." : "Scan repository"}
                </button>

                {result && (
                  <>
                    <button
                      type="button"
                      onClick={() => downloadJsonReport(result)}
                      className="rounded-xl border border-white/20 px-5 py-3 text-sm font-medium text-white transition hover:border-white/40"
                    >
                      Export JSON
                    </button>

                    <button
                      type="button"
                      onClick={() => downloadPdfReport(result)}
                      className="rounded-xl border border-white/20 px-5 py-3 text-sm font-medium text-white transition hover:border-white/40"
                    >
                      Export PDF
                    </button>
                  </>
                )}
              </div>
            </form>

            <div className="mt-6 space-y-4">
              {!loading && !error && !result && (
                <div className="rounded-xl border border-dashed border-white/10 bg-black/40 p-4">
                  <p className="text-sm text-zinc-500">
                    Status: waiting for scan request
                  </p>
                </div>
              )}

              {error && (
                <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                  <p className="text-sm text-white">{error}</p>
                </div>
              )}

              {result && (
                <div className="space-y-4">
                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <p className="break-all text-sm text-zinc-300">
                      <span className="text-zinc-500">Repository:</span>{" "}
                      {result.repoUrl}
                    </p>
                    <p className="mt-2 text-sm text-zinc-300">
                      <span className="text-zinc-500">Branch scanned:</span>{" "}
                      {result.branchScanned || "unknown"}
                    </p>
                    <p className="mt-2 text-sm text-zinc-300">
                      <span className="text-zinc-500">Message:</span>{" "}
                      {result.message}
                    </p>
                    <p className="mt-2 text-sm text-zinc-300">
                      <span className="text-zinc-500">Summary:</span>{" "}
                      {result.summary || "No summary yet."}
                    </p>

                    <div className="mt-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-8">
                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Files
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {result.filesScanned}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Branch
                        </p>
                        <p className="mt-2 truncate text-2xl font-semibold">
                          {result.branchScanned || "-"}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Score
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {result.score}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Confidence
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {confidenceLabel(result.confidence)}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Touchpoints
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {touchpoints.length}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Findings
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {findings.length}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Quantum
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {result.counts.quantumFindings}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Risk
                        </p>
                        <p className="mt-2 text-2xl font-semibold">
                          {riskLabel(result.overallRisk)}
                        </p>
                      </div>
                    </div>

                    <div className="mt-4 grid gap-3 sm:grid-cols-4">
                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Weak crypto
                        </p>
                        <p className="mt-2 text-lg font-semibold">
                          {result.counts.weakCryptoFindings}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Key material
                        </p>
                        <p className="mt-2 text-lg font-semibold">
                          {result.counts.keyMaterialFindings}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          PKI
                        </p>
                        <p className="mt-2 text-lg font-semibold">
                          {result.counts.pkiFindings}
                        </p>
                      </div>

                      <div className="rounded-lg border border-white/10 p-3">
                        <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                          Blockchain
                        </p>
                        <p className="mt-2 text-lg font-semibold">
                          {result.counts.blockchainFindings}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Migration plan
                    </h3>

                    {migrationPlan.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No migration plan items generated.
                      </p>
                    ) : (
                      <div className="mt-3 space-y-3">
                        {migrationPlan.map((item) => (
                          <div
                            key={item.id}
                            className="rounded-lg border border-white/10 p-4"
                          >
                            <div className="flex flex-wrap items-center gap-3">
                              <p className="text-sm font-medium text-white">
                                {item.title}
                              </p>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                {priorityLabel(item.priority)}
                              </span>
                            </div>

                            <p className="mt-3 text-sm text-zinc-300">
                              <span className="text-zinc-500">
                                Current state:
                              </span>{" "}
                              {item.currentState}
                            </p>

                            <p className="mt-3 text-sm text-zinc-300">
                              <span className="text-zinc-500">Why risky:</span>{" "}
                              {item.whyRisky}
                            </p>

                            <p className="mt-3 text-sm text-zinc-300">
                              <span className="text-zinc-500">
                                Recommended target:
                              </span>{" "}
                              {item.recommendedTarget}
                            </p>

                            <p className="mt-3 text-sm text-zinc-300">
                              <span className="text-zinc-500">Scope:</span>{" "}
                              {item.scope}
                            </p>

                            <p className="mt-3 text-sm text-zinc-400">
                              <span className="text-zinc-500">Notes:</span>{" "}
                              {item.notes}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Module risk map
                    </h3>

                    {moduleSummaries.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No affected modules found.
                      </p>
                    ) : (
                      <div className="mt-3 space-y-3">
                        {moduleSummaries.map((moduleItem) => (
                          <div
                            key={moduleItem.module}
                            className="rounded-lg border border-white/10 p-4"
                          >
                            <div className="flex flex-wrap items-center gap-3">
                              <p className="text-sm font-medium text-white">
                                {moduleItem.module}
                              </p>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                {riskLabel(moduleItem.overallRisk)}
                              </span>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                SCORE {moduleItem.score}
                              </span>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                {confidenceLabel(moduleItem.confidence)}
                              </span>
                            </div>

                            <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                              <div className="rounded-lg border border-white/10 p-3">
                                <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                                  Files
                                </p>
                                <p className="mt-2 text-lg font-semibold">
                                  {moduleItem.affectedFiles}
                                </p>
                              </div>

                              <div className="rounded-lg border border-white/10 p-3">
                                <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                                  Findings
                                </p>
                                <p className="mt-2 text-lg font-semibold">
                                  {moduleItem.findings}
                                </p>
                              </div>

                              <div className="rounded-lg border border-white/10 p-3">
                                <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                                  Quantum
                                </p>
                                <p className="mt-2 text-lg font-semibold">
                                  {moduleItem.quantumFindings}
                                </p>
                              </div>

                              <div className="rounded-lg border border-white/10 p-3">
                                <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                                  Weak crypto
                                </p>
                                <p className="mt-2 text-lg font-semibold">
                                  {moduleItem.weakCryptoFindings}
                                </p>
                              </div>

                              <div className="rounded-lg border border-white/10 p-3">
                                <p className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                                  Touchpoints
                                </p>
                                <p className="mt-2 text-lg font-semibold">
                                  {moduleItem.touchpoints.length}
                                </p>
                              </div>
                            </div>

                            <p className="mt-3 text-xs text-zinc-500">
                              {moduleItem.touchpoints.join(", ") ||
                                "No touchpoints"}
                            </p>

                            {moduleItem.sampleFiles.length > 0 && (
                              <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                                {moduleItem.sampleFiles.map((file) => (
                                  <li key={file} className="break-all">
                                    - {file}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Affected files
                    </h3>

                    {affectedFiles.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No affected files found.
                      </p>
                    ) : (
                      <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                        {affectedFiles.map((file) => (
                          <li key={file} className="break-all">
                            - {file}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Migration actions
                    </h3>

                    {migrationActions.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No migration actions generated.
                      </p>
                    ) : (
                      <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                        {migrationActions.map((action) => (
                          <li key={action}>- {action}</li>
                        ))}
                      </ul>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Crypto touchpoints
                    </h3>

                    {touchpoints.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No touchpoints found.
                      </p>
                    ) : (
                      <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                        {touchpoints.map((item) => (
                          <li key={item}>- {item}</li>
                        ))}
                      </ul>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Findings
                    </h3>

                    {findings.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No flagged items found in this scan.
                      </p>
                    ) : (
                      <div className="mt-3 space-y-3">
                        {findings.map((finding) => (
                          <div
                            key={finding.id}
                            className="rounded-lg border border-white/10 p-4"
                          >
                            <div className="flex flex-wrap items-center gap-3">
                              <p className="text-sm font-medium text-white">
                                {finding.title}
                              </p>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                {severityLabel(finding.severity)}
                              </span>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                {confidenceLabel(finding.confidence)}
                              </span>
                              <span className="rounded-full border border-white/20 px-2 py-1 text-[10px] tracking-[0.2em] text-zinc-300">
                                {finding.category}
                              </span>
                            </div>

                            {finding.file && (
                              <p className="mt-3 break-all text-xs text-zinc-500">
                                {finding.file}
                                {finding.line ? ` : line ${finding.line}` : ""}
                              </p>
                            )}

                            <p className="mt-3 text-sm text-zinc-300">
                              {finding.description}
                            </p>

                            <p className="mt-3 text-sm text-zinc-400">
                              <span className="text-zinc-500">Why flagged:</span>{" "}
                              {finding.rationale}
                            </p>

                            <p className="mt-3 text-sm text-zinc-400">
                              <span className="text-zinc-500">
                                Recommendation:
                              </span>{" "}
                              {finding.recommendation}
                            </p>

                            {finding.snippet && (
                              <pre className="mt-3 overflow-x-auto rounded-lg border border-white/10 bg-black p-3 text-xs text-zinc-300">
                                <code>{finding.snippet}</code>
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                    <h3 className="text-sm font-semibold text-white">
                      Fetched files preview
                    </h3>

                    {sampleFiles.length === 0 ? (
                      <p className="mt-3 text-sm text-zinc-500">
                        No files fetched yet.
                      </p>
                    ) : (
                      <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                        {sampleFiles.map((file) => (
                          <li key={file} className="break-all">
                            - {file}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          <aside className="space-y-6">
            <div className="rounded-2xl border border-white/10 bg-zinc-950 p-5">
              <h3 className="text-sm font-semibold text-white">
                MVP flow locked
              </h3>

              <ul className="mt-3 space-y-2 text-sm text-zinc-400">
                <li>1. Paste repo link</li>
                <li>2. Fetch repo files</li>
                <li>3. Scan crypto touchpoints</li>
                <li>4. Flag quantum risk</li>
                <li>5. Show affected files</li>
                <li>6. Suggest migration actions</li>
                <li>7. Generate audit report</li>
              </ul>
            </div>

            <div className="rounded-2xl border border-white/10 bg-zinc-950 p-5">
              <h3 className="text-sm font-semibold text-white">
                What this MVP is
              </h3>
              <p className="mt-3 text-sm leading-6 text-zinc-400">
                A small first version focused on GitHub repo link input, repo
                analysis, crypto discovery, quantum risk flagging, and simple
                reporting.
              </p>
            </div>
          </aside>
        </section>
      </div>
    </main>
  );
}