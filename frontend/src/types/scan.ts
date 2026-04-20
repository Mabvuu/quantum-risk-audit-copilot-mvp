export type Severity = "low" | "medium" | "high";
export type RiskLevel = "none" | "low" | "medium" | "high";
export type Confidence = "low" | "medium" | "high";
export type MigrationPriority = "now" | "next" | "later";

export type FindingCategory =
  | "quantum-vulnerable-public-key"
  | "classical-pki"
  | "hardcoded-key-material"
  | "weak-hash"
  | "weak-symmetric"
  | "symmetric-margin"
  | "blockchain-signing";

export type ScanFinding = {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  description: string;
  recommendation: string;
  rationale: string;
  file?: string;
  line?: number;
  snippet?: string;
};

export type ModuleRiskSummary = {
  module: string;
  overallRisk: RiskLevel;
  score: number;
  confidence: Confidence;
  affectedFiles: number;
  findings: number;
  quantumFindings: number;
  weakCryptoFindings: number;
  touchpoints: string[];
  sampleFiles: string[];
};

export type ScanCounts = {
  totalFindings: number;
  quantumFindings: number;
  weakCryptoFindings: number;
  keyMaterialFindings: number;
  pkiFindings: number;
  blockchainFindings: number;
};

export type MigrationPlanItem = {
  id: string;
  title: string;
  priority: MigrationPriority;
  currentState: string;
  whyRisky: string;
  recommendedTarget: string;
  scope: string;
  notes: string;
};

export type ScanResponse = {
  ok: boolean;
  repoUrl: string;
  branchScanned: string;
  message: string;
  summary: string;
  overallRisk: RiskLevel;
  score: number;
  confidence: Confidence;
  filesScanned: number;
  sampleFiles: string[];
  affectedFiles: string[];
  touchpoints: string[];
  migrationActions: string[];
  migrationPlan: MigrationPlanItem[];
  findings: ScanFinding[];
  moduleSummaries: ModuleRiskSummary[];
  counts: ScanCounts;
};