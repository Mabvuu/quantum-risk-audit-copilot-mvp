import type {
  Confidence,
  FindingCategory,
  MigrationPlanItem,
  MigrationPriority,
  ModuleRiskSummary,
  RepoFile,
  RiskLevel,
  ScanCounts,
  ScanFinding,
  ScanResponse,
  Severity,
} from "../types/scan";
import { fetchRepoFiles, normalizeGithubRepoUrl } from "./githubService";

type TouchpointRule = {
  label: string;
  matcher: (file: RepoFile) => boolean;
};

type FindingRule = {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  description: string;
  recommendation: string;
  rationale: string;
  matcher: (file: RepoFile) => boolean;
  lineInfo: (file: RepoFile) => { line?: number; snippet?: string };
};

const PUBLIC_KEY_PATTERNS: RegExp[] = [
  /\bRSA\b/i,
  /\bRS256\b/,
  /\bRS384\b/,
  /\bRS512\b/,
  /\bPS256\b/,
  /\bPS384\b/,
  /\bPS512\b/,
  /\bECDSA\b/i,
  /\bECDH\b/i,
  /\bES256\b/,
  /\bES384\b/,
  /\bES512\b/,
  /\bEd25519\b/i,
  /\bCurve25519\b/i,
  /\bX25519\b/i,
  /\bDiffieHellman\b/i,
  /\bdiffie-hellman\b/i,
  /generateKeyPair(?:Sync)?\(/,
  /createSign\(/,
  /createVerify\(/,
  /publicEncrypt\(/,
  /privateDecrypt\(/,
  /subtle\.(?:generateKey|sign|verify|deriveKey|deriveBits)\(/,
  /KeyPairGenerator\.getInstance\(/,
  /Signature\.getInstance\(/,
  /cryptography\.hazmat\.primitives\.asymmetric/i,
  /from\s+cryptography\.hazmat\.primitives\.asymmetric/i,
];

const TOKEN_PATTERNS: RegExp[] = [
  /\bjsonwebtoken\b/i,
  /jwt\.sign\(/,
  /jwt\.verify\(/,
  /\bSignJWT\b/,
  /\bjwtVerify\b/,
  /\bjose\b/i,
  /\bJWT\b/,
  /\bJWS\b/,
];

const PKI_PATTERNS: RegExp[] = [
  /\bBEGIN CERTIFICATE\b/,
  /\.pem\b/i,
  /\.crt\b/i,
  /\.cer\b/i,
  /\bx509\b/i,
  /createSecureContext\(/,
  /tls\.createServer\(/,
  /https\.createServer\(/,
  /SSLContext/i,
  /KeyStore/i,
  /TrustManager/i,
];

const CERTIFICATE_FILE_PATTERNS: RegExp[] = [/\.(pem|crt|cer|p12|pfx)$/i];

const HASHING_PATTERNS: RegExp[] = [
  /\bsha1\b/i,
  /\bsha256\b/i,
  /\bsha384\b/i,
  /\bsha512\b/i,
  /\bmd5\b/i,
  /createHash\(/,
  /MessageDigest\.getInstance\(/,
  /\bhashlib\./,
];

const SYMMETRIC_PATTERNS: RegExp[] = [
  /\bAES\b/i,
  /\baes-128\b/i,
  /\baes-192\b/i,
  /\baes-256\b/i,
  /\bDES\b/i,
  /\b3DES\b/i,
  /\bTripleDES\b/i,
  /\bRC4\b/i,
  /createCipheriv\(/,
  /createDecipheriv\(/,
  /Cipher\.getInstance\(/,
  /subtle\.(?:encrypt|decrypt)\(/,
];

const BLOCKCHAIN_PATTERNS: RegExp[] = [
  /\becrecover\b/i,
  /\bsecp256k1\b/i,
  /\.signMessage\(/,
  /\bverifyMessage\(/,
  /\brecoverAddress\(/,
  /\bethers\.Wallet\b/i,
  /\bnew\s+Wallet\(/,
  /\bweb3\.eth\.accounts\./i,
  /\bgetSigner\(/,
];

const WEAK_HASH_PATTERNS: RegExp[] = [/\bmd5\b/i, /\bsha1\b/i];
const WEAK_SYMMETRIC_PATTERNS: RegExp[] = [
  /\bDES\b/i,
  /\b3DES\b/i,
  /\bTripleDES\b/i,
  /\bRC4\b/i,
];
const AES128_PATTERNS: RegExp[] = [/\baes-128\b/i, /\bAES128\b/i];

const PEM_BLOCK_PATTERNS: RegExp[] = [
  /\bBEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY\b/,
  /\bBEGIN PUBLIC KEY\b/,
  /\bBEGIN CERTIFICATE\b/,
];

const SECRET_FALLBACK_PATTERNS: RegExp[] = [
  /process\.env\.[A-Z0-9_]*(?:PRIVATE_KEY|SECRET_KEY|API_KEY|ACCESS_KEY|TOKEN|PASSWORD)\s*\|\|\s*["'`][^"'`\n]{16,}/,
  /(?:JWT_PRIVATE_KEY|PRIVATE_KEY|SECRET_KEY|API_KEY|ACCESS_KEY|TOKEN|PASSWORD)\s*\|\|\s*["'`][^"'`\n]{16,}/,
];

const HARD_CODED_SECRET_ASSIGNMENT_PATTERNS: RegExp[] = [
  /\b(?:const|let|var)\s+(?:privateKey|secretKey|apiKey|accessKey|clientSecret|jwtPrivateKey|token|password)\s*=\s*["'`][^"'`\n]{16,}/i,
  /\b(?:private_key|secret_key|api_key|access_key|client_secret|jwt_private_key)\b\s*[:=]\s*["'`][^"'`\n]{16,}/i,
];

const SENSITIVE_KEY_FILE_PATTERNS: RegExp[] = [/\.(key|pem|p12|pfx)$/i];

function matchesAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

function findLineInfo(
  content: string,
  patterns: RegExp[]
): { line?: number; snippet?: string } {
  const lines = content.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];

    if (matchesAny(line, patterns)) {
      return {
        line: index + 1,
        snippet: line.trim().slice(0, 220),
      };
    }
  }

  return {};
}

function getFileModule(filePath: string): string {
  const parts = filePath.split("/").filter(Boolean);
  return parts.length === 0 ? "root" : parts[0];
}

function riskPriority(risk: RiskLevel): number {
  if (risk === "high") return 3;
  if (risk === "medium") return 2;
  if (risk === "low") return 1;
  return 0;
}

function confidencePriority(confidence: Confidence): number {
  if (confidence === "high") return 3;
  if (confidence === "medium") return 2;
  return 1;
}

function normalizeConfidence(value: number): Confidence {
  if (value >= 3) return "high";
  if (value >= 2) return "medium";
  return "low";
}

function getSeverityScore(severity: Severity): number {
  if (severity === "high") return 24;
  if (severity === "medium") return 12;
  return 5;
}

function getConfidenceMultiplier(confidence: Confidence): number {
  if (confidence === "high") return 1;
  if (confidence === "medium") return 0.75;
  return 0.5;
}

function isQuantumCategory(category: FindingCategory): boolean {
  return (
    category === "quantum-vulnerable-public-key" ||
    category === "classical-pki" ||
    category === "blockchain-signing"
  );
}

function isWeakCryptoCategory(category: FindingCategory): boolean {
  return (
    category === "weak-hash" ||
    category === "weak-symmetric" ||
    category === "symmetric-margin"
  );
}

function hasPemBlock(content: string): boolean {
  return matchesAny(content, PEM_BLOCK_PATTERNS);
}

function hasSecretFallback(content: string): boolean {
  return matchesAny(content, SECRET_FALLBACK_PATTERNS);
}

function hasHardcodedSecretAssignment(content: string): boolean {
  return matchesAny(content, HARD_CODED_SECRET_ASSIGNMENT_PATTERNS);
}

function hasSensitiveKeyFilePath(filePath: string): boolean {
  return matchesAny(filePath, SENSITIVE_KEY_FILE_PATTERNS);
}

function hasHardcodedKeyMaterial(file: RepoFile): boolean {
  return (
    hasPemBlock(file.content) ||
    hasSecretFallback(file.content) ||
    hasHardcodedSecretAssignment(file.content) ||
    hasSensitiveKeyFilePath(file.path)
  );
}

function findHardcodedKeyLineInfo(file: RepoFile): {
  line?: number;
  snippet?: string;
} {
  if (hasSensitiveKeyFilePath(file.path)) {
    return {
      line: 1,
      snippet: file.path,
    };
  }

  return (
    findLineInfo(file.content, PEM_BLOCK_PATTERNS) ||
    findLineInfo(file.content, SECRET_FALLBACK_PATTERNS) ||
    findLineInfo(file.content, HARD_CODED_SECRET_ASSIGNMENT_PATTERNS)
  );
}

const TOUCHPOINT_RULES: TouchpointRule[] = [
  {
    label: "public-key cryptography",
    matcher: (file) => matchesAny(file.content, PUBLIC_KEY_PATTERNS),
  },
  {
    label: "token signing",
    matcher: (file) => matchesAny(file.content, TOKEN_PATTERNS),
  },
  {
    label: "certificate handling",
    matcher: (file) =>
      matchesAny(file.content, PKI_PATTERNS) ||
      matchesAny(file.path, CERTIFICATE_FILE_PATTERNS),
  },
  {
    label: "hashing",
    matcher: (file) => matchesAny(file.content, HASHING_PATTERNS),
  },
  {
    label: "symmetric encryption",
    matcher: (file) => matchesAny(file.content, SYMMETRIC_PATTERNS),
  },
  {
    label: "key material",
    matcher: (file) => hasHardcodedKeyMaterial(file),
  },
  {
    label: "blockchain / wallet signing",
    matcher: (file) => matchesAny(file.content, BLOCKCHAIN_PATTERNS),
  },
];

const FINDING_RULES: FindingRule[] = [
  {
    id: "quantum-public-key",
    title: "Quantum-vulnerable public-key cryptography detected",
    category: "quantum-vulnerable-public-key",
    severity: "high",
    confidence: "high",
    description:
      "This file appears to use classical public-key cryptography such as RSA, ECC, ECDSA, ECDH, Ed25519, or Diffie-Hellman. These are the main post-quantum migration concern.",
    recommendation:
      "Map where this algorithm is used, who creates and verifies the keys, and plan migration to approved post-quantum or hybrid signature and key-establishment schemes.",
    rationale:
      "Classical public-key algorithms are the primary quantum migration risk because Shor-style attacks directly affect them.",
    matcher: (file) => matchesAny(file.content, PUBLIC_KEY_PATTERNS),
    lineInfo: (file) => findLineInfo(file.content, PUBLIC_KEY_PATTERNS),
  },
  {
    id: "classical-pki",
    title: "Classical certificate or PKI flow detected",
    category: "classical-pki",
    severity: "high",
    confidence: "high",
    description:
      "This file appears to handle certificates, TLS material, or x509 trust logic. Classical certificate and PKI flows are part of quantum migration planning.",
    recommendation:
      "Identify certificate issuers, trust stores, TLS endpoints, and client dependencies, then plan migration to post-quantum or hybrid certificate and handshake strategies.",
    rationale:
      "TLS certificates and PKI chains depend on classical signature systems that will need migration planning.",
    matcher: (file) =>
      matchesAny(file.content, PKI_PATTERNS) ||
      matchesAny(file.path, CERTIFICATE_FILE_PATTERNS),
    lineInfo: (file) =>
      findLineInfo(file.content, PKI_PATTERNS) || {
        line: 1,
        snippet: file.path,
      },
  },
  {
    id: "blockchain-signing",
    title: "Blockchain or wallet signing flow detected",
    category: "blockchain-signing",
    severity: "high",
    confidence: "medium",
    description:
      "This file appears to use blockchain or wallet signature flows such as secp256k1, ecrecover, or wallet signing helpers.",
    recommendation:
      "Map chain-facing signing and verification flows and document where classical wallet signatures are required before planning migration options.",
    rationale:
      "Blockchain and wallet ecosystems commonly depend on classical elliptic-curve signatures, which are a quantum migration concern.",
    matcher: (file) => matchesAny(file.content, BLOCKCHAIN_PATTERNS),
    lineInfo: (file) => findLineInfo(file.content, BLOCKCHAIN_PATTERNS),
  },
  {
    id: "hardcoded-key-material",
    title: "Key material appears in source or config",
    category: "hardcoded-key-material",
    severity: "medium",
    confidence: "high",
    description:
      "This file appears to reference private keys, public keys, certificates, or real secret-like values directly in code or config.",
    recommendation:
      "Move key material to managed secrets storage, remove embedded keys from source, and rotate exposed keys.",
    rationale:
      "Embedded keys increase operational exposure and make crypto inventory and rotation harder.",
    matcher: (file) => hasHardcodedKeyMaterial(file),
    lineInfo: (file) => findHardcodedKeyLineInfo(file),
  },
  {
    id: "weak-hash",
    title: "Weak hash algorithm detected",
    category: "weak-hash",
    severity: "medium",
    confidence: "high",
    description:
      "This file appears to use MD5 or SHA-1. These are weak even before quantum concerns and should not remain in security-sensitive flows.",
    recommendation:
      "Replace MD5 or SHA-1 with stronger modern hashes and review where the hash is used for signatures, integrity, certificates, or password workflows.",
    rationale:
      "MD5 and SHA-1 are already weak by current standards and should be removed from security-sensitive systems.",
    matcher: (file) => matchesAny(file.content, WEAK_HASH_PATTERNS),
    lineInfo: (file) => findLineInfo(file.content, WEAK_HASH_PATTERNS),
  },
  {
    id: "weak-symmetric",
    title: "Weak symmetric cipher detected",
    category: "weak-symmetric",
    severity: "high",
    confidence: "high",
    description:
      "This file appears to use DES, 3DES, or RC4. These are outdated and should be removed from modern systems.",
    recommendation:
      "Replace legacy ciphers with modern authenticated encryption and review protocol settings, SDK defaults, and compatibility code.",
    rationale:
      "Legacy symmetric ciphers are already weak and should not remain in production security flows.",
    matcher: (file) => matchesAny(file.content, WEAK_SYMMETRIC_PATTERNS),
    lineInfo: (file) => findLineInfo(file.content, WEAK_SYMMETRIC_PATTERNS),
  },
  {
    id: "aes128-margin",
    title: "AES-128 usage detected",
    category: "symmetric-margin",
    severity: "low",
    confidence: "medium",
    description:
      "AES-128 is not broken by quantum computers, but some teams prefer a stronger long-term margin for highly sensitive systems.",
    recommendation:
      "Review whether AES-256 is better for data that must stay confidential for many years.",
    rationale:
      "This is a long-term margin issue, not a broken-crypto issue.",
    matcher: (file) => matchesAny(file.content, AES128_PATTERNS),
    lineInfo: (file) => findLineInfo(file.content, AES128_PATTERNS),
  },
];

function getFileTouchpoints(file: RepoFile): string[] {
  const found = new Set<string>();

  for (const rule of TOUCHPOINT_RULES) {
    if (rule.matcher(file)) {
      found.add(rule.label);
    }
  }

  return Array.from(found);
}

function collectTouchpoints(files: RepoFile[]): string[] {
  const found = new Set<string>();

  for (const file of files) {
    for (const touchpoint of getFileTouchpoints(file)) {
      found.add(touchpoint);
    }
  }

  return Array.from(found);
}

function collectFindings(files: RepoFile[]): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    for (const rule of FINDING_RULES) {
      if (!rule.matcher(file)) {
        continue;
      }

      const key = `${rule.id}:${file.path}`;

      if (seen.has(key)) {
        continue;
      }

      seen.add(key);

      const lineInfo = rule.lineInfo(file);

      findings.push({
        id: key,
        title: rule.title,
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        description: rule.description,
        recommendation: rule.recommendation,
        rationale: rule.rationale,
        file: file.path,
        line: lineInfo.line,
        snippet: lineInfo.snippet,
      });

      if (findings.length >= 100) {
        return findings;
      }
    }
  }

  return findings;
}

function collectAffectedFiles(
  files: RepoFile[],
  findings: ScanFinding[]
): string[] {
  const findingFiles = new Set(
    findings.map((finding) => finding.file).filter(Boolean) as string[]
  );

  for (const file of files) {
    if (getFileTouchpoints(file).length > 0) {
      findingFiles.add(file.path);
    }

    if (findingFiles.size >= 30) {
      break;
    }
  }

  return Array.from(findingFiles).slice(0, 30);
}

function buildCounts(findings: ScanFinding[]): ScanCounts {
  return {
    totalFindings: findings.length,
    quantumFindings: findings.filter((finding) =>
      isQuantumCategory(finding.category)
    ).length,
    weakCryptoFindings: findings.filter((finding) =>
      isWeakCryptoCategory(finding.category)
    ).length,
    keyMaterialFindings: findings.filter(
      (finding) => finding.category === "hardcoded-key-material"
    ).length,
    pkiFindings: findings.filter(
      (finding) => finding.category === "classical-pki"
    ).length,
    blockchainFindings: findings.filter(
      (finding) => finding.category === "blockchain-signing"
    ).length,
  };
}

function buildScore(
  findings: ScanFinding[],
  touchpoints: string[],
  affectedFiles: string[]
): number {
  const findingScore = findings.reduce((total, finding) => {
    return (
      total +
      Math.round(
        getSeverityScore(finding.severity) *
          getConfidenceMultiplier(finding.confidence)
      )
    );
  }, 0);

  const touchpointBonus = Math.min(touchpoints.length * 3, 15);
  const affectedFileBonus = Math.min(affectedFiles.length, 10);
  const quantumBonus = findings.some((finding) =>
    isQuantumCategory(finding.category)
  )
    ? 10
    : 0;

  return Math.min(
    findingScore + touchpointBonus + affectedFileBonus + quantumBonus,
    100
  );
}

function getOverallRisk(
  score: number,
  touchpoints: string[],
  findings: ScanFinding[]
): RiskLevel {
  if (findings.some((finding) => finding.severity === "high")) {
    return "high";
  }

  if (score >= 60) return "high";
  if (score >= 25) return "medium";

  if (
    touchpoints.includes("public-key cryptography") ||
    touchpoints.includes("certificate handling") ||
    touchpoints.includes("blockchain / wallet signing")
  ) {
    return "medium";
  }

  if (score > 0 || touchpoints.length > 0) {
    return "low";
  }

  return "none";
}

function getOverallConfidence(
  findings: ScanFinding[],
  touchpoints: string[]
): Confidence {
  if (findings.length === 0) {
    return touchpoints.length > 0 ? "medium" : "low";
  }

  const maxConfidence = findings.reduce((max, finding) => {
    return Math.max(max, confidencePriority(finding.confidence));
  }, 1);

  return normalizeConfidence(maxConfidence);
}

function buildMigrationActions(
  touchpoints: string[],
  findings: ScanFinding[]
): string[] {
  const actions = new Set<string>();

  if (
    touchpoints.includes("public-key cryptography") ||
    findings.some(
      (finding) => finding.category === "quantum-vulnerable-public-key"
    )
  ) {
    actions.add(
      "Inventory every RSA/ECC signing, verification, and key-exchange flow."
    );
    actions.add(
      "Plan migration to post-quantum or hybrid signature and key-establishment schemes where classical public-key crypto is used."
    );
  }

  if (
    touchpoints.includes("certificate handling") ||
    findings.some((finding) => finding.category === "classical-pki")
  ) {
    actions.add(
      "List all certificates, TLS endpoints, trust stores, and external clients that depend on the current PKI flow."
    );
    actions.add(
      "Prepare a certificate and handshake migration plan for post-quantum or hybrid TLS/PKI."
    );
  }

  if (
    touchpoints.includes("blockchain / wallet signing") ||
    findings.some((finding) => finding.category === "blockchain-signing")
  ) {
    actions.add(
      "Map wallet signing, signature recovery, and chain-facing verification flows that depend on classical signatures."
    );
  }

  if (
    findings.some((finding) => finding.category === "hardcoded-key-material")
  ) {
    actions.add(
      "Move hardcoded key material to managed secrets storage and rotate any exposed keys."
    );
  }

  if (findings.some((finding) => finding.category === "weak-hash")) {
    actions.add("Replace MD5 or SHA-1 in security-sensitive code paths.");
  }

  if (findings.some((finding) => finding.category === "weak-symmetric")) {
    actions.add("Replace DES, 3DES, or RC4 with modern supported ciphers.");
  }

  if (findings.some((finding) => finding.category === "symmetric-margin")) {
    actions.add(
      "Review whether AES-256 is preferred for data that must stay confidential for many years."
    );
  }

  if (
    touchpoints.includes("hashing") &&
    !findings.some((f) => f.category === "weak-hash")
  ) {
    actions.add(
      "Review where hashing is used for signatures, integrity, passwords, or certificate workflows."
    );
  }

  if (
    touchpoints.includes("symmetric encryption") &&
    !findings.some((f) => f.category === "weak-symmetric")
  ) {
    actions.add(
      "Review cipher choices, modes, and key sizes; prefer modern authenticated encryption where needed."
    );
  }

  if (actions.size === 0) {
    actions.add(
      "No major crypto migration action was triggered by this scan. Review manually if the repo uses external security services not visible in source files."
    );
  }

  return Array.from(actions);
}

function priorityWeight(priority: MigrationPriority): number {
  if (priority === "now") return 3;
  if (priority === "next") return 2;
  return 1;
}

function buildMigrationPlan(
  findings: ScanFinding[],
  touchpoints: string[]
): MigrationPlanItem[] {
  const plan = new Map<string, MigrationPlanItem>();

  const addPlanItem = (item: MigrationPlanItem) => {
    const existing = plan.get(item.id);

    if (!existing) {
      plan.set(item.id, item);
      return;
    }

    if (priorityWeight(item.priority) > priorityWeight(existing.priority)) {
      plan.set(item.id, item);
    }
  };

  if (
    findings.some(
      (finding) => finding.category === "quantum-vulnerable-public-key"
    ) ||
    touchpoints.includes("public-key cryptography")
  ) {
    addPlanItem({
      id: "migrate-classical-public-key",
      title: "Migrate classical public-key cryptography",
      priority: "now",
      currentState:
        "The repo uses classical public-key signing or key-exchange flows such as RSA, ECC, ECDSA, ECDH, or similar.",
      whyRisky:
        "These are the main quantum migration exposure because future quantum attacks directly affect classical public-key systems.",
      recommendedTarget:
        "Adopt approved post-quantum or hybrid signature and key-establishment designs.",
      scope:
        "Signing services, token issuers, key exchange, verification flows, and externally shared crypto boundaries.",
      notes:
        "Inventory all issuers, verifiers, clients, and dependent systems before changing algorithms.",
    });
  }

  if (
    findings.some((finding) => finding.category === "classical-pki") ||
    touchpoints.includes("certificate handling")
  ) {
    addPlanItem({
      id: "migrate-pki-and-tls",
      title: "Prepare PKI and TLS migration plan",
      priority: "now",
      currentState:
        "The repo handles certificates, trust stores, TLS materials, or x509 flows.",
      whyRisky:
        "Certificate chains and TLS identities usually rely on classical signatures that need quantum-era migration planning.",
      recommendedTarget:
        "Prepare hybrid or post-quantum certificate and handshake strategy for PKI-facing systems.",
      scope:
        "TLS endpoints, trust stores, certificates, certificate provisioning, and client/server auth boundaries.",
      notes:
        "Track partner dependencies and certificate issuance process before rollout.",
    });
  }

  if (
    findings.some((finding) => finding.category === "blockchain-signing") ||
    touchpoints.includes("blockchain / wallet signing")
  ) {
    addPlanItem({
      id: "review-blockchain-signature-dependencies",
      title: "Review blockchain and wallet signature dependencies",
      priority: "next",
      currentState:
        "The repo appears to depend on wallet signing, chain verification, or secp256k1-style flows.",
      whyRisky:
        "Blockchain ecosystems commonly depend on classical elliptic-curve signatures that are part of the long-term quantum risk story.",
      recommendedTarget:
        "Document chain-facing signature dependencies and design a phased compatibility plan.",
      scope:
        "Wallet signing, transaction signing, signature recovery, smart-contract verification, and cross-system chain integrations.",
      notes:
        "This often requires ecosystem coordination, not just local code changes.",
    });
  }

  if (
    findings.some((finding) => finding.category === "hardcoded-key-material")
  ) {
    addPlanItem({
      id: "remove-embedded-key-material",
      title: "Remove embedded key material from code and config",
      priority: "next",
      currentState:
        "The repo contains hardcoded keys, secrets, or embedded key-like values.",
      whyRisky:
        "Hardcoded material increases operational exposure and makes rotation and migration much harder.",
      recommendedTarget:
        "Move secrets to managed storage and rotate exposed materials.",
      scope:
        "Environment fallbacks, config files, local key blobs, and secret-like source constants.",
      notes:
        "Do this before or alongside algorithm migration so inventory stays clean.",
    });
  }

  if (findings.some((finding) => finding.category === "weak-hash")) {
    addPlanItem({
      id: "replace-weak-hashes",
      title: "Replace weak hash algorithms",
      priority: "now",
      currentState:
        "The repo appears to use MD5 or SHA-1 in security-relevant code.",
      whyRisky:
        "These hashes are already weak by current standards even without quantum pressure.",
      recommendedTarget:
        "Move to stronger modern hashes appropriate for the actual use case.",
      scope:
        "Integrity checks, signatures, certificates, password flows, and legacy compatibility helpers.",
      notes:
        "This is a modern security hygiene issue and should be cleaned up fast.",
    });
  }

  if (findings.some((finding) => finding.category === "weak-symmetric")) {
    addPlanItem({
      id: "replace-legacy-ciphers",
      title: "Replace legacy symmetric ciphers",
      priority: "now",
      currentState:
        "The repo appears to use DES, 3DES, RC4, or similar legacy symmetric encryption.",
      whyRisky:
        "These ciphers are already outdated and should not remain in modern production systems.",
      recommendedTarget:
        "Use modern authenticated encryption and supported cipher suites.",
      scope:
        "Encryption helpers, protocol configuration, library defaults, and backward-compatibility code.",
      notes:
        "This is separate from quantum migration and should be treated as immediate cleanup.",
    });
  }

  if (
    findings.some((finding) => finding.category === "symmetric-margin") ||
    touchpoints.includes("symmetric encryption")
  ) {
    addPlanItem({
      id: "review-long-term-symmetric-margin",
      title: "Review long-term symmetric security margin",
      priority: "later",
      currentState:
        "The repo uses symmetric encryption and may include AES-128 or similar lower-margin choices.",
      whyRisky:
        "This is not broken crypto, but highly sensitive long-lifetime data may need a stronger long-term margin.",
      recommendedTarget:
        "Review whether AES-256 or stronger long-term settings are appropriate.",
      scope:
        "Long-retention confidential data, archived data, and sensitive regulated datasets.",
      notes:
        "Treat this as strategic hardening, not emergency remediation.",
    });
  }

  return Array.from(plan.values()).sort(
    (a, b) => priorityWeight(b.priority) - priorityWeight(a.priority)
  );
}

function buildModuleSummaries(
  files: RepoFile[],
  findings: ScanFinding[]
): ModuleRiskSummary[] {
  const findingsByFile = new Map<string, ScanFinding[]>();

  for (const finding of findings) {
    if (!finding.file) continue;

    const current = findingsByFile.get(finding.file) ?? [];
    current.push(finding);
    findingsByFile.set(finding.file, current);
  }

  const moduleMap = new Map<
    string,
    {
      files: Set<string>;
      touchpoints: Set<string>;
      findings: ScanFinding[];
    }
  >();

  for (const file of files) {
    const fileTouchpoints = getFileTouchpoints(file);
    const fileFindings = findingsByFile.get(file.path) ?? [];

    if (fileTouchpoints.length === 0 && fileFindings.length === 0) {
      continue;
    }

    const moduleName = getFileModule(file.path);
    const current = moduleMap.get(moduleName) ?? {
      files: new Set<string>(),
      touchpoints: new Set<string>(),
      findings: [],
    };

    current.files.add(file.path);

    for (const touchpoint of fileTouchpoints) {
      current.touchpoints.add(touchpoint);
    }

    current.findings.push(...fileFindings);
    moduleMap.set(moduleName, current);
  }

  return Array.from(moduleMap.entries())
    .map(([module, data]) => {
      const touchpoints = Array.from(data.touchpoints);
      const affectedFiles = Array.from(data.files);
      const score = buildScore(data.findings, touchpoints, affectedFiles);
      const overallRisk = getOverallRisk(score, touchpoints, data.findings);
      const confidence = getOverallConfidence(data.findings, touchpoints);

      return {
        module,
        overallRisk,
        score,
        confidence,
        affectedFiles: affectedFiles.length,
        findings: data.findings.length,
        quantumFindings: data.findings.filter((finding) =>
          isQuantumCategory(finding.category)
        ).length,
        weakCryptoFindings: data.findings.filter((finding) =>
          isWeakCryptoCategory(finding.category)
        ).length,
        touchpoints,
        sampleFiles: affectedFiles.slice(0, 5),
      };
    })
    .sort((a, b) => {
      const riskDiff = riskPriority(b.overallRisk) - riskPriority(a.overallRisk);
      if (riskDiff !== 0) return riskDiff;
      if (b.score !== a.score) return b.score - a.score;
      if (b.findings !== a.findings) return b.findings - a.findings;
      return a.module.localeCompare(b.module);
    })
    .slice(0, 20);
}

function buildSummary(
  filesScanned: number,
  branchScanned: string,
  score: number,
  confidence: Confidence,
  overallRisk: RiskLevel,
  counts: ScanCounts,
  affectedFiles: string[],
  moduleSummaries: ModuleRiskSummary[]
): string {
  if (counts.totalFindings === 0 && affectedFiles.length === 0) {
    return `Scanned ${filesScanned} files from branch ${branchScanned} and did not detect clear crypto findings in the scanned source set.`;
  }

  return `Scanned ${filesScanned} files from branch ${branchScanned}, found ${counts.totalFindings} findings across ${affectedFiles.length} affected files in ${moduleSummaries.length} modules. Risk is ${overallRisk} with score ${score}/100 and ${confidence} confidence.`;
}

export async function scanRepo(
  repoUrl: string,
  githubToken?: string,
  branch?: string
): Promise<ScanResponse> {
  const cleanRepoUrl = normalizeGithubRepoUrl(repoUrl);
  const { files, branchScanned } = await fetchRepoFiles(
    cleanRepoUrl,
    githubToken,
    branch
  );

  const touchpoints = collectTouchpoints(files);
  const findings = collectFindings(files);
  const affectedFiles = collectAffectedFiles(files, findings);
  const counts = buildCounts(findings);
  const score = buildScore(findings, touchpoints, affectedFiles);
  const overallRisk = getOverallRisk(score, touchpoints, findings);
  const confidence = getOverallConfidence(findings, touchpoints);
  const migrationActions = buildMigrationActions(touchpoints, findings);
  const migrationPlan = buildMigrationPlan(findings, touchpoints);
  const moduleSummaries = buildModuleSummaries(files, findings);
  const summary = buildSummary(
    files.length,
    branchScanned,
    score,
    confidence,
    overallRisk,
    counts,
    affectedFiles,
    moduleSummaries
  );

  return {
    ok: true,
    repoUrl: cleanRepoUrl,
    branchScanned,
    message: `Fetched ${files.length} files from branch ${branchScanned}. Found ${counts.totalFindings} findings.`,
    summary,
    overallRisk,
    score,
    confidence,
    filesScanned: files.length,
    sampleFiles: files.slice(0, 10).map((file) => file.path),
    affectedFiles,
    touchpoints,
    migrationActions,
    migrationPlan,
    findings,
    moduleSummaries,
    counts,
  };
}