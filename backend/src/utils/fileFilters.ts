const BLOCKED_FOLDERS = [
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
];

const ALLOWED_EXTENSIONS = [
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".java",
  ".go",
  ".rs",
  ".sol",
  ".cs",
  ".php",
  ".rb",
  ".kt",
  ".swift",
  ".cpp",
  ".c",
  ".h",
  ".json",
  ".yaml",
  ".yml",
  ".pem",
  ".crt",
  ".key",
  ".conf",
  ".ini",
];

export function isIgnoredPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();

  return BLOCKED_FOLDERS.some(
    (folder) =>
      normalized.includes(`/${folder}/`) || normalized.startsWith(`${folder}/`)
  );
}

export function isScannableFile(filePath: string): boolean {
  const normalized = filePath.toLowerCase();

  if (isIgnoredPath(normalized)) {
    return false;
  }

  return ALLOWED_EXTENSIONS.some((ext) => normalized.endsWith(ext));
}