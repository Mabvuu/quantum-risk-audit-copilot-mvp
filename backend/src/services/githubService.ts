import axios from "axios";
import AdmZip from "adm-zip";
import type { RepoFile } from "../types/scan";
import { isScannableFile } from "../utils/fileFilters";

type GithubRepoParts = {
  owner: string;
  repo: string;
};

export type FetchRepoFilesResult = {
  files: RepoFile[];
  branchScanned: string;
};

function getGithubRepoParts(url: string): GithubRepoParts | null {
  try {
    const parsed = new URL(url.trim());
    const isGithubHost =
      parsed.hostname === "github.com" || parsed.hostname === "www.github.com";

    if (!isGithubHost) {
      return null;
    }

    const parts = parsed.pathname.split("/").filter(Boolean);

    if (parts.length < 2) {
      return null;
    }

    return {
      owner: parts[0],
      repo: parts[1].replace(/\.git$/, ""),
    };
  } catch {
    return null;
  }
}

function buildGithubHeaders(githubToken?: string) {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "quantum-risk-audit-mvp",
  };

  if (githubToken && githubToken.trim()) {
    headers.Authorization = `Bearer ${githubToken.trim()}`;
  }

  return headers;
}

function looksBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8000));

  if (sample.length === 0) {
    return false;
  }

  let suspiciousBytes = 0;

  for (const byte of sample) {
    if (byte === 0) {
      return true;
    }

    const isTab = byte === 9;
    const isLineFeed = byte === 10;
    const isCarriageReturn = byte === 13;
    const isPrintableAscii = byte >= 32 && byte <= 126;

    if (!isTab && !isLineFeed && !isCarriageReturn && !isPrintableAscii) {
      suspiciousBytes += 1;
    }
  }

  return suspiciousBytes / sample.length > 0.3;
}

export function validateGithubRepoUrl(url: string): boolean {
  return getGithubRepoParts(url) !== null;
}

export function normalizeGithubRepoUrl(url: string): string {
  const trimmed = url.trim().replace(/\.git$/, "");

  try {
    const parsed = new URL(trimmed);
    const cleanPath = parsed.pathname.replace(/\/+$/, "");
    return `${parsed.protocol}//${parsed.hostname}${cleanPath}`;
  } catch {
    return trimmed;
  }
}

export async function fetchRepoFiles(
  repoUrl: string,
  githubToken?: string,
  branch?: string
): Promise<FetchRepoFilesResult> {
  const repoParts = getGithubRepoParts(repoUrl);

  if (!repoParts) {
    throw new Error("Invalid GitHub repository link");
  }

  const { owner, repo } = repoParts;
  const headers = buildGithubHeaders(githubToken);

  try {
    const repoMetaResponse = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}`,
      { headers }
    );

    const defaultBranch =
      (repoMetaResponse.data.default_branch as string | undefined)?.trim() ||
      "main";

    const requestedBranch = branch?.trim();
    const branchToUse = requestedBranch || defaultBranch;

    const zipResponse = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/zipball/${encodeURIComponent(
        branchToUse
      )}`,
      {
        responseType: "arraybuffer",
        headers,
      }
    );

    const zip = new AdmZip(Buffer.from(zipResponse.data));
    const files: RepoFile[] = [];

    for (const entry of zip.getEntries()) {
      if (entry.isDirectory) {
        continue;
      }

      const cleanPath = entry.entryName.split("/").slice(1).join("/");

      if (!cleanPath) {
        continue;
      }

      if (!isScannableFile(cleanPath)) {
        continue;
      }

      const buffer = entry.getData();

      if (buffer.length === 0) {
        continue;
      }

      if (buffer.length > 250_000) {
        continue;
      }

      if (looksBinary(buffer)) {
        continue;
      }

      const content = buffer.toString("utf8");

      files.push({
        path: cleanPath,
        content,
      });

      if (files.length >= 500) {
        break;
      }
    }

    return {
      files,
      branchScanned: branchToUse,
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      const requestedBranch = branch?.trim();

      if (status === 401) {
        throw new Error("GitHub token is invalid or expired");
      }

      if (status === 404) {
        if (requestedBranch) {
          if (githubToken?.trim()) {
            throw new Error(
              `Branch "${requestedBranch}" was not found, or this token does not have access`
            );
          }

          throw new Error(
            `Branch "${requestedBranch}" was not found, or the repo is private`
          );
        }

        if (githubToken?.trim()) {
          throw new Error("Repo not found, or this token does not have access");
        }

        throw new Error(
          "GitHub repository not found or private. Add a GitHub token if this is a private repo"
        );
      }

      if (status === 403) {
        if (githubToken?.trim()) {
          throw new Error(
            "GitHub denied access or rate limit was hit for this token"
          );
        }

        throw new Error(
          "GitHub rate limit reached. Add a token or try again later"
        );
      }
    }

    throw new Error("Failed to fetch repository files from GitHub");
  }
}