import type { Request, Response } from "express";
import { validateGithubRepoUrl } from "../services/githubService";
import { scanRepo } from "../services/scanService";
import type { ScanRequestBody } from "../types/scan";

export async function scanRepository(
  req: Request<{}, {}, ScanRequestBody>,
  res: Response
): Promise<void> {
  try {
    const { repoUrl, githubToken, branch } = req.body;

    if (!repoUrl || typeof repoUrl !== "string") {
      res.status(400).json({
        ok: false,
        message: "repoUrl is required",
      });
      return;
    }

    if (!validateGithubRepoUrl(repoUrl)) {
      res.status(400).json({
        ok: false,
        message: "Please enter a valid GitHub repository link",
      });
      return;
    }

    if (githubToken && typeof githubToken !== "string") {
      res.status(400).json({
        ok: false,
        message: "githubToken must be a string",
      });
      return;
    }

    if (branch && typeof branch !== "string") {
      res.status(400).json({
        ok: false,
        message: "branch must be a string",
      });
      return;
    }

    const result = await scanRepo(repoUrl, githubToken, branch);
    res.status(200).json(result);
  } catch (error) {
    console.error("Scan controller error:", error);

    const message =
      error instanceof Error
        ? error.message
        : "Something went wrong while scanning";

    res.status(500).json({
      ok: false,
      message,
    });
  }
}