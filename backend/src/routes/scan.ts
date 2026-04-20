import { Router } from "express";
import { scanRepository } from "../controllers/scanController";

const router = Router();

router.get("/health", (_req, res) => {
  res.status(200).json({
    ok: true,
    message: "Scan route is working",
  });
});

router.post("/", scanRepository);

export default router;