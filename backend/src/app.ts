import express from "express";
import cors from "cors";
import scanRoutes from "./routes/scan";

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.get("/api/health", (_req, res) => {
  res.status(200).json({
    ok: true,
    message: "Backend is alive",
  });
});

app.use("/api/scan", scanRoutes);

export default app;