import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { registerStorageProxy } from "./storageProxy";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { getDb } from "../db";
import { validateRuntimeEnvironment } from "./env";

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

async function startServer() {
  validateRuntimeEnvironment();
  const app = express();
  const server = createServer(app);
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use((req, res, next) => {
    const started = Date.now();
    const requestId = typeof req.header("x-request-id") === "string" && req.header("x-request-id")!.length <= 48 ? req.header("x-request-id")! : crypto.randomUUID().slice(0, 36);
    res.setHeader("x-request-id", requestId);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline' https:; connect-src 'self' https:; upgrade-insecure-requests");
    if (process.env.NODE_ENV === "production") res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.on("finish", () => { console.info(JSON.stringify({ event: "http.request", requestId, method: req.method, path: req.path, status: res.statusCode, durationMs: Date.now() - started })); });
    next();
  });
  app.get("/healthz", (_req, res) => res.status(200).json({ status: "ok" }));
  app.get("/readyz", async (_req, res) => {
    const database = await getDb();
    res.status(database ? 200 : 503).json({ status: database ? "ready" : "degraded", database: Boolean(database) });
  });
  app.use(express.json({ limit: "256kb" }));
  app.use(express.urlencoded({ limit: "32kb", extended: false }));
  registerStorageProxy(app);
  registerOAuthRoutes(app);
  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );
  // development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  app.use((error: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(JSON.stringify({ event: "http.error", requestId: res.getHeader("x-request-id"), path: req.path, message: error instanceof Error ? error.message : "unknown" }));
    if (!res.headersSent) res.status(500).json({ error: "internal_error", requestId: res.getHeader("x-request-id") });
  });

  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);

  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}

startServer().catch(console.error);
