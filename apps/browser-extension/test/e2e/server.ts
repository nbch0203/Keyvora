// Local fixture server (dual-stack, so both http://127.0.0.1:<port> and http://localhost:<port> reach it; they are
// different origins, which gives us a cross-origin iframe without any external network).
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

export interface FixtureServer {
  base: string;
  cross: string;
  close(): Promise<void>;
}

export async function startFixtureServer(): Promise<FixtureServer> {
  let port = 0;
  const server: Server = createServer(async (req, res) => {
    const name = path.basename(new URL(req.url ?? "/", "http://x").pathname) || "login.html";
    if (!/^[a-z-]+\.html$/.test(name)) {
      res.writeHead(404).end();
      return;
    }
    try {
      const html = (await readFile(path.join(FIXTURES, name), "utf8")).replaceAll("{{CROSS_ORIGIN}}", `http://localhost:${port}`);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }).end(html);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "::", resolve));
  const addr = server.address();
  port = typeof addr === "object" && addr ? addr.port : 0;
  return {
    base: `http://127.0.0.1:${port}`,
    cross: `http://localhost:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
