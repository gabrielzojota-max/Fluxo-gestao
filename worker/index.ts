export interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/api/health") {
      try {
        const row = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf_%'"
        ).first<{ total: number }>();

        return Response.json({
          service: "FLUXO GESTÃO API",
          status: "ok",
          database: "connected",
          applicationTables: row?.total ?? 0
        }, { headers: { "Cache-Control": "no-store" } });
      } catch {
        return Response.json({
          service: "FLUXO GESTÃO API",
          status: "error",
          database: "unavailable"
        }, { status: 503 });
      }
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  }
};