/**
 * Custom sign-server routes, added on top of upstream carcabot/tiktok-signature.
 *
 * These implement the contract TikTok-Live-Connector-family libraries expect from a
 * "custom sign server" (see Euler Stream's own public docs at
 * eulerstream.com/docs/sign-server/custom-sign-servers, and — read directly, not
 * assumed — the actual request the `tiktok-live-api-sdk` package builds for
 * `TikTokLIVERoomsApi.fetchWebcastURL`):
 *
 *   GET /webcast/rooms/:roomId/connect
 *     query:  unique_id, cursor, user_agent, client_enter, country, platform, client
 *     headers in: x-oauth-token / x-cookie-header (optional, session auth)
 *     headers out: x-set-tt-cookie (REQUIRED), x-room-id (optional)
 *     body out: raw bytes of TikTok's own protobuf `WebcastResponse` — NOT JSON.
 *
 * ⚠️ The first version of this route built TikTok's `webcast/im/fetch` URL by hand,
 * signed it the same way `/signature` does, and fetched it with an injected
 * `fetch()` call from page-side JS. Verified LIVE (not assumed) that this never
 * worked: TikTok's CORS policy on that endpoint rejects a cross-origin fetch issued
 * by injected code — confirmed by isolating the failure with a diagnostic pass
 * (`fetch() rejected: TypeError: Failed to fetch`, 100% of attempts, not
 * intermittent — ruling out flakiness or a signing bug). `handleConnect` now instead
 * navigates to the target user's real LIVE page and captures the raw bytes of
 * whatever matching request TikTok's OWN first-party JS makes there (see
 * `fetchWebcastRawBytes` in `server.mjs`) — response bytes read via Puppeteer's CDP
 * layer aren't subject to the page's own fetch()-level CORS enforcement, so this
 * sidesteps the wall instead of fighting it. Still not diffed against Euler Stream's
 * own reference implementation, so treat as freshly-live-tested, not battle-hardened.
 */

/**
 * Registers the two new routes on the existing HTTP router. Called once from
 * `server.mjs`, passed the same `page`/signing internals it already has — nothing here
 * duplicates or forks the signing engine itself.
 *
 * @param {object} deps
 * @param {() => Promise<void>} deps.initBrowser
 * @param {() => Promise<void>} deps.ensurePageReady
 * @param {(targetUrl: string, userAgent?: string) => Promise<any>} deps.generateSignedUrl
 *   Existing `/signature` engine, already self-queued — reused as-is for
 *   `/webcast/sign_url`, which only signs (no follow-up page fetch, so nothing else
 *   can race it).
 * @param {(uniqueId: string) => Promise<{status: number, bytes: Buffer}>} deps.fetchWebcastRawBytes
 *   Navigates to `@uniqueId`'s real LIVE page and returns the raw bytes TikTok's own
 *   page naturally received from `webcast/im/fetch` — see this file's own header
 *   comment for why this replaced the sign+fetch approach.
 * @param {() => Array<{name: string, value: string}>} deps.getCookies
 */
export function createWebcastRoutes({
  initBrowser,
  ensurePageReady,
  generateSignedUrl,
  fetchWebcastRawBytes,
  getCookies,
}) {
  /** GET /webcast/rooms/:roomId/connect */
  async function handleConnect(req, res, roomId, query) {
    await initBrowser();
    await ensurePageReady();

    const uniqueId = query.get("unique_id");
    if (!uniqueId) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "unique_id query param is required" }));
      return;
    }

    let raw;
    try {
      raw = await fetchWebcastRawBytes(uniqueId);
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: `webcast fetch failed: ${e.message}` }));
      return;
    }

    // DIAGNOSTIC — keep until this route has been confirmed working against several
    // real live rooms. If `preview` reads as HTML/JSON text instead of binary
    // garbage, TikTok returned an error PAGE (captcha, bot check, account not live)
    // with a 200 status instead of real protobuf.
    const preview = raw.bytes.subarray(0, 200).toString("utf8").replace(/[^\x20-\x7e]/g, ".");
    console.log(
      `[webcast] status=${raw.status} bytes=${raw.bytes.length} preview="${preview}"`,
    );

    if (raw.status !== 200) {
      res.writeHead(raw.status, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: `TikTok returned HTTP ${raw.status}` }));
      return;
    }

    const cookies = getCookies() || [];
    const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");

    res.writeHead(200, {
      "content-type": "application/protobuf",
      // REQUIRED by the connector library — see fetch-signed-websocket-euler.ts's
      // check on this exact header before it'll accept the response at all.
      "x-set-tt-cookie": cookieHeader,
      "x-room-id": roomId,
    });
    res.end(raw.bytes);
  }

  /** POST /webcast/sign_url — thin alias of the existing /signature route. */
  async function handleSignUrl(req, res, body) {
    let targetUrl = null;
    let userAgent = null;
    try {
      const json = JSON.parse(body);
      targetUrl = json.url;
      userAgent = json.userAgent || null;
    } catch {
      /* falls through to the 400 below */
    }
    if (!targetUrl) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: 'body must be JSON with a "url" field' }));
      return;
    }
    const result = await generateSignedUrl(targetUrl, userAgent);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ signedUrl: result.signedUrl }));
  }

  /** GET /healthz — dumb and fast, for Render's own health checker. The existing
   *  `/health` (rich diagnostics: ready/session age/queue length) stays as-is. */
  function handleHealthz(req, res) {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  }

  /**
   * Tries to handle the request if it matches one of these routes. Returns `true` if
   * it did (caller should stop routing), `false` otherwise.
   */
  return async function tryHandleWebcastRoute(req, res, url) {
    if (url.pathname === "/healthz") {
      handleHealthz(req, res);
      return true;
    }

    const connectMatch = url.pathname.match(/^\/webcast\/rooms\/([^/]+)\/connect$/);
    if (connectMatch && req.method === "GET") {
      await handleConnect(req, res, decodeURIComponent(connectMatch[1]), url.searchParams);
      return true;
    }

    if (url.pathname === "/webcast/sign_url" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;
      await handleSignUrl(req, res, body);
      return true;
    }

    return false;
  };
}
