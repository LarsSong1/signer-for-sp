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
 *     query:  cursor, user_agent, client_enter, country, platform, client
 *     headers in: x-oauth-token / x-cookie-header (optional, session auth)
 *     headers out: x-set-tt-cookie (REQUIRED), x-room-id (optional)
 *     body out: raw bytes of TikTok's own protobuf `WebcastResponse` — NOT JSON.
 *
 * Confirmed live (not assumed) that `tiktok-live-connector` never sends `unique_id`
 * on this specific call — only `roomId` (already resolved by an earlier, unsigned
 * step the library does directly against TikTok, before this route is ever hit). The
 * real endpoint (`webcast.tiktok.com/webcast/im/fetch/`) only needs `room_id` anyway
 * — TikTok's own protocol was never username-scoped here, only OUR two earlier,
 * wrong attempts assumed it had to be:
 *   1. First tried an injected `fetch()` from page-side JS — hit CORS every time
 *      (`TypeError: Failed to fetch`, 100% reproducible).
 *   2. Then tried navigating to the user's real `/live` page and intercepting
 *      whatever TikTok's own JS fetched there — but that needs `unique_id`, which
 *      this call never carries.
 * Both were solving a problem that doesn't exist once the ACTUAL fetch happens in
 * plain Node.js instead of inside a browser page — CORS is a browser-only
 * restriction; a server-to-server request was never subject to it (confirmed with a
 * one-line live check: `node -e "fetch('https://www.tiktok.com')..."` reached
 * TikTok fine). `fetchWebcastRawBytes` (`server.mjs`) signs the URL through the
 * browser/SDK as always, then fetches the signed URL with Node's own `fetch`.
 */

const TIKTOK_WEBCAST_FETCH_URL = "https://webcast.tiktok.com/webcast/im/fetch/";

/** TikTok's own param names for the webcast fetch endpoint, built from the sign
 *  server's simplified query params. `room_id` is the only one TikTok's protocol
 *  actually requires — `target_uid` is set when we happen to have it, but nothing
 *  here depends on it. */
function buildTikTokWebcastUrl({ roomId, uniqueId, cursor, userAgent, clientEnter }) {
  const params = new URLSearchParams({
    aid: "1988",
    app_language: "en",
    app_name: "tiktok_web",
    browser_language: "en-US",
    browser_name: "Mozilla",
    browser_online: "true",
    browser_platform: "MacIntel",
    browser_version: "5.0",
    channel: "tiktok_web",
    cookie_enabled: "true",
    device_platform: "web_pc",
    focus_state: "true",
    from_page: "user",
    history_len: "2",
    is_fullscreen: "false",
    is_page_visible: "true",
    did_rule: "3",
    fetch_rule: "1",
    identity: "audience",
    last_rtt: "0",
    live_id: "12",
    os: "mac",
    priority_region: "",
    resp_content_type: "protobuf",
    screen_height: "1080",
    screen_width: "1920",
    tz_name: "America/New_York",
    root_referer: "https://www.tiktok.com/",
    referer: "https://www.tiktok.com/",
    room_id: roomId,
    cursor: cursor || "",
    internal_ext: "",
    client_enter: clientEnter ? "1" : "0",
  });
  if (uniqueId) params.set("target_uid", uniqueId);
  if (userAgent) params.set("user_agent", userAgent);
  return `${TIKTOK_WEBCAST_FETCH_URL}?${params.toString()}`;
}

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
 *   `/webcast/sign_url`, which only signs (no follow-up fetch, so nothing else can
 *   race it).
 * @param {(targetUrl: string, userAgent?: string) => Promise<{status: number, bytes: Buffer}>} deps.fetchWebcastRawBytes
 *   Signs `targetUrl` and fetches it with Node's own `fetch` — see this file's own
 *   header comment for why that replaced the two earlier, browser-side attempts.
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

    const userAgent = query.get("user_agent");
    const targetUrl = buildTikTokWebcastUrl({
      roomId,
      uniqueId: query.get("unique_id"),
      cursor: query.get("cursor"),
      userAgent,
      clientEnter: query.get("client_enter") === "true" || query.get("client_enter") === "1",
    });

    let raw;
    try {
      raw = await fetchWebcastRawBytes(targetUrl, userAgent || null);
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: `webcast fetch failed: ${e.message}` }));
      return;
    }

    // DIAGNOSTIC — keep until this route has been confirmed working against several
    // real live rooms. If `preview` reads as HTML/JSON text instead of binary
    // garbage, TikTok returned an error PAGE (captcha, bot check, account not live,
    // malformed params) with a 200 status instead of real protobuf.
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
