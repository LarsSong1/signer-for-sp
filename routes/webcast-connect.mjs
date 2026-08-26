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
 * By default `tiktok-live-connector` never sends `unique_id` on this call — only
 * `roomId`. Confirmed live against the real Euler Stream API (a known-working sign
 * server, tested directly with a real API key): sending BOTH `room_id` and a
 * user-identifying param (`unique_id`) together is explicitly rejected — `422 "You
 * cannot provide both room_id and unique_id"`. `room_id` ALONE, tested against a real
 * live room through THIS repo's own signing engine, returns genuine TikTok protobuf
 * (200, real bytes, readable "Welcome to TikTok LIVE!" system message) — see
 * `fetchRawBytesThroughPage`'s comment in `server.mjs`. This is why
 * `buildTikTokWebcastUrl` below only ever sets `room_id`, never `target_uid`.
 *
 * The actual data fetch is a plain in-page `fetch()` (`page.evaluate`), signed the
 * same way `/signature` already signs anything. A long detour was taken this session
 * (Node's own `fetch` → CDP's `Network.loadNetworkResource`) on the theory that
 * page-JS `fetch()` hits CORS here — confirmed live that it doesn't; that detour was
 * solving a problem that turned out not to be the real one.
 */

const TIKTOK_WEBCAST_FETCH_URL = "https://webcast.tiktok.com/webcast/im/fetch/";

/** TikTok's own param names for the webcast fetch endpoint, built from the sign
 *  server's simplified query params. `room_id` is the only one TikTok's protocol
 *  actually requires — `target_uid` is set when we happen to have it, but nothing
 *  here depends on it. */
function buildTikTokWebcastUrl({ roomId, cursor, userAgent, clientEnter }) {
  // This exact param set (unmodified from the original working version) was verified
  // live against a real room through this repo's own signing engine — genuine
  // protobuf back, not the empty-JSON `{"data":[],"status_code":0}` that came back
  // when `resp_content_type` was dropped from here during an earlier "cleanup" this
  // session that turned out to be based on a wrong assumption (that it only belonged
  // to the WebSocket's own param set). Don't remove fields from this list without
  // re-testing against a real live room — several were tried and each one mattered.
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
  // NOT `target_uid`/`unique_id` here — confirmed live against the real Euler Stream
  // API (a known-working sign server) that sending BOTH `room_id` and a
  // user-identifying param together is explicitly rejected ("You cannot provide both
  // room_id and unique_id", HTTP 422). `room_id` alone is what the successful live
  // test above used too.
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
 *   Signs `targetUrl` through the browser/SDK, then fetches the signed URL through
 *   that same page (`page.evaluate(fetch(...))`) — see `fetchRawBytesThroughPage` in
 *   `server.mjs`.
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
      cursor: query.get("cursor"),
      userAgent,
      clientEnter: query.get("client_enter") === "true" || query.get("client_enter") === "1",
    });

    // Túnel propio del streamer (opt-in, ver `chat.rs`/`tunnelBroker.ts`) — llega como
    // header desde el gateway, threadeado por el patch de `tiktok-live-connector`. Hoy
    // sólo viaja hasta acá y se loguea (ver el comentario de `fetchWebcastRawBytes`).
    const tunnelId = req.headers["x-streampack-tunnel-id"] || null;

    let raw;
    try {
      raw = await fetchWebcastRawBytes(targetUrl, userAgent || null, tunnelId);
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
