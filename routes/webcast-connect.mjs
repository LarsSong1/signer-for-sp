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
 * carcabot's existing engine (browser + local TikTok SDK) does the signing; this file
 * only adds the glue that (a) builds TikTok's REAL webcast fetch URL from the params
 * above, (b) signs it the same way `/signature` already does, (c) actually performs
 * the request and hands back the raw bytes instead of JSON-parsing them.
 *
 * ⚠️ NOT YET VERIFIED AGAINST A LIVE ROOM. TikTok's exact query-parameter set for its
 * real `webcast/im/fetch` endpoint is reconstructed here from the publicly documented
 * browser-fingerprint parameters carcabot's own README already uses for other TikTok
 * endpoints (the same `aid`/`app_language`/`device_platform`/… family) — it has NOT
 * been diffed against a byte-for-byte browser capture of the live endpoint yet. Before
 * connecting a real client, capture one real request in a browser's DevTools Network
 * tab while watching a real TikTok LIVE, and reconcile `buildTikTokWebcastUrl` below
 * against it. See "Verificación", paso 1, in the project's plan.
 */

const TIKTOK_WEBCAST_FETCH_URL = "https://webcast.tiktok.com/webcast/im/fetch/";

/** TikTok's own param names for the webcast fetch endpoint, built from the sign
 *  server's simplified query params. Needs the live-capture check noted above. */
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
 * Fetches the RAW bytes of a signed URL through the browser page — the protobuf-safe
 * sibling of the existing `/fetch` route, which JSON-parses the response and would
 * corrupt binary data. Bytes cross the `page.evaluate` boundary as base64, since
 * Puppeteer serializes return values as JSON.
 */
async function fetchRawBytesThroughPage(page, signedUrl) {
  const result = await page.evaluate(async (url) => {
    try {
      const response = await fetch(url, {
        credentials: "include",
        headers: { Accept: "application/protobuf,application/json" },
      });
      const buf = await response.arrayBuffer();
      let binary = "";
      const bytes = new Uint8Array(buf);
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return {
        status: response.status,
        bodyBase64: btoa(binary),
      };
    } catch (e) {
      return { error: e.message };
    }
  }, signedUrl);

  if (result.error) throw new Error(result.error);
  return { status: result.status, bytes: Buffer.from(result.bodyBase64, "base64") };
}

/**
 * Registers the two new routes on the existing HTTP router. Called once from
 * `server.mjs`, passed the same `page`/signing internals it already has — nothing here
 * duplicates or forks the signing engine itself.
 *
 * @param {object} deps
 * @param {() => Promise<void>} deps.initBrowser
 * @param {() => Promise<void>} deps.ensurePageReady
 * @param {() => import('puppeteer').Page} deps.getPage
 * @param {(targetUrl: string, userAgent?: string) => Promise<any>} deps.generateSignedUrl
 *   Existing `/signature` engine, already self-queued — reused as-is for
 *   `/webcast/sign_url`, which only signs (no follow-up page fetch, so nothing else
 *   can race it).
 * @param {(targetUrl: string, userAgent?: string, navigateTo?: string) => Promise<any>} deps.generateSignedUrlUnqueued
 *   Same signing engine, WITHOUT its own queue wrapper — for `/webcast/rooms/:id/connect`,
 *   which needs to run the sign step AND the raw-bytes fetch that follows it as a
 *   single atomic turn on the shared browser page (see `handleConnect`'s own comment).
 * @param {(fn: () => Promise<any>) => Promise<any>} deps.queueSignatureRequest
 *   The raw request queue `generateSignedUrl` normally wraps itself in.
 * @param {() => Array<{name: string, value: string}>} deps.getCookies
 */
export function createWebcastRoutes({
  initBrowser,
  ensurePageReady,
  getPage,
  generateSignedUrl,
  generateSignedUrlUnqueued,
  queueSignatureRequest,
  getCookies,
}) {
  /** GET /webcast/rooms/:roomId/connect */
  async function handleConnect(req, res, roomId, query) {
    await initBrowser();
    await ensurePageReady();

    const targetUrl = buildTikTokWebcastUrl({
      roomId,
      uniqueId: query.get("unique_id"),
      cursor: query.get("cursor"),
      userAgent: query.get("user_agent"),
      clientEnter: query.get("client_enter") === "true" || query.get("client_enter") === "1",
    });

    // Sign AND fetch the raw bytes as ONE turn on the shared page queue — not two
    // separate queued calls back to back. The real bug this fixes: `generateSignedUrl`
    // used to release its queue slot as soon as SIGNING finished, so a second overlapping
    // `/connect` request (the gateway retries every ~2.5s) could start its OWN
    // `page.goto()` navigation while THIS request's `fetchRawBytesThroughPage` still had
    // a `page.evaluate(...)` fetch in flight on that same page — tearing down its JS
    // execution context mid-await and leaving `response` as `undefined`, which surfaced
    // as the cryptic "Cannot read properties of undefined (reading 'arrayBuffer')".
    // Wrapping the whole sequence in one `queueSignatureRequest` call closes that gap.
    let raw;
    try {
      raw = await queueSignatureRequest(async () => {
        // Reuses the SAME sign+navigate machinery `/signature` already uses (this
        // module never touches the browser/SDK internals directly) — the UNQUEUED
        // variant, since we're already inside the queue here.
        const signed = await generateSignedUrlUnqueued(targetUrl, query.get("user_agent") || null);
        return fetchRawBytesThroughPage(getPage(), signed.signedUrl);
      });
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: `webcast fetch failed: ${e.message}` }));
      return;
    }

    // DIAGNOSTIC — remove once the "not yet verified" caveat above is resolved. If
    // `preview` reads as HTML/JSON text instead of binary garbage, TikTok rejected the
    // request (captcha, malformed params, bot check) and returned an error PAGE with a
    // 200 status instead of real protobuf — which is exactly what makes the connector's
    // `pushServer` end up empty/wrong and `ws` fail with "Unexpected server response:
    // 200" one step later.
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
