#!/usr/bin/env node
/**
 * TikTok Signature Server
 *
 * Generates valid X-Bogus and X-Gnarly signatures for TikTok API requests.
 * Uses a persistent browser session with local SDK injection for reliable signature generation.
 *
 * Endpoints:
 * - POST /signature - Generate signed URL (body: { "url": "..." }) - RECOMMENDED for scalability
 * - POST /fetch     - Fetch through browser (slower, but 100% reliable fallback)
 * - GET  /health    - Health check
 * - GET  /restart   - Restart browser session
 *
 * Environment Variables:
 * - PORT          - Server port (default: 8080)
 * - PROXY_ENABLED - Enable proxy (default: false)
 * - PROXY_HOST    - Proxy host:port (e.g., "proxy.example.com:8080")
 * - PROXY_USER    - Proxy username
 * - PROXY_PASS    - Proxy password
 * - TUNNEL_INTERNAL_SECRET   - Opt-in per-streamer tunnel, shared with the gateway (see
 *                              tunnelBroker.ts). Empty = fully inert.
 * - GATEWAY_TUNNEL_PROXY_URL - The gateway's internal CONNECT proxy URL for the tunnel.
 */

import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import { encode as encodeXGnarly } from "./xgnarly.mjs";
import { createWebcastRoutes } from "./routes/webcast-connect.mjs";
import { createWsProxyRoutes } from "./routes/ws-proxy.mjs";

// Use stealth plugin with default evasions
puppeteer.use(StealthPlugin());

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

// Custom user data directory to avoid filling /tmp
const USER_DATA_DIR = path.join(__dirname, ".chrome-profile");

// User agent - Safari on macOS
const DEFAULT_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15";

// Current active user agent (can be overridden per-request)
let currentUserAgent = DEFAULT_UA;

// Proxy configuration from environment
const PROXY_ENABLED =
  process.env.PROXY_ENABLED === "true" && process.env.PROXY_HOST;
const PROXY_HOST = process.env.PROXY_HOST || "";
const PROXY_USER = process.env.PROXY_USER || "";
const PROXY_PASS = process.env.PROXY_PASS || "";

// Túnel opcional por streamer (ver streampack-tiktok-gateway/src/tunnelBroker.ts) —
// mismo secreto compartido SOLO entre este proceso y el gateway. Vacío = la función
// queda inerte del todo: fetchWebcastRawBytes ignora cualquier tunnelId que le llegue y
// sigue firmando siempre por el proxy compartido de siempre, sin excepción.
const TUNNEL_INTERNAL_SECRET = process.env.TUNNEL_INTERNAL_SECRET || "";
// URL del proxy CONNECT interno del gateway (ej. "http://localhost:8082") — nunca
// expuesto a internet, sólo alcanzable desde este proceso.
const GATEWAY_TUNNEL_PROXY_URL = process.env.GATEWAY_TUNNEL_PROXY_URL || "";
const TUNNEL_FEATURE_ENABLED = !!(TUNNEL_INTERNAL_SECRET && GATEWAY_TUNNEL_PROXY_URL);

// Local SDK path - the SDK is used to generate valid signatures
const SDK_PATH = path.join(__dirname, "javascript", "webmssdk_5.1.3.js");
let localSdkContent = null;

// Versioned SDK files served in place of the CDN copies.
const SDK_368_PATH = path.join(
  __dirname,
  "javascript",
  "webmssdk_1.0.0.368.js",
);
const SDK_485_PATH = path.join(
  __dirname,
  "javascript",
  "webmssdk_2.0.0.485.js",
);
let sdk368 = null;
let sdk485 = null;
try {
  if (fs.existsSync(SDK_368_PATH)) {
    sdk368 = fs.readFileSync(SDK_368_PATH, "utf-8");
    console.log("[Server] Loaded:", SDK_368_PATH);
  }
  if (fs.existsSync(SDK_485_PATH)) {
    sdk485 = fs.readFileSync(SDK_485_PATH, "utf-8");
    console.log("[Server] Loaded:", SDK_485_PATH);
  }
} catch (e) {
  console.log("[Server] SDK load error:", e.message);
}

// Try to load local SDK
try {
  if (fs.existsSync(SDK_PATH)) {
    localSdkContent = fs.readFileSync(SDK_PATH, "utf-8");
    console.log("[Server] Local SDK loaded:", SDK_PATH);
  }
} catch (e) {
  console.log("[Server] Local SDK not found:", e.message);
}

// Browser state
let browser = null;
let page = null;
let cookies = null;
let isInitializing = false;
let isReady = false;
let generationCount = 0;
let initMethod = null;
let lastInitTime = null;

// Cache of page-emitted signed URLs, keyed by pathname.
const signedUrlCache = new Map();
const SIGNED_CACHE_MAX_AGE_MS = 60_000;

// Auto-refresh configuration to avoid blocks
const MAX_GENERATIONS_BEFORE_REFRESH =
  Number(process.env.MAX_GENERATIONS_BEFORE_REFRESH) || 500; // Restart browser after this many signatures
const MAX_SESSION_AGE_MS =
  Number(process.env.MAX_SESSION_AGE_MS) || 30 * 60 * 1000; // Restart browser after 30 minutes

// Request queue for sequential processing (prevents concurrent access to browser page)
const requestQueue = [];
let isProcessingQueue = false;

/**
 * Add a signature request to the queue and process sequentially
 */
function queueSignatureRequest(signFn) {
  return new Promise((resolve, reject) => {
    const queuePosition = requestQueue.length + 1;
    if (queuePosition > 1) {
      console.log(`[Queue] Request queued at position ${queuePosition}`);
    }
    requestQueue.push({ signFn, resolve, reject });
    processQueue();
  });
}

/**
 * Process the queue sequentially
 */
async function processQueue() {
  if (isProcessingQueue || requestQueue.length === 0) {
    return;
  }

  isProcessingQueue = true;

  while (requestQueue.length > 0) {
    const { signFn, resolve, reject } = requestQueue.shift();
    const remaining = requestQueue.length;
    if (remaining > 0) {
      console.log(
        `[Queue] Processing request, ${remaining} remaining in queue`,
      );
    }
    try {
      const result = await signFn();
      resolve(result);
    } catch (e) {
      console.error(`[Queue] Request failed: ${e.message}`);
      reject(e);
    }
  }

  isProcessingQueue = false;
}

/**
 * Initialize browser with local SDK injection
 */
async function initBrowser() {
  if (isInitializing) {
    // Wait for initialization to complete
    while (isInitializing) {
      await new Promise((r) => setTimeout(r, 100));
    }
    return;
  }

  if (isReady && browser && page) {
    return;
  }

  isInitializing = true;
  console.log("[Server] Initializing browser...");

  try {
    // Determine Chrome executable path
    const getChromePath = () => {
      // Check for Docker/env override first
      if (process.env.PUPPETEER_EXECUTABLE_PATH) {
        return process.env.PUPPETEER_EXECUTABLE_PATH;
      }
      // macOS
      if (process.platform === "darwin") {
        return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
      }
      // Linux - try common paths
      if (process.platform === "linux") {
        const paths = [
          "/usr/bin/chromium",
          "/usr/bin/chromium-browser",
          "/usr/bin/google-chrome",
          "/usr/bin/google-chrome-stable",
        ];
        for (const p of paths) {
          try {
            fs.accessSync(p);
            return p;
          } catch {}
        }
      }
      return undefined; // Let Puppeteer find it
    };

    // Build browser args
    const browserArgs = [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-blink-features=AutomationControlled",
      "--disable-gpu",
      "--window-size=1920,1080",
    ];

    // Add proxy if enabled
    if (PROXY_ENABLED) {
      browserArgs.push(`--proxy-server=http://${PROXY_HOST}`);
      // Scraping-API-style proxies (scrape.do, and most others in this category)
      // terminate TLS themselves and re-issue their own certificate — needed for
      // their own features (JS rendering, unblocking) — which Chromium's public CA
      // trust store rejects by default (`ERR_CERT_AUTHORITY_INVALID`, confirmed
      // live). Only relaxed when a proxy is actually in use, not by default.
      browserArgs.push("--ignore-certificate-errors");
      console.log(`[Server] Proxy enabled: ${PROXY_HOST}`);
    } else {
      console.log("[Server] Proxy disabled - direct connection");
    }

    // Ensure user data directory exists
    if (!fs.existsSync(USER_DATA_DIR)) {
      fs.mkdirSync(USER_DATA_DIR, { recursive: true });
    }

    browser = await puppeteer.launch({
      headless: "new",
      executablePath: getChromePath(),
      args: browserArgs,
      userDataDir: USER_DATA_DIR,
      ignoreDefaultArgs: ["--enable-automation"],
    });

    page = await browser.newPage();

    // StreamPack: CONFIRMADO en vivo (consola real capturada) — la petición a
    // webcast/im/fetch la bloquea la propia Content-Security-Policy (`connect-src`) de
    // la página de tiktok.com: "Fetch API cannot load .../webcast/im/fetch/... Refused
    // to connect because it violates the document's Content Security Policy." Esa CSP
    // permite `wss://im-ws.tiktok.com` pero no `https://webcast.tiktok.com` para fetch
    // normal — coincide exacto con por qué nunca aparecía ni en response, ni en
    // requestfailed, ni en nuestro propio interceptor de peticiones: el bloqueo pasa
    // ANTES de que la petición llegue a la capa de red. `setBypassCSP` es el mecanismo
    // oficial de Puppeteer/CDP para que herramientas de automatización ignoren la CSP
    // de la página — a diferencia de los intentos anteriores (fetch nativo, captura por
    // CDP, bypass de Service Worker), esto ataca la causa real ya confirmada, no una
    // teoría.
    await page.setBypassCSP(true);

    // Se deja también el bypass de Service Worker (barato, sin downside) por si en
    // algún momento vuelve a haber una capa de bloqueo distinta — pero la CSP de arriba
    // es la causa real confirmada de este síntoma.
    const cdpSession = await page.target().createCDPSession();
    await cdpSession.send("Network.setBypassServiceWorker", { bypass: true });

    // Registers the in-page WS bridge (see routes/ws-proxy.mjs) — must happen before
    // this page's first navigation so `evaluateOnNewDocument` covers it.
    await wsProxy.installBridge(page);

    // Forwards the bridge's own [SP-WS] diagnostic console.log calls (see
    // routes/ws-proxy.mjs) to this terminal — otherwise they're only visible in the
    // headless browser's own console, which nothing reads.
    //
    // DIAGNOSTIC — este filtro descartaba TODO lo demás en silencio, incluido
    // cualquier error real que Chrome loguee a consola (un bloqueo de CSP se reporta
    // EXACTAMENTE así: "Refused to connect to '...' because it violates the following
    // Content Security Policy directive..."). Dado que la petición a webcast/im/fetch
    // no deja rastro en ningún otro lado (ni response, ni requestfailed, ni nuestro
    // propio interceptor), esto puede ser la señal real que nos faltaba ver. Se
    // reenvía también cualquier mensaje de tipo error/warning, no sólo los [SP-WS].
    page.on("console", (msg) => {
      const text = msg.text();
      if (text.startsWith("[SP-WS]") || text.startsWith("[SP-FETCH]")) {
        console.log("[Server]", text);
        return;
      }
      const type = msg.type();
      if (type === "error" || type === "warning") {
        // Acortar cualquier URL larga DENTRO del mensaje (nuestras URLs firmadas son
        // enormes por X-Bogus/X-Gnarly/msToken) en vez de cortar el mensaje entero por
        // longitud — el motivo real de Chrome suele venir DESPUÉS de la URL, y un
        // slice(0, N) simple se lo comía antes de que llegáramos a verlo.
        const shortened = text.replace(/https?:\/\/\S{80,}/g, (m) => m.slice(0, 60) + "…[url acortada]");
        console.log(`[webcast] console.${type}:`, shortened.slice(0, 1500));
      }
    });
    page.on("pageerror", (err) => {
      console.log(`[webcast] pageerror:`, String(err).slice(0, 500));
    });

    // Permanent passive listener: every signed request the page emits gets
    // cached by its pathname. /signature reads this cache and returns the
    // freshest URL without navigating.
    page.on("request", (request) => {
      try {
        const u = request.url();
        if (!u.includes("X-Gnarly=")) return;
        const parsed = new URL(u);
        signedUrlCache.set(parsed.pathname, {
          url: u,
          capturedAt: Date.now(),
          referer: request.headers().referer || "",
        });
      } catch (e) {}
    });

    // Authenticate with proxy if enabled
    if (PROXY_ENABLED && PROXY_USER && PROXY_PASS) {
      await page.authenticate({
        username: PROXY_USER,
        password: PROXY_PASS,
      });
    }

    await page.setUserAgent(DEFAULT_UA);
    await page.setViewport({ width: 1920, height: 1080 });

    // Apply platform override to match Safari on macOS
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, "platform", {
        get: () => "MacIntel",
        configurable: true,
      });
    });

    await page.evaluateOnNewDocument(() => {
      if (typeof window.process === "undefined") {
        window.process = {
          env: { NODE_ENV: "production" },
          browser: true,
          version: "",
          versions: {},
        };
      }
    });

    // StreamPack: TikTok's own SDK patches `window.fetch` (it needs to, to build the
    // totalFetchRequests/interceptedFetchRequests counters `_signDirectly` reads from
    // `window.__cap3` for its own anti-bot signature) — confirmed live: after that
    // patch, calling `fetch()` against `webcast.tiktok.com/webcast/im/fetch/` resolves
    // to `undefined` instead of a real Response (`fetchIsNative: false` in the
    // diagnostic added alongside this fix). `evaluateOnNewDocument` runs before ANY
    // page script on every navigation (a CDP guarantee), so this always wins the race
    // and stashes the true native fetch before TikTok's SDK can touch it.
    await page.evaluateOnNewDocument(() => {
      window.__streampackNativeFetch = window.fetch.bind(window);
    });

    // Initialize with local SDK
    await initWithLocalSdk();
    lastInitTime = new Date().toISOString();
    console.log(`[Server] Browser ready (init method: ${initMethod})`);
    isReady = true;
  } catch (e) {
    console.error("[Server] Init error:", e.message);
    await closeBrowser();
    throw e;
  } finally {
    isInitializing = false;
  }
}

/**
 * Detect TikTok's "Something went wrong" interstitial and click its Refresh
 * button. Returns true if the error was detected and handled, false otherwise.
 * Tries up to 2 retries since the second load occasionally errors too.
 */
async function dismissTikTokErrorIfPresent(maxAttempts = 2, targetPage = page) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const state = await targetPage.evaluate(() => {
      const text = document.body ? document.body.innerText || "" : "";
      const hasError = /Something went wrong/i.test(text);
      const refreshBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => /^\s*Refresh\s*$/i.test(b.textContent || ""),
      );
      return { hasError, hasRefreshBtn: !!refreshBtn };
    });
    if (!state.hasError) {
      return attempt === 1 ? false : true;
    }
    console.log(
      `[Server] Detected "Something went wrong" interstitial (attempt ${attempt}/${maxAttempts}), clicking Refresh...`,
    );
    await targetPage.evaluate(() => {
      const btn = Array.from(document.querySelectorAll("button")).find((b) =>
        /^\s*Refresh\s*$/i.test(b.textContent || ""),
      );
      if (btn) btn.click();
    });
    // Wait for the bundle to re-initialise after the click
    try {
      await targetPage.waitForNavigation({
        waitUntil: "domcontentloaded",
        timeout: 30000,
      });
    } catch (e) {
      // Some refreshes don't trigger a full navigation; just wait
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return true;
}


/**
 * Initialize with TikTok page context and LOCAL SDK
 * Injects local SDK BEFORE page loads using evaluateOnNewDocument
 */
async function initWithLocalSdk() {
  if (!localSdkContent) {
    throw new Error(
      "Local SDK not available - ensure webmssdk_5.1.3.js exists in javascript/ folder",
    );
  }

  console.log("[Server] Injecting local SDK before navigation...");

  // Inject SDK before any page scripts run
  await page.evaluateOnNewDocument((sdkCode) => {
    try {
      eval(sdkCode);
      console.log("[SDK] Injected via evaluateOnNewDocument");
    } catch (e) {
      console.error("[SDK] Injection error:", e.message);
    }
  }, localSdkContent);

  // Set up request interception to block TikTok's SDK (prevent conflicts)
  console.log("[Server] Setting up request interception...");
  await page.setRequestInterception(true);

  const requestHandler = async (request) => {
    const url = request.url();
    const resourceType = request.resourceType();

    // DIAGNOSTIC — la petición a webcast/im/fetch nunca aparece en response ni en
    // requestfailed del lado de Puppeteer, aunque curl desde la misma VM sí conecta
    // bien contra ese host. Candidato principal: algo en ESTE handler (o el
    // `request.continue()` de más abajo, sin try/catch hoy) la deja colgada sin
    // resolver. Loguear entrada + resultado real de la resolución para esta URL en
    // particular, sin tocar el comportamiento de ninguna otra.
    const isWebcastFetch = url.includes("/webcast/im/fetch/");
    if (isWebcastFetch) {
      console.log(
        `[webcast] requestHandler vio la petición — resourceType=${resourceType} isInterceptResolutionHandled=${request.isInterceptResolutionHandled?.()}`,
      );
    }

    if (url.includes("/webmssdk/")) {
      let body = null;
      if (url.includes("2.0.0.485") && sdk485) body = sdk485;
      else if (url.includes("1.0.0.368") && sdk368) body = sdk368;
      else if (sdk485) body = sdk485;
      if (body) {
        try {
          await request.respond({
            status: 200,
            contentType: "application/javascript; charset=utf-8",
            body,
          });
        } catch (e) {
          await request.abort();
        }
        return;
      }
    }

    // Block other security/telemetry SDK files (we don't want them interfering)
    if (
      url.includes("/webmssdk/") ||
      url.includes("slardar") ||
      url.includes("acrawler")
    ) {
      await request.abort();
      return;
    }

    // Block heavy resources to speed up loading
    if (["image", "media", "font"].includes(resourceType)) {
      if (isWebcastFetch) {
        console.log(`[webcast] requestHandler la ABORTÓ por resourceType=${resourceType} (bug: no debería pasar)`);
      }
      await request.abort();
      return;
    }

    try {
      await request.continue();
      if (isWebcastFetch) console.log(`[webcast] requestHandler llamó a continue() sin tirar error`);
    } catch (e) {
      // Antes de este cambio esto quedaba sin capturar: si continue() tira acá, la
      // petición queda colgada para siempre (ni continúa, ni aborta, ni responde) —
      // exactamente el síntoma que estamos viendo para webcast/im/fetch.
      console.log(`[Server] request.continue() failed for ${url.slice(0, 100)}: ${e.message}`);
    }
  };

  page.on("request", requestHandler);

  console.log("[Server] Navigating to TikTok...");
  await page.goto("https://www.tiktok.com/@zara", {
    waitUntil: "domcontentloaded",
    timeout: 60000,
  });

  // Wait for page to settle and SDK to initialize
  console.log("[Server] Waiting for SDK...");
  await new Promise((r) => setTimeout(r, 3000));

  // Check SDK status
  const sdkStatus = await page.evaluate(() => {
    const hasAcrawler = !!window.byted_acrawler;
    const hasFrontierSign =
      hasAcrawler && typeof window.byted_acrawler.frontierSign === "function";
    const keys = window.byted_acrawler
      ? Object.keys(window.byted_acrawler).slice(0, 10)
      : [];
    return { hasAcrawler, hasFrontierSign, keys };
  });

  console.log("[Server] SDK status:", JSON.stringify(sdkStatus));

  if (!sdkStatus.hasFrontierSign) {
    // DIAGNOSTIC — investigating a proxy-specific init failure: capture what the page
    // actually looks like (title + visible text) when the SDK check fails, to tell
    // apart "TikTok served a real page but our injection lost a race" from "TikTok (or
    // the proxy) served something else entirely (block page, captcha, error page)".
    try {
      const pageState = await page.evaluate(() => ({
        title: document.title,
        url: location.href,
        bodyPreview: (document.body?.innerText || "").slice(0, 300),
      }));
      console.log("[Server] Page state at SDK failure:", JSON.stringify(pageState));
    } catch (e) {
      console.log("[Server] Could not capture page state:", e.message);
    }
    throw new Error(
      `Local SDK failed to initialize: ${JSON.stringify(sdkStatus)}`,
    );
  }

  initMethod = "local-sdk";
  console.log("[Server] Local SDK initialized successfully");

  // Interception remains active across navigations.

  // Warm up the SDK
  console.log("[Server] Warming up SDK...");
  await page.evaluate(() => window.scrollBy(0, 500));
  await new Promise((r) => setTimeout(r, 2000));

  // Always reload after the initial load. First load is unreliable — sometimes
  // a blank/white page, sometimes the "Something went wrong" interstitial. The
  // reload primes the second pass with the cookies/msToken accumulated on the
  // first pass, after which the page bundle reliably emits signed requests.
  console.log("[Server] Reloading page to stabilize session...");
  try {
    await page.reload({ waitUntil: "domcontentloaded", timeout: 60000 });
  } catch (e) {
    console.log("[Server] Reload warning:", e.message);
  }
  await new Promise((r) => setTimeout(r, 3000));

  // If the second pass still shows the "Something went wrong" interstitial,
  // click its in-page Refresh button to retry once more.
  await dismissTikTokErrorIfPresent();

  // Extract cookies for use in requests
  cookies = await page.cookies();
  console.log(`[Server] Captured ${cookies.length} cookies`);
}

async function closeBrowser() {
  isReady = false;
  cookies = null;
  generationCount = 0;
  initMethod = null;
  lastInitTime = null;

  if (browser) {
    try {
      await browser.close();
    } catch (e) {
      console.error("[Server] Error closing browser:", e.message);
    }
    browser = null;
    page = null;
  }

  // browser.close() ya se llevó puesto cualquier BrowserContext de túnel que hubiera —
  // limpiar el mapa para no intentar reusar páginas muertas la próxima vez.
  tunnelContexts.clear();

  // Clean up user data directory to prevent disk space accumulation
  try {
    if (fs.existsSync(USER_DATA_DIR)) {
      fs.rmSync(USER_DATA_DIR, { recursive: true, force: true });
      console.log("[Server] Cleaned up browser profile directory");
    }
  } catch (e) {
    console.error("[Server] Error cleaning up profile:", e.message);
  }

  console.log("[Server] Browser closed, all state reset");
}

/**
 * Túnel opcional por streamer (ver streampack-tiktok-gateway/src/tunnelBroker.ts) —
 * cada streamer con el túnel activo tiene su PROPIO BrowserContext, lanzado con el
 * proxy CONNECT interno del gateway como su `proxyServer`, así que cualquier fetch
 * hecho desde una página de ese contexto sale por la conexión de ESE streamer en vez
 * de la del signer. La FIRMA (`_signDirectly`) sigue haciéndose siempre en la página
 * global de siempre — no toca este archivo — porque el perfil en disco
 * (`userDataDir`) se comparte entre todos los contextos del mismo `browser.launch()`,
 * así que las cookies/msToken de la sesión firmante ya están disponibles acá también
 * sin duplicar nada: sólo cambia por dónde sale la conexión del FETCH final.
 *
 * `tunnelId -> { context, page, lastUsed }`. Vive mientras dure la conexión de chat de
 * ese streamer en Studio (un `tunnelId` nuevo por cada sesión — ver `wsServer.ts`); el
 * barrido de `pruneIdleTunnelContexts` se encarga de los que quedan huérfanos si el
 * streamer se desconecta sin que este proceso se entere directamente.
 */
const tunnelContexts = new Map();
const TUNNEL_CONTEXT_IDLE_MS = 15 * 60 * 1000;

/** Bloquea request/response pesados (imágenes, media, fuentes, SDKs de telemetría) en
 *  una página de túnel — no firma nada acá, así que no hace falta servir el SDK local
 *  ni interceptar webmssdk como sí hace la página principal; esto es sólo para no
 *  gastar de más el ancho de banda del propio streamer. */
function installLightRequestBlocking(targetPage) {
  return targetPage.setRequestInterception(true).then(() => {
    targetPage.on("request", async (request) => {
      const url = request.url();
      const resourceType = request.resourceType();
      if (
        url.includes("slardar") ||
        url.includes("acrawler") ||
        ["image", "media", "font"].includes(resourceType)
      ) {
        try {
          await request.abort();
        } catch (e) {}
        return;
      }
      try {
        await request.continue();
      } catch (e) {}
    });
  });
}

/** Crea (o reusa) el contexto de túnel de un streamer. Tira si algo falla en el
 *  camino — el llamador (`fetchWebcastRawBytes`) cae al proxy compartido de siempre
 *  ante cualquier error acá, el túnel es la excepción, no lo único que existe. */
async function getOrCreateTunnelPage(tunnelId) {
  const existing = tunnelContexts.get(tunnelId);
  if (existing) {
    existing.lastUsed = Date.now();
    return existing.page;
  }

  console.log(`[tunnel] creando contexto propio para tunnelId=${tunnelId}`);
  const context = await browser.createBrowserContext({
    proxyServer: GATEWAY_TUNNEL_PROXY_URL,
  });
  let tunnelPage;
  try {
    tunnelPage = await context.newPage();
    // El proxy CONNECT del gateway pide Basic auth: usuario = tunnelId (así identifica
    // de cuál streamer es este pedido), contraseña = el secreto compartido — ver
    // `tunnelBroker.ts::parseBasicAuth`.
    await tunnelPage.authenticate({ username: tunnelId, password: TUNNEL_INTERNAL_SECRET });
    // Mismo motivo que en la página principal — ver el comentario largo en initBrowser.
    await tunnelPage.setBypassCSP(true);
    await tunnelPage.setUserAgent(DEFAULT_UA);
    await tunnelPage.setViewport({ width: 1920, height: 1080 });
    await installLightRequestBlocking(tunnelPage);

    // Navegar a un origen real de tiktok.com es necesario para que las cookies de la
    // sesión firmante (SameSite=Lax/Strict, no None) viajen en el fetch de más abajo —
    // un fetch cross-site desde una página que nunca pisó tiktok.com no las mandaría.
    await tunnelPage.goto("https://www.tiktok.com/@zara", {
      waitUntil: "domcontentloaded",
      timeout: 60000,
    });
    await dismissTikTokErrorIfPresent(2, tunnelPage);
  } catch (e) {
    try {
      await context.close();
    } catch (closeErr) {}
    throw e;
  }

  tunnelContexts.set(tunnelId, { context, page: tunnelPage, lastUsed: Date.now() });
  console.log(`[tunnel] contexto listo para tunnelId=${tunnelId}`);
  return tunnelPage;
}

/** Barrido periódico — cierra contextos de túnel que ningún pedido usó en un buen
 *  rato (el streamer se desconectó de Studio sin que este proceso se entere
 *  directamente de otra forma). Sin esto, cada sesión nueva de Studio (un `tunnelId`
 *  distinto cada vez) dejaría un contexto huérfano acumulándose para siempre. */
async function pruneIdleTunnelContexts() {
  const now = Date.now();
  for (const [tunnelId, t] of tunnelContexts) {
    if (now - t.lastUsed > TUNNEL_CONTEXT_IDLE_MS) {
      console.log(`[tunnel] cerrando contexto inactivo para tunnelId=${tunnelId}`);
      tunnelContexts.delete(tunnelId);
      try {
        await t.context.close();
      } catch (e) {
        console.error(`[tunnel] error cerrando contexto de ${tunnelId}:`, e.message);
      }
    }
  }
}

if (TUNNEL_FEATURE_ENABLED) {
  setInterval(() => {
    pruneIdleTunnelContexts().catch((e) => console.error("[tunnel] prune error:", e.message));
  }, 5 * 60 * 1000);
}

/**
 * Check if the browser session should be refreshed based on age or generation count
 */
function shouldRefreshSession() {
  if (!lastInitTime) return false;

  const sessionAge = Date.now() - new Date(lastInitTime).getTime();

  if (generationCount >= MAX_GENERATIONS_BEFORE_REFRESH) {
    console.log(
      `[Server] Session refresh needed: ${generationCount} generations reached`,
    );
    return true;
  }

  if (sessionAge >= MAX_SESSION_AGE_MS) {
    console.log(
      `[Server] Session refresh needed: ${Math.round(sessionAge / 60000)} minutes elapsed`,
    );
    return true;
  }

  return false;
}

/**
 * Check if the page is still valid and ready
 */
async function ensurePageReady() {
  try {
    if (!browser || !page) {
      throw new Error("Browser or page not initialized");
    }

    // Check if session should be refreshed to avoid blocks
    if (shouldRefreshSession()) {
      console.log("[Server] Proactive session refresh...");
      await closeBrowser();
      await initBrowser();
      return true;
    }

    await page.mainFrame();
    return true;
  } catch (e) {
    console.log("[Server] Page invalid, reinitializing...", e.message);
    isReady = false;
    await closeBrowser();
    await initBrowser();
    return true;
  }
}

/**
 * Generate signed URL for any TikTok URL
 * Triggers fetch, SDK signs it, we capture and abort
 * @param {string} targetUrl - The URL to sign
 * @param {string|null} userAgent - Optional custom user agent to return in response
 */
async function generateSignedUrl(
  targetUrl,
  userAgent = null,
  navigateTo = null,
) {
  return queueSignatureRequest(() =>
    _generateSignedUrlInternal(targetUrl, userAgent, navigateTo),
  );
}

/**
 * Fetches the RAW bytes of a signed URL through the browser page — the protobuf-safe
 * sibling of the existing `/fetch` route, which JSON-parses the response and would
 * corrupt binary data. Bytes cross the `page.evaluate` boundary as base64, since
 * Puppeteer serializes return values as JSON.
 *
 * CAUSA RAÍZ CONFIRMADA en vivo (ver commits anteriores de esta misma sesión de
 * depuración): el `fetch()` de la página estaba bloqueado por la propia
 * Content-Security-Policy de tiktok.com (`connect-src` no incluye
 * `https://webcast.tiktok.com`) — arreglado con `page.setBypassCSP(true)` en
 * `initBrowser`. Con eso confirmado (`[SP-FETCH] fetch() resolvió, status= 200`, dos
 * veces seguidas), se volvió a esta forma simple de leer el cuerpo DENTRO de la
 * página — el rodeo por `page.waitForResponse`/`response.buffer()` de Puppeteer (CDP)
 * que se probó mientras se buscaba la causa real terminó siendo, en sí mismo, un
 * problema nuevo: `response.buffer()` se cuelga de forma conocida cuando se combina
 * interceptación de peticiones con bypass de CSP. Ya no hace falta ese rodeo.
 */
async function fetchRawBytesThroughPage(signedUrl, targetPage = page) {
  const result = await targetPage.evaluate(async (url) => {
    try {
      const response = await fetch(url, {
        credentials: "include",
        headers: { Accept: "application/protobuf,application/json" },
      });
      const buf = await response.arrayBuffer();
      let binary = "";
      const bytes = new Uint8Array(buf);
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return { status: response.status, bodyBase64: btoa(binary) };
    } catch (e) {
      return { error: e.message };
    }
  }, signedUrl);

  if (result.error) throw new Error(result.error);
  return { status: result.status, bytes: Buffer.from(result.bodyBase64, "base64") };
}

/**
 * Signs `targetUrl` (browser+SDK, needs the shared page) then fetches the signed URL —
 * por el contexto de túnel propio del streamer si lo pidió y está disponible
 * (`tunnelId`), si no por la página compartida de siempre. Runs as ONE queue slot
 * (sign + fetch together) so an overlapping request's signing can't interleave with
 * this one's fetch.
 *
 * @param {string|null} tunnelId - Si el gateway mandó `x-streampack-tunnel-id` (el
 *   streamer activó el túnel propio, ver `streampack-tiktok-gateway/src/tunnelBroker.ts`)
 *   Y este proceso tiene `TUNNEL_INTERNAL_SECRET`/`GATEWAY_TUNNEL_PROXY_URL`
 *   configurados, el fetch (NO la firma — esa siempre corre en la página compartida,
 *   ver `getOrCreateTunnelPage`) sale por la conexión propia de ese streamer. Ante
 *   cualquier fallo armando/usando ese contexto, cae al proxy compartido de siempre en
 *   vez de romper el pedido — el túnel es la excepción, no lo único que existe.
 */
async function fetchWebcastRawBytes(targetUrl, userAgent, tunnelId = null) {
  return queueSignatureRequest(async () => {
    const signed = await _generateSignedUrlInternal(targetUrl, userAgent, null);

    if (tunnelId && TUNNEL_FEATURE_ENABLED) {
      try {
        const tunnelPage = await getOrCreateTunnelPage(tunnelId);
        return await fetchRawBytesThroughPage(signed.signedUrl, tunnelPage);
      } catch (e) {
        console.log(
          `[tunnel] falló para tunnelId=${tunnelId} (${e.message}) — cayendo al proxy compartido`,
        );
        tunnelContexts.delete(tunnelId);
      }
    }

    return fetchRawBytesThroughPage(signed.signedUrl);
  });
}

/**
 * Internal implementation - must be called through queue
 * @param {string} targetUrl - The URL to sign
 * @param {string|null} userAgent - Optional UA to return in response
 * @param {string|null} navigateTo - Optional TikTok page URL; when given,
 *   the response uses a page-intercept path instead of the default fast path.
 */
async function _generateSignedUrlInternal(
  targetUrl,
  userAgent = null,
  navigateTo = null,
) {
  await initBrowser();
  await ensurePageReady();

  // Parse target URL - remove existing signatures and normalize fingerprint params
  const urlObj = new URL(targetUrl);
  urlObj.searchParams.delete("X-Bogus");
  urlObj.searchParams.delete("X-Gnarly");
  urlObj.searchParams.delete("msToken");
  normalizeUrlFingerprint(urlObj);
  const fetchUrl = urlObj.toString();

  const attempt = async () => {
    if (navigateTo) {
      console.log(`[Server] Sign via page intercept: navigateTo=${navigateTo}`);
      return _signViaPageIntercept(fetchUrl, navigateTo, userAgent);
    }
    console.log(`[Server] Signing URL: ${fetchUrl.substring(0, 100)}...`);
    return _signDirectly(fetchUrl, userAgent);
  };

  try {
    return await attempt();
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    // SDK got detached from the page (navigation, crash, lost context).
    // Tear the session down and rebuild it, then retry the sign once.
    if (/SDK not initialized|SDK not ready/i.test(msg)) {
      console.log(
        `[Server] "${msg}" — restarting browser session and retrying...`,
      );
      try {
        await closeBrowser();
      } catch (closeErr) {
        console.error(
          "[Server] closeBrowser during recovery failed:",
          closeErr.message,
        );
      }
      await initBrowser();
      return attempt();
    }
    throw e;
  }
}

async function _signViaPageIntercept(targetUrl, navigateTo, userAgent = null) {
  const targetPath = new URL(targetUrl).pathname;
  const callStart = Date.now();

  // Always navigate per call — that's the only reliable way to get a fresh
  // signed URL that TikTok will accept on external fetch. Cache-reuse and
  // scroll-trigger were both tried and produced unfetchable URLs.
  await page.goto(navigateTo, {
    waitUntil: "domcontentloaded",
    timeout: 60000,
  });
  await dismissTikTokErrorIfPresent();

  // Wait for the permanent listener to capture a matching signed URL emitted
  // after this call started (rules out a stale entry left from a prior nav).
  // Residential proxies can be slow — give it 15s.
  const WAIT_MS = 15000;
  while (Date.now() - callStart < WAIT_MS) {
    const c = signedUrlCache.get(targetPath);
    if (c && c.capturedAt >= callStart) {
      cookies = await page.cookies();
      generationCount++;
      return parseResult(c.url, userAgent);
    }
    await new Promise((r) => setTimeout(r, 50));
  }

  throw new Error(
    `No fresh ${targetPath} request emitted by ${navigateTo} within ${WAIT_MS / 1000}s`,
  );
}

async function _signDirectly(fetchUrl, userAgent = null) {
  const out = await page.evaluate((url) => {
    if (typeof window.__sdkN === "undefined") {
      return { error: "SDK not initialized" };
    }
    const sdkN = window.__sdkN;
    let table = null;
    if (sdkN.u && sdkN.u[995] && sdkN.u[995].v) table = sdkN.u;
    else if (sdkN.B && sdkN.B.o && sdkN.B.o[995] && sdkN.B.o[995].v)
      table = sdkN.B.o;
    else if (sdkN.o && sdkN.o[995] && sdkN.o[995].v) table = sdkN.o;
    if (!table) return { error: "SDK not ready" };
    const u995 = table[995] && table[995].v;
    if (typeof u995 !== "function") {
      return { error: "SDK not ready" };
    }

    const u = new URL(url);
    const msTokenMatches = [...document.cookie.matchAll(/msToken=([^;]+)/g)];
    const msToken = msTokenMatches.length
      ? msTokenMatches[msTokenMatches.length - 1][1]
      : "";
    u.searchParams.delete("X-Bogus");
    u.searchParams.delete("X-Gnarly");
    u.searchParams.set("msToken", msToken);
    const queryString = u.search.slice(1);

    if (typeof window.__sigCallCount !== "number") window.__sigCallCount = 100;
    window.__sigCallCount += 1;
    const baseN = window.__sigCallCount;
    let counterObj = {
      totalXHRRequests: Math.floor(baseN * 0.6),
      totalFetchRequests: Math.floor(baseN * 0.4) + 3,
      interceptedXHRRequests: Math.floor(baseN * 0.1),
      interceptedFetchRequests: Math.floor(baseN * 0.05) + 1,
    };
    try {
      const cap3 = window.__cap3 || [];
      const lastNat = [...cap3]
        .reverse()
        .find((c) => c.fn === "gnarly_x" && c.args && c.args[3] && c.args[3].v);
      if (lastNat && lastNat.args[3].v) {
        const v = lastNat.args[3].v;
        const fromCap = {
          totalXHRRequests: (v.totalXHRRequests && v.totalXHRRequests.v) || 0,
          totalFetchRequests:
            (v.totalFetchRequests && v.totalFetchRequests.v) || 0,
          interceptedXHRRequests:
            (v.interceptedXHRRequests && v.interceptedXHRRequests.v) || 0,
          interceptedFetchRequests:
            (v.interceptedFetchRequests && v.interceptedFetchRequests.v) || 0,
        };
        if (fromCap.totalXHRRequests + fromCap.totalFetchRequests > 0) {
          counterObj = fromCap;
        }
      }
    } catch (e) {}

    const acrawlerInst =
      window.byted_acrawler && typeof window.byted_acrawler === "object"
        ? window.byted_acrawler
        : null;
    try {
      const xb = u995.call(acrawlerInst, queryString, "");
      return {
        urlBase: u.toString(),
        queryString,
        xBogus: xb,
        msTokenUsed: msToken,
        userAgent: navigator.userAgent,
        cookies: document.cookie,
        counters: counterObj,
      };
    } catch (e) {
      return { error: e.message, stack: e.stack };
    }
  }, fetchUrl);

  if (out.error) {
    throw new Error("Sign failed: " + out.error);
  }

  const xg = encodeXGnarly(out.queryString, "", out.userAgent, out.counters, {
    ubcode: 4,
    sdkVersion: "1.0.0.368",
  });

  const u = new URL(out.urlBase);
  u.searchParams.set("X-Bogus", out.xBogus);
  u.searchParams.set("X-Gnarly", xg);

  cookies = await page.cookies();
  generationCount++;
  return parseResult(u.toString(), userAgent);
}

/**
 * Normalize browser fingerprint query parameters to match the browser environment.
 * TikTok's X-Bogus signature encodes the browser's actual fingerprint, so the URL
 * params must be consistent with the browser environment or TikTok returns
 * "url doesn't match".
 * Only overwrites params that are already present in the URL.
 * @param {URL} urlObj - The URL object to normalize in place
 */
function normalizeUrlFingerprint(urlObj) {
  const params = urlObj.searchParams;

  // Map of fingerprint param -> correct value for our browser environment
  const fingerprint = {
    browser_platform: "MacIntel", // matches navigator.platform override
    os: "mac", // matches Safari macOS UA
    screen_width: "1920", // matches viewport
    screen_height: "1080", // matches viewport
  };

  let normalized = false;
  for (const [key, correctValue] of Object.entries(fingerprint)) {
    if (params.has(key) && params.get(key) !== correctValue) {
      console.log(
        `[Server] Normalizing ${key}: "${params.get(key)}" -> "${correctValue}"`,
      );
      params.set(key, correctValue);
      normalized = true;
    }
  }

  if (normalized) {
    console.log(
      "[Server] URL fingerprint params normalized to match browser environment",
    );
  }
}

/**
 * Sign URL using fetch interception
 * SDK intercepts fetch and adds signature params (X-Bogus, X-Gnarly)
 * @param {string} fetchUrl - The URL to sign
 * @param {string|null} userAgent - Optional custom user agent to return in response
 */
async function _signWithFetchInterception(fetchUrl, userAgent = null) {
  return new Promise(async (resolve, reject) => {
    let signedUrl = null;
    let timeout = null;
    let resolved = false;
    let cleanedUp = false;

    async function cleanup() {
      if (cleanedUp) return;
      cleanedUp = true;
      try {
        page.off("request", requestHandler);
        await page.setRequestInterception(false);
      } catch (e) {
        // Ignore cleanup errors
      }
    }

    const requestHandler = async (request) => {
      if (resolved) {
        try {
          if (!request.isInterceptResolutionHandled()) {
            await request.abort("aborted");
          }
        } catch (e) {}
        return;
      }

      const url = request.url();

      // Capture any signed request (contains X-Bogus)
      if (url.includes("X-Bogus") && !signedUrl) {
        signedUrl = url;

        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          await cleanup();
          generationCount++;
          resolve(parseResult(signedUrl, userAgent));
        }
      }

      // Abort request
      try {
        if (!request.isInterceptResolutionHandled()) {
          await request.abort("aborted");
        }
      } catch (e) {}
    };

    try {
      await page.setRequestInterception(true);
    } catch (e) {
      reject(new Error("Failed to enable request interception: " + e.message));
      return;
    }

    page.on("request", requestHandler);

    // Timeout fallback
    timeout = setTimeout(async () => {
      if (!resolved) {
        resolved = true;
        await cleanup();
        if (signedUrl) {
          generationCount++;
          resolve(parseResult(signedUrl, userAgent));
        } else {
          reject(new Error("Timeout waiting for signed URL"));
        }
      }
    }, 5000);

    // Trigger fetch - SDK will sign it
    try {
      page
        .evaluate((url) => {
          fetch(url, {
            method: "GET",
            credentials: "include",
            headers: { Accept: "*/*" },
          }).catch(() => {});
        }, fetchUrl)
        .catch((e) => {
          if (!resolved) {
            console.error("[Server] page.evaluate failed:", e.message);
          }
        });
    } catch (e) {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        await cleanup();
        reject(new Error("page.evaluate failed: " + e.message));
      }
    }
  });
}

function parseResult(url, userAgent = null) {
  const urlObj = new URL(url);
  const cookieString = cookies
    ? cookies.map((c) => `${c.name}=${c.value}`).join("; ")
    : "";
  return {
    signedUrl: url,
    xBogus: urlObj.searchParams.get("X-Bogus"),
    xGnarly: urlObj.searchParams.get("X-Gnarly"),
    secUid: urlObj.searchParams.get("secUid"),
    cursor: urlObj.searchParams.get("cursor"),
    deviceId: urlObj.searchParams.get("device_id"),
    userAgent: userAgent || currentUserAgent,
    cookies: cookieString,
  };
}

// Custom-sign-server routes (StreamPack addition — see routes/webcast-connect.mjs for
// why these exist and what they map to). Reuses this same file's browser/signing
// engine; doesn't duplicate it.
const tryHandleWebcastRoute = createWebcastRoutes({
  initBrowser,
  ensurePageReady,
  generateSignedUrl,
  // `/webcast/rooms/:id/connect` signs the URL through the browser/SDK, then fetches
  // it through that same page — see `fetchRawBytesThroughPage`'s comment above.
  fetchWebcastRawBytes,
  getCookies: () => cookies,
});

// Proxies the real TikTok live-push WebSocket through this same browser session — see
// routes/ws-proxy.mjs for why a plain Node `ws` connection to TikTok gets soft-rejected.
const wsProxy = createWsProxyRoutes({
  initBrowser,
  ensurePageReady,
  getPage: () => page,
});

/**
 * HTTP Request Handler
 */
async function handleRequest(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  try {
    // The webcast routes set their own content-type (protobuf, not JSON) — checked
    // before the default `Content-Type: application/json` below applies to everything
    // else, and inside this SAME try block so a route error gets the same 500 handling
    // as every other route instead of an unhandled rejection.
    if (await tryHandleWebcastRoute(req, res, url)) {
      return;
    }
    res.setHeader("Content-Type", "application/json");

    // Health check
    if (url.pathname === "/health") {
      const sessionAge = lastInitTime
        ? Date.now() - new Date(lastInitTime).getTime()
        : 0;
      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: "ok",
          ready: isReady,
          initializing: isInitializing,
          initMethod: initMethod,
          lastInitTime: lastInitTime,
          sessionAgeMinutes: Math.round(sessionAge / 60000),
          generationCount: generationCount,
          maxGenerationsBeforeRefresh: MAX_GENERATIONS_BEFORE_REFRESH,
          maxSessionAgeMinutes: MAX_SESSION_AGE_MS / 60000,
          queueLength: requestQueue.length,
          isProcessing: isProcessingQueue,
          localSdkAvailable: !!localSdkContent,
          proxyEnabled: PROXY_ENABLED,
          userAgent: currentUserAgent,
        }),
      );
      return;
    }

    // Fetch endpoint - makes request through browser (slower, but 100% reliable fallback)
    // Use /signature + external requests for better scalability
    if (url.pathname === "/fetch" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }

      let targetUrl = null;
      try {
        const json = JSON.parse(body);
        targetUrl = json.url;
      } catch (e) {
        try {
          new URL(body.trim());
          targetUrl = body.trim();
        } catch (e2) {}
      }

      if (!targetUrl) {
        res.writeHead(400);
        res.end(
          JSON.stringify({ status: "error", message: "URL is required" }),
        );
        return;
      }

      await initBrowser();
      await ensurePageReady();

      console.log(
        "[Server] Fetching through browser:",
        targetUrl.substring(0, 80) + "...",
      );

      const fetchResult = await page.evaluate(async (url) => {
        try {
          const response = await fetch(url, {
            credentials: "include",
            headers: { Accept: "application/json" },
          });
          const text = await response.text();
          return {
            status: response.status,
            bodyLength: text.length,
            data: text ? JSON.parse(text) : null,
          };
        } catch (e) {
          return { error: e.message };
        }
      }, targetUrl);

      console.log(
        "[Server] Fetch result:",
        fetchResult.error || `${fetchResult.bodyLength} bytes`,
      );

      if (fetchResult.error) {
        res.writeHead(500);
        res.end(
          JSON.stringify({ status: "error", message: fetchResult.error }),
        );
        return;
      }

      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: "ok",
          httpStatus: fetchResult.status,
          data: fetchResult.data,
        }),
      );
      return;
    }

    if (url.pathname === "/signature" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }

      let targetUrl = null;
      let userAgent = null;
      let navigateTo = null;

      // Try to parse as JSON first
      try {
        const json = JSON.parse(body);
        if (json.url) targetUrl = json.url;
        if (json.userAgent) userAgent = json.userAgent;
        if (json.navigateTo) navigateTo = json.navigateTo;
      } catch (e) {
        // Body might be a direct URL string
        try {
          new URL(body);
          targetUrl = body;
        } catch (e2) {}
      }

      if (!targetUrl) {
        res.writeHead(400);
        res.end(
          JSON.stringify({
            status: "error",
            message:
              'URL is required in body as JSON { "url": "...", "navigateTo": "...", "userAgent": "..." } or plain text URL',
          }),
        );
        return;
      }

      const result = await generateSignedUrl(targetUrl, userAgent, navigateTo);

      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: "ok",
          data: {
            signed_url: result.signedUrl,
            "x-bogus": result.xBogus,
            "x-gnarly": result.xGnarly,
            "device-id": result.deviceId,
            cookies: result.cookies,
            navigator: {
              user_agent: result.userAgent,
              platform: "MacIntel",
              browser_language: "en-US",
              os: "mac",
              screen_width: "1920",
              screen_height: "1080",
            },
          },
        }),
      );
      return;
    }

    // Restart browser
    if (url.pathname === "/restart") {
      console.log("[Server] Restarting browser...");
      await closeBrowser();
      await initBrowser();
      res.writeHead(200);
      res.end(JSON.stringify({ status: "ok", message: "Browser restarted" }));
      return;
    }

    // 404
    res.writeHead(404);
    res.end(JSON.stringify({ error: "Not found" }));
  } catch (e) {
    console.error("[Server] Error:", e.message);
    res.writeHead(500);
    res.end(JSON.stringify({ status: "error", message: e.message }));
  }
}

// Create server
const server = http.createServer(handleRequest);

server.on("upgrade", (req, socket, head) => {
  wsProxy.handleUpgrade(req, socket, head).catch((e) => {
    console.error("[Server] ws-proxy upgrade error:", e.message);
    try {
      socket.destroy();
    } catch {}
  });
});

server.listen(PORT, () => {
  console.log(`[Server] TikTok Signature Server running on port ${PORT}`);
  console.log(`[Server] Endpoints:`);
  console.log(
    `  POST /signature - Generate signed URL (RECOMMENDED for scalability)`,
  );
  console.log(
    `  POST /fetch     - Fetch through browser (fallback, 100% reliable)`,
  );
  console.log(`  GET  /health    - Health check`);
  console.log(`  GET  /restart   - Restart browser session`);
  console.log(`  WS   /webcast/ws-proxy?target=... - proxies a WS through the browser`);

  // Initialize browser on startup
  initBrowser().catch((e) => console.error("[Server] Init failed:", e.message));
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("\n[Server] Shutting down...");
  await closeBrowser();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\n[Server] Received SIGTERM, shutting down...");
  await closeBrowser();
  process.exit(0);
});
