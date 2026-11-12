/**
 * Pool of "relay" pages: browser tabs that ONLY host the live-room WebSockets opened by
 * `ws-proxy.mjs`, separate from the signing page.
 *
 * Why: before this, every room's WebSocket lived inside the single signing page, so the
 * proactive session refresh (every 30 min / 500 signatures, which closed the whole
 * browser) dropped every live room at once. Relay pages share the browser's default
 * context — same profile and cookie jar as the signing session — so the handshake is
 * the same as before, but recycling the signing page no longer touches them.
 *
 * A room goes to the relay with the fewest rooms that still has room
 * (`RELAY_ROOMS_PER_PAGE`); a relay left empty is closed after a short idle delay.
 */

const RELAY_ROOMS_PER_PAGE = Math.max(1, Number(process.env.RELAY_ROOMS_PER_PAGE) || 40);
/** A light same-origin document on tiktok.com: the socket's Origin is www.tiktok.com,
 *  as with the old signing page, without loading the whole web app. */
const RELAY_URL = process.env.RELAY_URL || "https://www.tiktok.com/robots.txt";
const RELAY_IDLE_CLOSE_MS = 60_000;

export function createRelayPool({ getBrowser, installBridge, userAgent }) {
  /** @type {Set<{page: import('puppeteer').Page, rooms: Set<string>, idleTimer: NodeJS.Timeout|null, ready: Promise<void>}>} */
  const relays = new Set();
  /** room id -> relay */
  const byRoom = new Map();
  let created = 0;

  async function openRelay() {
    const browser = getBrowser();
    if (!browser) throw new Error("browser not ready");
    const page = await browser.newPage();
    const relay = { page, rooms: new Set(), idleTimer: null, ready: null };
    relay.ready = (async () => {
      await page.setBypassCSP(true);
      if (userAgent) await page.setUserAgent(userAgent);
      await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, "platform", { get: () => "MacIntel", configurable: true });
      });
      await installBridge(page);
      await page.setRequestInterception(true);
      page.on("request", (request) => {
        const type = request.resourceType();
        const url = request.url();
        const block = ["image", "media", "font", "stylesheet"].includes(type) || url.includes("slardar") || url.includes("acrawler");
        (block ? request.abort() : request.continue()).catch(() => {});
      });
      page.on("console", (msg) => {
        const text = msg.text();
        if (text.startsWith("[SP-WS]")) console.log("[relay]", text);
      });
      await page.goto(RELAY_URL, { waitUntil: "domcontentloaded", timeout: 60_000 });
    })();
    relays.add(relay);
    created++;
    try {
      await relay.ready;
    } catch (e) {
      relays.delete(relay);
      page.close().catch(() => {});
      throw e;
    }
    console.log(`[relay] new relay page (${relays.size} open)`);
    return relay;
  }

  function pickRelay() {
    let best = null;
    for (const r of relays) {
      if (r.rooms.size >= RELAY_ROOMS_PER_PAGE || r.page.isClosed()) continue;
      if (!best || r.rooms.size < best.rooms.size) best = r;
    }
    return best;
  }

  /** The page that must host room `id` (opens a relay if every one is full). */
  async function acquire(id) {
    let relay = pickRelay();
    if (!relay) relay = await openRelay();
    else await relay.ready;
    if (relay.idleTimer) {
      clearTimeout(relay.idleTimer);
      relay.idleTimer = null;
    }
    relay.rooms.add(id);
    byRoom.set(id, relay);
    return relay.page;
  }

  /** The page hosting room `id`, or null if it isn't (or no longer is) in the pool. */
  function pageFor(id) {
    return byRoom.get(id)?.page ?? null;
  }

  function release(id) {
    const relay = byRoom.get(id);
    if (!relay) return;
    byRoom.delete(id);
    relay.rooms.delete(id);
    if (relay.rooms.size > 0 || relay.idleTimer) return;
    relay.idleTimer = setTimeout(() => {
      if (relay.rooms.size > 0) return;
      relays.delete(relay);
      relay.page.close().catch(() => {});
      console.log(`[relay] closed idle relay page (${relays.size} open)`);
    }, RELAY_IDLE_CLOSE_MS);
  }

  /** The browser went away (crash or full restart): every relay died with it. */
  function reset() {
    for (const r of relays) if (r.idleTimer) clearTimeout(r.idleTimer);
    relays.clear();
    byRoom.clear();
  }

  function stats() {
    return {
      relayPages: relays.size,
      relayRooms: byRoom.size,
      roomsPerRelay: [...relays].map((r) => r.rooms.size),
      relayRoomsPerPageMax: RELAY_ROOMS_PER_PAGE,
      relaysCreated: created,
    };
  }

  return { acquire, pageFor, release, reset, stats, activeRooms: () => byRoom.size };
}
