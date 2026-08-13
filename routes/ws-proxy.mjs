/**
 * WebSocket proxy for TikTok's real-time push server, opened FROM INSIDE the signer's
 * own Puppeteer/Chrome session instead of from Node.
 *
 * Why this exists: the HTTP fetch (`/webcast/rooms/:id/connect`) already succeeds
 * end-to-end — it runs through the real browser page, so it carries a genuine browser
 * TLS fingerprint and cookies. The follow-up WebSocket to TikTok's push server
 * (`wss://webcast-ws.tiktok.com/...`), by contrast, was being opened directly by Node's
 * `ws` library in the gateway process. Even with correct headers/host/Origin/cookies
 * (all tried and ruled out — see the gateway's `tiktokPool.ts` history), TikTok's WS
 * gateway kept soft-rejecting the handshake (HTTP 200 instead of 101) — consistent with
 * a TLS-level (JA3/JA4) fingerprint check that no HTTP-layer header can fix, since
 * Node's TLS stack simply looks different from a real browser's.
 *
 * This route sidesteps that: the gateway connects to THIS local WS endpoint instead of
 * TikTok directly; this module opens the *actual* TikTok WebSocket from inside the page
 * (a real `new WebSocket(...)` in Chrome's own JS context, using the page's own TLS
 * stack and cookie jar), and relays frames in BOTH directions — browser->gateway for
 * incoming chat/gift events, and gateway->browser for the connector's own outgoing
 * heartbeat/ack frames (`WebcastWebSocketClient.sendHeartbeat`/`sendAck` in
 * tiktok-live-connector), which TikTok's push server requires periodically or it drops
 * the connection.
 *
 * Ordering matters here in a way that isn't obvious: the gateway-facing WS upgrade must
 * NOT complete until the REAL TikTok socket has actually finished connecting. Confirmed
 * live — without this wait, `tiktok-live-connector` considers its socket "open" as soon
 * as THIS local hop connects (near-instant, it's localhost), and immediately sends its
 * `im_enter_room` message. That message would race the real (slower, real-network)
 * TikTok handshake and arrive while the real socket was still `readyState === 0`
 * (CONNECTING), getting silently dropped — so TikTok's WS server was never actually told
 * which room to push data for. It kept accepting heartbeats (a separate, room-agnostic
 * mechanism) without ever pushing chat/gifts, which is why the symptom looked like "the
 * connection is stable but nothing ever arrives" rather than an outright failure.
 */
import { WebSocketServer } from "ws";
import { randomUUID } from "crypto";

const OPEN_TIMEOUT_MS = 15000;

export function createWsProxyRoutes({ getPage, initBrowser, ensurePageReady }) {
  const wss = new WebSocketServer({ noServer: true });
  /** id -> the local (gateway-facing) WebSocket for that in-page connection. */
  const localSockets = new Map();
  /** id -> {resolve, reject} while waiting for the real in-page socket to open. */
  const pendingOpens = new Map();

  /** Called (via `page.exposeFunction`) from inside the browser page. */
  function onBridgeEvent(id, type, payload) {
    const pending = pendingOpens.get(id);
    if (pending) {
      if (type === "open") {
        pendingOpens.delete(id);
        pending.resolve();
      } else if (type === "close" || type === "error") {
        pendingOpens.delete(id);
        pending.reject(new Error(`upstream socket ${type} before opening`));
      }
      return;
    }

    const local = localSockets.get(id);
    if (!local) return;
    if (type === "message") {
      if (local.readyState === local.OPEN) {
        local.send(Buffer.from(payload, "base64"));
      }
      return;
    }
    if (type === "close" || type === "error") {
      localSockets.delete(id);
      try {
        local.close(type === "error" ? 1011 : 1000, type);
      } catch {}
    }
  }

  /**
   * Registers the in-page bridge. Must be called once per `page` instance, before that
   * page's first navigation — `evaluateOnNewDocument` re-injects on every navigation
   * after that (matches the pattern `server.mjs` already uses for its other
   * `evaluateOnNewDocument` calls), so it does NOT need to be re-run on every
   * `page.goto`/`page.reload`, only when the browser/page itself is recreated.
   */
  async function installBridge(page) {
    await page.exposeFunction("__spWsEvent", onBridgeEvent);
    await page.evaluateOnNewDocument(() => {
      window.__spSockets = new Map();
      window.__spWsOpen = (id, url) => {
        try {
          const socket = new WebSocket(url);
          socket.binaryType = "arraybuffer";
          window.__spSockets.set(id, socket);
          socket.onopen = () => window.__spWsEvent(id, "open", "");
          socket.onmessage = (ev) => {
            let b64;
            if (typeof ev.data === "string") {
              b64 = btoa(unescape(encodeURIComponent(ev.data)));
            } else {
              const bytes = new Uint8Array(ev.data);
              let bin = "";
              for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
              b64 = btoa(bin);
            }
            window.__spWsEvent(id, "message", b64);
          };
          socket.onclose = () => {
            window.__spSockets.delete(id);
            window.__spWsEvent(id, "close", "");
          };
          socket.onerror = () => {
            window.__spWsEvent(id, "error", "");
          };
        } catch (e) {
          window.__spWsEvent(id, "error", String((e && e.message) || e));
        }
      };
      window.__spWsClose = (id) => {
        const s = window.__spSockets.get(id);
        if (s) {
          try {
            s.close();
          } catch {}
        }
        window.__spSockets.delete(id);
      };
      window.__spWsSend = (id, base64) => {
        const s = window.__spSockets.get(id);
        if (!s || s.readyState !== WebSocket.OPEN) return;
        const bin = atob(base64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        s.send(bytes);
      };
    });
  }

  /** Registered on the HTTP server's `upgrade` event in server.mjs. */
  async function handleUpgrade(req, socket, head) {
    let target;
    try {
      const url = new URL(req.url, "http://localhost");
      if (url.pathname !== "/webcast/ws-proxy") {
        socket.destroy();
        return;
      }
      target = url.searchParams.get("target");
      if (!target) throw new Error("missing target");
      new URL(target);
    } catch {
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }

    try {
      await initBrowser();
      await ensurePageReady();
    } catch {
      socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      socket.destroy();
      return;
    }

    const id = randomUUID();

    // Open the REAL TikTok socket and wait for it to actually finish connecting BEFORE
    // completing the gateway-facing upgrade — see the module header comment for why.
    const opened = new Promise((resolve, reject) => {
      pendingOpens.set(id, { resolve, reject });
    });
    const timeout = setTimeout(() => {
      const pending = pendingOpens.get(id);
      if (pending) {
        pendingOpens.delete(id);
        pending.reject(new Error("timed out waiting for upstream socket to open"));
      }
    }, OPEN_TIMEOUT_MS);

    getPage()
      .evaluate((wsId, wsUrl) => window.__spWsOpen(wsId, wsUrl), id, target)
      .catch((e) => {
        const pending = pendingOpens.get(id);
        if (pending) {
          pendingOpens.delete(id);
          pending.reject(e);
        }
      });

    try {
      await opened;
    } catch (e) {
      clearTimeout(timeout);
      socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      socket.destroy();
      getPage()
        .evaluate((wsId) => {
          if (window.__spWsClose) window.__spWsClose(wsId);
        }, id)
        .catch(() => {});
      return;
    }
    clearTimeout(timeout);

    wss.handleUpgrade(req, socket, head, (local) => {
      localSockets.set(id, local);

      local.on("message", (data) => {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        getPage()
          .evaluate((wsId, b64) => {
            if (window.__spWsSend) window.__spWsSend(wsId, b64);
          }, id, buf.toString("base64"))
          .catch(() => {});
      });

      local.on("close", () => {
        localSockets.delete(id);
        getPage()
          .evaluate((wsId) => {
            if (window.__spWsClose) window.__spWsClose(wsId);
          }, id)
          .catch(() => {});
      });
    });
  }

  return { installBridge, handleUpgrade };
}
