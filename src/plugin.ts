// opencode remote-control plugin
// Control any opencode session from your phone: scan a QR, prompt, watch answers, approve permissions, get push alerts.
// State + docs live in ~/.config/opencode/remote-control/
import type { Plugin } from "@opencode-ai/plugin"
import { createServer, type IncomingMessage, type ServerResponse } from "node:http"
import { networkInterfaces, homedir } from "node:os"
import { randomBytes, createHash, timingSafeEqual } from "node:crypto"
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs"
import { join } from "node:path"
import { createRequire } from "node:module"
import { spawn, type ChildProcess } from "node:child_process"

// ---------- types ----------
interface RCState {
  token: string
  vapidPublicKey?: string
  vapidPrivateKey?: string
  subscriptions: PushSub[]
}
interface PushSub {
  endpoint: string
  keys: { p256dh: string; auth: string }
}
interface SessLite {
  id: string
  title: string
  directory: string
  parentID?: string
  updated: number
}
interface PendingPermission {
  id: string
  sessionID: string
  title: string
  type: string
  created: number
  metadata?: Record<string, unknown>
}
interface BusEvent {
  type: string
  properties?: Record<string, unknown>
}

const RC_DIR = join(homedir(), ".config", "opencode", "remote-control")
const STATE_FILE = join(RC_DIR, "state.json")
const PORT_RANGE = [7777, 7778, 7779, 7780, 7781, 7782, 7783, 7784, 7785, 7786, 7787]
// bump when the embedded PWA changes - connected phones auto-reload on mismatch
const UI_VERSION = "4"

// ---------- state ----------
function loadState(): RCState {
  try {
    if (existsSync(STATE_FILE)) {
      const raw = JSON.parse(readFileSync(STATE_FILE, "utf8")) as Partial<RCState>
      if (typeof raw.token === "string" && raw.token.length >= 32) {
        return {
          token: raw.token,
          vapidPublicKey: typeof raw.vapidPublicKey === "string" ? raw.vapidPublicKey : undefined,
          vapidPrivateKey: typeof raw.vapidPrivateKey === "string" ? raw.vapidPrivateKey : undefined,
          subscriptions: Array.isArray(raw.subscriptions) ? (raw.subscriptions as PushSub[]) : [],
        }
      }
    }
  } catch {
    // corrupted state -> regenerate
  }
  return { token: randomBytes(24).toString("hex"), subscriptions: [] }
}
function saveState(state: RCState): void {
  try {
    mkdirSync(RC_DIR, { recursive: true })
    writeFileSync(STATE_FILE, JSON.stringify(state, null, 2))
  } catch (e) {
    log("failed to save state: " + String(e))
  }
}
function log(msg: string): void {
  try {
    const line = new Date().toISOString() + " " + msg + "\n"
    mkdirSync(RC_DIR, { recursive: true })
    writeFileSync(join(RC_DIR, "plugin.log"), line, { flag: "a" })
  } catch {
    /* ignore */
  }
}

// ---------- helpers ----------
function lanIP(): string {
  const nets = networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] ?? []) {
      if (net.family === "IPv4" && !net.internal) return net.address
    }
  }
  return "127.0.0.1"
}
function safeEqualToken(given: string, actual: string): boolean {
  const a = createHash("sha256").update(given).digest()
  const b = createHash("sha256").update(actual).digest()
  return timingSafeEqual(a, b)
}
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ""
    req.on("data", (c: Buffer) => {
      data += c.toString()
      if (data.length > 1_000_000) reject(new Error("body too large"))
    })
    req.on("end", () => resolve(data))
    req.on("error", reject)
  })
}
function sendJSON(res: ServerResponse, code: number, obj: unknown): void {
  const body = JSON.stringify(obj)
  res.writeHead(code, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  })
  res.end(body)
}
function sendText(res: ServerResponse, code: number, type: string, body: string): void {
  res.writeHead(code, { "Content-Type": type, "Access-Control-Allow-Origin": "*", "Cache-Control": "no-store" })
  res.end(body)
}

// ---------- the plugin ----------
export const RemoteControlPlugin: Plugin = async ({ client, directory }) => {
  try {
    mkdirSync(RC_DIR, { recursive: true })
    const state = loadState()

    // optional deps (graceful degradation)
    let webpush: typeof import("web-push") | null = null
    try {
      webpush = (await import("web-push")).default
      if (!state.vapidPublicKey || !state.vapidPrivateKey) {
        const keys = webpush.generateVAPIDKeys()
        state.vapidPublicKey = keys.publicKey
        state.vapidPrivateKey = keys.privateKey
      }
      webpush.setVapidDetails("mailto:remote-control@opencode.local", state.vapidPublicKey, state.vapidPrivateKey)
    } catch (e) {
      log("web-push unavailable, push alerts disabled: " + String(e))
      webpush = null
    }
    let qrlib: ((typeNumber: number, errorCorrectionLevel: string) => QRCodeObj) | null = null
    try {
      const mod = (await import("qrcode-generator")) as unknown as {
        default?: (t: number, e: string) => QRCodeObj
      }
      qrlib = typeof mod.default === "function" ? mod.default : (mod as unknown as (t: number, e: string) => QRCodeObj)
    } catch (e) {
      log("qrcode-generator unavailable, ASCII QR disabled: " + String(e))
    }
    saveState(state)

    // live state
    const sseClients = new Set<ServerResponse>()
    const sessions = new Map<string, SessLite>()
    const pendingPerms = new Map<string, PendingPermission>()
    const lastIdlePush = new Map<string, number>()
    const busySessions = new Set<string>()

    function cacheSession(info: unknown): void {
      if (typeof info !== "object" || info === null) return
      const s = info as Record<string, unknown>
      if (typeof s.id !== "string") return
      const time = (s.time as Record<string, unknown> | undefined) ?? {}
      sessions.set(s.id, {
        id: s.id,
        title: typeof s.title === "string" ? s.title : "(untitled)",
        directory: typeof s.directory === "string" ? s.directory : directory,
        parentID: typeof s.parentID === "string" ? s.parentID : undefined,
        updated: typeof time.updated === "number" ? time.updated : Date.now(),
      })
    }
    async function refreshSessions(): Promise<Array<SessLite & { busy: boolean }>> {
      try {
        const result = await client.session.list()
        const data = result.data
        if (Array.isArray(data)) for (const s of data) cacheSession(s)
      } catch (e) {
        log("session list failed: " + String(e))
      }
      return [...sessions.values()]
        .sort((a, b) => b.updated - a.updated)
        .map((s) => ({ ...s, busy: busySessions.has(s.id) }))
    }

    function broadcast(ev: BusEvent): void {
      if (sseClients.size === 0) return
      const payload = "data: " + JSON.stringify(ev) + "\n\n"
      for (const res of sseClients) {
        try {
          res.write(payload)
        } catch {
          sseClients.delete(res)
        }
      }
    }

    async function pushAll(title: string, body: string, tag: string): Promise<void> {
      if (!webpush || state.subscriptions.length === 0) return
      const payload = JSON.stringify({ title, body, tag })
      const dead: string[] = []
      await Promise.all(
        state.subscriptions.map(async (sub) => {
          try {
            await webpush!.sendNotification(
              { endpoint: sub.endpoint, keys: sub.keys },
              payload,
            )
          } catch (err: unknown) {
            const code = (err as { statusCode?: number }).statusCode
            if (code === 404 || code === 410) dead.push(sub.endpoint)
          }
        }),
      )
      if (dead.length) {
        state.subscriptions = state.subscriptions.filter((s) => !dead.includes(s.endpoint))
        saveState(state)
      }
    }

    // ---------- HTTP server ----------
    let port = 0
    let tunnelURL: string | null = null
    let tunnelProc: ChildProcess | null = null

    function authorized(url: URL, req: IncomingMessage): boolean {
      const qk = url.searchParams.get("key")
      if (qk && safeEqualToken(qk, state.token)) return true
      const h = req.headers.authorization
      if (h && h.startsWith("Bearer ") && safeEqualToken(h.slice(7), state.token)) return true
      return false
    }

    const server = createServer((req, res) => {
      void handle(req, res).catch((e) => {
        log("handler error: " + String(e))
        try {
          sendJSON(res, 500, { error: "internal error" })
        } catch {
          /* ignore */
        }
      })
    })

    async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
      const url = new URL(req.url ?? "/", "http://localhost")
      const p = url.pathname
      if (req.method === "OPTIONS") {
        res.writeHead(204, {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        })
        res.end()
        return
      }
      // public shell assets (no secrets inside)
      if (p === "/" && req.method === "GET") return sendText(res, 200, "text/html; charset=utf-8", PWA_HTML)
      if (p === "/version") return sendJSON(res, 200, { uiVersion: UI_VERSION })
      if (p === "/sw.js") return sendText(res, 200, "application/javascript", SW_JS)
      if (p === "/manifest.webmanifest") return sendText(res, 200, "application/manifest+json", MANIFEST)
      if (p === "/icon.svg") return sendText(res, 200, "image/svg+xml", ICON_SVG)
      if (p === "/icon.png") {
        res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" })
        res.end(Buffer.from(ICON_PNG_B64, "base64"))
        return
      }
      if (p === "/vendor/qrcode.js") {
        try {
          // resolve relative to this package so it works both as an npm plugin and as a file copy
          const vendorPath = createRequire(import.meta.url).resolve("qrcode-generator")
          return sendText(res, 200, "application/javascript", readFileSync(vendorPath, "utf8"))
        } catch {
          return sendText(res, 404, "text/plain", "qrcode lib not installed")
        }
      }
      // everything else is token-gated
      if (!authorized(url, req)) return sendJSON(res, 401, { error: "unauthorized" })

      if (p === "/qr" && req.method === "GET") {
        const connect = (tunnelURL ?? "http://" + lanIP() + ":" + port) + "/?key=" + state.token
        return sendText(res, 200, "text/html; charset=utf-8", qrPage(connect, tunnelURL !== null))
      }
      if (p === "/api/state" && req.method === "GET") {
        const list = await refreshSessions()
        return sendJSON(res, 200, {
          ok: true,
          directory,
          uiVersion: UI_VERSION,
          baseUrl: tunnelURL ?? "http://" + lanIP() + ":" + port,
          lanUrl: "http://" + lanIP() + ":" + port,
          tunnelUrl: tunnelURL,
          https: tunnelURL !== null,
          pushEnabled: webpush !== null,
          sessions: list,
        })
      }
      if (p === "/api/sessions" && req.method === "GET") {
        return sendJSON(res, 200, await refreshSessions())
      }
      const msgMatch = p.match(/^\/api\/session\/([^/]+)\/messages$/)
      if (msgMatch && req.method === "GET") {
        const id = msgMatch[1]
        const limit = Number(url.searchParams.get("limit") ?? "120")
        const dir = sessions.get(id)?.directory
        const result = await client.session.messages({
          path: { id },
          query: { limit: Number.isFinite(limit) ? limit : 120, directory: dir },
        })
        return sendJSON(res, 200, result.data ?? [])
      }
      const promptMatch = p.match(/^\/api\/session\/([^/]+)\/prompt$/)
      if (promptMatch && req.method === "POST") {
        const id = promptMatch[1]
        const body = JSON.parse((await readBody(req)) || "{}") as { text?: string }
        if (!body.text || typeof body.text !== "string") return sendJSON(res, 400, { error: "text required" })
        const dir = sessions.get(id)?.directory
        await client.session.promptAsync({
          path: { id },
          query: { directory: dir },
          body: { parts: [{ type: "text", text: body.text }] },
        })
        return sendJSON(res, 202, { ok: true })
      }
      const permMatch = p.match(/^\/api\/session\/([^/]+)\/permission\/([^/]+)$/)
      if (permMatch && req.method === "POST") {
        const [, id, pid] = permMatch
        const body = JSON.parse((await readBody(req)) || "{}") as { response?: string }
        const response = body.response
        if (response !== "once" && response !== "always" && response !== "reject")
          return sendJSON(res, 400, { error: "response must be once|always|reject" })
        const dir = sessions.get(id)?.directory
        await client.postSessionIdPermissionsPermissionId({
          path: { id, permissionID: pid },
          query: { directory: dir },
          body: { response },
        })
        pendingPerms.delete(pid)
        return sendJSON(res, 200, { ok: true })
      }
      const abortMatch = p.match(/^\/api\/session\/([^/]+)\/abort$/)
      if (abortMatch && req.method === "POST") {
        const id = abortMatch[1]
        const dir = sessions.get(id)?.directory
        await client.session.abort({ path: { id }, query: { directory: dir } })
        return sendJSON(res, 200, { ok: true })
      }
      if (p === "/api/session/new" && req.method === "POST") {
        const body = JSON.parse((await readBody(req)) || "{}") as { title?: string }
        const result = await client.session.create({ body: { title: body.title } })
        if (result.data) cacheSession(result.data)
        return sendJSON(res, 200, result.data ?? {})
      }
      if (p === "/api/permissions" && req.method === "GET") {
        return sendJSON(res, 200, [...pendingPerms.values()])
      }
      if (p === "/api/events" && req.method === "GET") {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          "Access-Control-Allow-Origin": "*",
        })
        res.write(": connected\n\n")
        sseClients.add(res)
        req.on("close", () => sseClients.delete(res))
        return
      }
      if (p === "/api/push/vapid" && req.method === "GET") {
        return sendJSON(res, 200, { publicKey: state.vapidPublicKey ?? null })
      }
      if (p === "/api/push/subscribe" && req.method === "POST") {
        const body = JSON.parse((await readBody(req)) || "{}") as PushSub
        if (!body.endpoint || !body.keys) return sendJSON(res, 400, { error: "invalid subscription" })
        state.subscriptions = state.subscriptions.filter((s) => s.endpoint !== body.endpoint)
        state.subscriptions.push({ endpoint: body.endpoint, keys: body.keys })
        saveState(state)
        return sendJSON(res, 200, { ok: true })
      }
      if (p === "/api/push/unsubscribe" && req.method === "POST") {
        const body = JSON.parse((await readBody(req)) || "{}") as { endpoint?: string }
        state.subscriptions = state.subscriptions.filter((s) => s.endpoint !== body.endpoint)
        saveState(state)
        return sendJSON(res, 200, { ok: true })
      }
      if (p === "/api/revoke" && req.method === "POST") {
        // rotate the access token: every previously paired device is locked out immediately
        state.token = randomBytes(24).toString("hex")
        state.subscriptions = []
        saveState(state)
        sendJSON(res, 200, { ok: true })
        for (const c of sseClients) {
          try {
            c.end()
          } catch {
            /* already closed */
          }
        }
        sseClients.clear()
        announce()
        log("access revoked: token rotated, all devices disconnected")
        return
      }
      sendJSON(res, 404, { error: "not found" })
    }

    // bind to first free port
    const bound = await new Promise<number>((resolve) => {
      let idx = 0
      const tryNext = (): void => {
        if (idx >= PORT_RANGE.length) return resolve(0)
        const candidate = PORT_RANGE[idx++]
        server.once("error", (err: NodeJS.ErrnoException) => {
          if (err.code === "EADDRINUSE") tryNext()
          else {
            log("server error: " + String(err))
            resolve(0)
          }
        })
        server.listen(candidate, "0.0.0.0", () => {
          server.removeAllListeners("error")
          resolve(candidate)
        })
      }
      tryNext()
    })
    if (bound === 0) {
      log("no free port in range; remote-control disabled for this instance")
      return {}
    }
    port = bound
    log("remote-control listening on port " + port + " (project: " + directory + ")")

    // optional cloudflared tunnel (enables HTTPS -> web push + access from anywhere)
    function startTunnel(): void {
      try {
        const proc = spawn("cloudflared", ["tunnel", "--url", "http://localhost:" + port], { stdio: ["ignore", "pipe", "pipe"] })
        tunnelProc = proc
        let buf = ""
        const timer = setTimeout(() => {
          if (!tunnelURL) log("cloudflared: no URL after 20s, continuing with LAN only")
        }, 20000)
        const scan = (chunk: Buffer): void => {
          buf += chunk.toString()
          const m = buf.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/)
          if (m && !tunnelURL) {
            tunnelURL = m[0]
            clearTimeout(timer)
            log("tunnel ready: " + tunnelURL)
            announce()
          }
        }
        proc.stderr?.on("data", scan)
        proc.stdout?.on("data", scan)
        proc.on("error", () => {
          /* cloudflared not installed */
        })
        const kill = (): void => {
          try {
            proc.kill()
          } catch {
            /* ignore */
          }
        }
        process.on("exit", kill)
        process.on("SIGINT", kill)
        process.on("SIGTERM", kill)
      } catch {
        /* no cloudflared, fine */
      }
    }
    startTunnel()

    // announce URL: toast + files
    function connectURL(): string {
      return (tunnelURL ?? "http://" + lanIP() + ":" + port) + "/?key=" + state.token
    }
    function announce(): void {
      const url = connectURL()
      const localQR = "http://127.0.0.1:" + port + "/qr?key=" + state.token
      let content = "opencode remote-control\n=======================\n\nConnect URL (open on phone):\n" + url + "\n\nQR page (open on THIS Mac, then scan with phone):\n" + localQR + "\n"
      if (qrlib) {
        try {
          const qr = qrlib(0, "M")
          qr.addData(url)
          qr.make()
          content += "\n" + qr.createASCII(1, 1) + "\n"
        } catch {
          /* ascii qr optional */
        }
      }
      try {
        writeFileSync(join(RC_DIR, "last-url.txt"), content)
        writeFileSync(
          join(RC_DIR, "qr.sh"),
          "#!/bin/bash\n# opens the opencode remote-control QR page in your browser - scan it with your phone\nopen \"" + localQR + "\"\n",
        )
        chmodSync(join(RC_DIR, "qr.sh"), 0o755)
      } catch (e) {
        log("announce write failed: " + String(e))
      }
      setTimeout(() => {
        void client.tui
          .showToast({
            body: {
              title: "Remote control ready",
              message: "Phone: " + url,
              variant: "info",
              duration: 10000,
            },
          })
          .catch(() => {
            /* headless serve mode has no TUI */
          })
      }, 3000)
    }
    announce()
    void refreshSessions()

    // SSE heartbeat
    const hb = setInterval(() => {
      for (const res of sseClients) {
        try {
          res.write(": hb\n\n")
        } catch {
          sseClients.delete(res)
        }
      }
    }, 25000)
    if (typeof hb.unref === "function") hb.unref()

    // ---------- hooks ----------
    return {
      event: async ({ event }) => {
        try {
          const ev = event as unknown as BusEvent
          const props = ev.properties ?? {}
          if (ev.type === "session.updated" || ev.type === "session.created") {
            cacheSession((props as { info?: unknown }).info)
          }
          if (ev.type === "session.status") {
            const sid = (props as { sessionID?: string }).sessionID
            const status = (props as { status?: { type?: string } }).status
            if (sid && status) {
              if (status.type === "idle") busySessions.delete(sid)
              else busySessions.add(sid)
            }
          }
          if (ev.type === "permission.updated") {
            const perm = props as unknown as PendingPermission & { time?: { created?: number } }
            if (typeof perm.id === "string" && typeof perm.sessionID === "string") {
              pendingPerms.set(perm.id, {
                id: perm.id,
                sessionID: perm.sessionID,
                title: typeof perm.title === "string" ? perm.title : "Permission request",
                type: typeof perm.type === "string" ? perm.type : "unknown",
                created: perm.time?.created ?? Date.now(),
                metadata: perm.metadata,
              })
              const sess = sessions.get(perm.sessionID)
              void pushAll(
                "🔐 Approval needed",
                (perm.title || perm.type) + (sess ? " — " + sess.title : ""),
                "perm-" + perm.id,
              )
            }
          }
          if (ev.type === "permission.replied") {
            const pid = (props as { permissionID?: string }).permissionID
            if (pid) pendingPerms.delete(pid)
          }
          if (ev.type === "session.idle") {
            const sid = (props as { sessionID?: string }).sessionID
            if (sid) {
              busySessions.delete(sid)
              const sess = sessions.get(sid)
              const isSub = sess?.parentID !== undefined
              const last = lastIdlePush.get(sid) ?? 0
              if (!isSub && Date.now() - last > 15000) {
                lastIdlePush.set(sid, Date.now())
                void pushAll("✅ opencode finished", sess?.title ?? "Session is idle — answer ready", "idle-" + sid)
              }
            }
          }
          if (ev.type === "session.error") {
            const sid = (props as { sessionID?: string }).sessionID
            if (sid) busySessions.delete(sid)
            const sess = sid ? sessions.get(sid) : undefined
            void pushAll("❌ opencode error", sess?.title ?? "A session hit an error", "err-" + (sid ?? "x"))
          }
          broadcast(ev)
        } catch (e) {
          log("event hook error: " + String(e))
        }
      },
    }
  } catch (e) {
    log("plugin init failed: " + String(e))
    return {}
  }
}

interface QRCodeObj {
  addData(data: string): void
  make(): void
  createASCII(cellSize?: number, margin?: number): string
}

// ============================================================
// embedded web assets
// ============================================================
function qrPage(connectURL: string, viaTunnel: boolean): string {
  const safe = connectURL.replace(/"/g, "&quot;")
  return (
    "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>" +
    "<title>opencode remote — scan me</title>" +
    "<style>body{background:#0d1117;color:#e6edf3;font-family:-apple-system,system-ui,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;text-align:center}" +
    "#qr{background:#fff;padding:20px;border-radius:16px;margin:24px 0}#qr svg{display:block}" +
    "h1{font-size:22px;font-weight:600}p{color:#8b949e;max-width:420px;line-height:1.5}code{background:#161b22;padding:2px 8px;border-radius:6px;font-size:12px;word-break:break-all}</style>" +
    "</head><body><h1>📱 Scan with your phone</h1><div id='qr'>loading…</div>" +
    "<p>" + (viaTunnel ? "Works from anywhere — any internet, push notifications enabled. Scan again after restarting opencode (the link rotates)." : "Tunnel still starting (or cloudflared missing) — this link works on the same WiFi as this Mac. Refresh this page in a few seconds for the anywhere link.") + "</p>" +
    "<p><code>" + safe + "</code></p>" +
    "<script src='/vendor/qrcode.js'></script>" +
    "<script>try{var qr=qrcode(0,'M');qr.addData(\"" + safe + "\");qr.make();document.getElementById('qr').innerHTML=qr.createSvgTag({cellSize:7,margin:0});}catch(e){document.getElementById('qr').textContent='QR lib missing — type the URL below manually';}</script>" +
    "</body></html>"
  )
}

const ICON_SVG =
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#6d9fff'/><stop offset='.55' stop-color='#5b8cff'/><stop offset='1' stop-color='#7c5cff'/></linearGradient><linearGradient id='sh' x1='0' y1='0' x2='0' y2='1'><stop offset='0' stop-color='#ffffff' stop-opacity='.22'/><stop offset='1' stop-color='#ffffff' stop-opacity='0'/></linearGradient></defs><rect width='100' height='100' rx='23' fill='url(#g)'/><path d='M0 23C0 10.3 10.3 0 23 0h54c12.7 0 23 10.3 23 23v27H0Z' fill='url(#sh)'/><path d='M28 35 L45 50 L28 65' fill='none' stroke='#ffffff' stroke-width='9' stroke-linecap='round' stroke-linejoin='round'/><rect x='51' y='60.5' width='22' height='9' rx='4.5' fill='#ffffff'/><circle cx='76' cy='30' r='7.5' fill='#34d399' stroke='#ffffff' stroke-width='3.5'/></svg>"

const ICON_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAAAAXNSR0IArs4c6QAAAERlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAtKADAAQAAAABAAAAtAAAAABW1ZZ5AABAAElEQVR4Acy9C7Bt+1XWOe/NzQsI5E0SCJGQhBAxqDyE0EAEeQqBUqi2FdoXttKWgtoPqujqoqi2ywd0Q2N3aQtNWxai0IIkQUU6AW0Q5E2MAQIkuUlAyOMmEEhunre/3/cf35hjzr324d6bc+SOOnOO1ze+Mf7/Odfaa6+99j63fd0L77lnk/h827bdJu8e6U36NumVBfHeCTzwIeEsl1aHGD4C/j3ULbfP4QJHbvKlFrBzGBLXYCg48c5xOkuRp9chnSYZTH7BL2pquz92kY1yB9n3S/sPzjOTjw0HDnIv+i9gnTPsDJ44SOX6p+f5+h36q9546nSkRfYavkhy8dHE9iIcyYGofOIGF1yYe96z7Ntl33EgAhsS7CqE45L4IkFYuGyAscROufeo8ZQz/aFewNzMRXVYdHpOjmkDZi2eUVy+GMR0ZImNxyBYEm6HTrm56WwkvHNOKLJMSmf59GO7ZYE8l06+qaktkK+Jh6mYgUV+6uEUdcSDwym7WvU1IxWZcON08gxKnK8NNXMvfa2LKPtXY6zoub8JdBpNuwcxpAiyz+iz0AuYaWTc4aFOzShq0Imh8RXnYt5eeJPL981TQ/WQFU89upvAJd/zBqdQjUXW0HWK4/Da1OrlCLz4OtLLNxxxSSnr3DieVwn6h8o4TgpQ3zJtBd0D3YCjEb5jdPXxBQpAzfMA7CEoIl9zdK/RDDP730NUjctk914XlVRL9oiA15l++IViTj848GuWaO8tNUjmCkf0zBm4luX9Lr7MCB/rOYupwydtPCAlfI9VwR1gepCjOcPGuPcgmzdC8XnSbnYewFONYdy8KgtrFVyTrsFmf5dWvS/KgqyKqsfxhs/csHORDBcXNziScmtOHsqpo12h4MvdCRQ4lMuZm287gOphVYSzbYaqVLeamKwnWHTw1jrNntQivl7trFifKZxNSAxSl5Wf8Mw3D2UC0D8PnJ5l1Ds2sKnxjCHrRgqIr10Z+0sOwOfB46N15IKH4dCk6jMA7sSFynFSau5nlpHoBSpP2I9gsDrcv+yUuBcxAQ4XEwDiwlYrlnPl4A3PKHH/5iSRplWfcrs4yhsiG80pvMGGz34FY7tGZfixD+uvePJdRx+ACIVOnOxypfa8cIGic21tG7hO7dNHTlrYxpFgI7yGnc/YwSQPBtt+EQdDDok/74XDV7Kq6+FrLmoZ547ewWpEkBpL7eht0oll4TQ8PPsJQC3ioaTJs0h86ueQtoMNRn2CAY9MbQ7Faqze3NQ4wBABQhAfOzLzsrteeeDwW5QzNJrgsFmXCwhTpEcooYSTt1Yc7MEmVuDsJaG+KZqI6IJObbsw8HqpOuUancqBtxhbXttwyOF7HXSkZ1YATvMqP+NgmRtJ3K5O0eTCO/c8ePJI96cwc5jEafMTnrzmUPCObDIN2IgDR1X1M0slKc4QhCzCZkFw5QIlBiY1bYev76AjxjidGKNGIWTpvvJsT8CwZ8+Es6nM5q8Sg4xRwCGEU2O/cIFPboD9TEltsAGbgFPJKT77+GIDgzO4CQiFcpewLqk6XwdqT0IabtcXln7eEx6YihF22+QHx4XQyC4ztd5vOb0WpaedwsR6JhMkW7PIJYyA91cF2am5I+88hMzIIuqh29gH6V4jR22aYR9SOF20A+mbGttyXEc8+BHjwZWa4OhlKbwXl5i0wwLnceO6yidmlwRgSfbD2HPPBSniOGtul5/wRXm8QRQkPm84HhC35WZS41ykxEIw15859yn2sdy3mhuHncVXnP6IU/VoBhtep0cdcV+XVXY4+8EgrOuV8VfncMMJGo0hHLSpqdTxK3rVgEN8rSrmYmJwSVAcd+CcJYs5x6dfPGuqStDYtZVsHyNTlQaXGxa4wzphJ2dbvoOVs12YM2egeaaEszlI/nbiIVb/cHsWkYQLCtvEZMAfrMsVcA1xBN+JsolR50IcSdm5ge0Xt1PzUacAdMSjoZhSdItWjvufwQUiHEn/1ONzw+QlDDhiSF+jBtc88g85+eao/oEzHLbDFcTODUqPSNcQqP57cVArdbyh00GYw1BVkwWbs4iNA181eVQSp3lTyuC6+EsEQcl8iUMoPV1XGHA2h7+TFr9ySc/1dt2clZmUmDh6WChIom6i8DpFToZj8KyqNry+imEXfFFWXfYwpeZLTwixU9igbnFInfunnDLb4uk9VcC2vgL4NWpxN8folfbgk0f7xk4S7lHjdYAhRk7J3PzxJzx2cOYaNelNfLRMmbVrZaEjxxt6DJKND5kLqtBKpyaqOjDzEZZ8tLmKA7vumZ06PCQNdurqiZwEXps65Vmk6B33TaWcY2CxA6DeLKMVZKcgoRblksbAnnnsrKmpZHQNdjtlA4x0kQJlX0yL47CWgc1MhPLNVV5WUnPpZq7yTLHPW2N0QsCM75qDs1AJMb/XOsmnLfjcixAfYuf+NQgY1kJN96vcetuunk5IguubkgCv6eoq9evXOZhsf0kR9EzeMCUOF6Cwh34Bo3NXyJx1wbtPcRqKXZzW8vNlHqw3oDR+t6BOTq9XuRY45ITPhvy5mcZWfXCZt2udWDy5ABUy/+0Cur+CicObByi2L7KS1gQkviYUYIvDtWgZF9dTOOM5DfH1M4G4pNM7a0iePomdbeg8h+rRCLO4wN6yU0/ItjDv1kU0lpiCscEgifmBWZzuEX40otp+285FBAsEKQ1zM5NCUrs8nQHtKuUdc2N7OsHJwIWP7kBwQ58vTi+kOM79a5w1Fw2449FTCuT+XTAByz7MdzW9L0Q506RPaceKP/nsh/dBuH7sChAMhu30nA52+pCXj9uQMhzTKf2ATkn/1E1cYuDn/vueIJmG0Qo5jI9Id2qSrayx3b/y3V+FbYNPHrtJcYYIA4z0HQzM69rcwGRIuiG6gFL+cuXXwPWIOjQGIOnYbC57PjDgRA7P+IXv+gXxuakyTOnMaC6djFMOjXhty/RcKSee9ZqjCsgjmSEXMN8X+Mt1vQZ1E+1DalblVT/x8PaMMtJnDS6Ek4sjOGKZlWdO+vkZdNZXE2oOa8t1Ip9aTNlZm22tyXniMr1OjJL0T9zPlOSKMzi5LdNOcPZN/+Raw6kjeTTiGFpHRiN2Fr+GJn4pGXw0RNgmTLB815NIN5m2wQ0s4ZbEpWMeeghIPLmuw1DwgJXvlxkKBu888cJ2/cAUVa+fGg5LEfkCVrD3KU2CvS86/eEsHlS+1Kd/bqTsraHUYsw6XPmHPCTByjwIcQLhQA87N1Egh5c3BO+vMBMSvby+ecu1b1jhev2ZMUBpcrn5SfuzHA6S1AFH1e0BYhRGy3AT+YjxKTzlyCeF3TKbCQCmn12UM6dPShSneRTLAqJdHEzp7lNGqKJpgA0nhrlP2DXEAmX9XUQ9dfSrOvOM/ombG6dymbv1Sq2vKMKwD5ZoCPLaJLGCoPJAdn98B5em1C7BU/+V0bk4C7KuLYUVz5zGVwy7169YMNHO63Rd/3mtwSLE5rtgK7o45v2WuOc7rYkvNn0xKWJea4wCg7HInwMzLAfihjiqA+NcJaGa0liCwuDnIkY7ZZJZubhdT5heKOm8pIk+Vp28Gog5swCH4AGK1uG1nkqdLpzrk6ew1hLO7EMgaHOClVhVjS+wYtHkD/wErhPmqRu+Xw4Iy/KmeLmZkYQDC+E9hacK5vqdqzgqfuY7rCkEwv12/Q2tebJu961erh8zVXgfsgPat1q/Pz6aGeZgXlk1o44cRROTuvBmodG9O9TrMJ7T4E3tFS1cv8ampAiyYGjMR2FxYk5ul1Tu3N81RTDLiVe4IbwUmOumDZjgbNAA6UayAyJWee9NMEWAqvQqTzzBAKSHqaqSwttTDT0aVwZUuegpM0hOsI5XLXZfR5zixcT2/ZNCNOGJWaFF7uSJj1jVhaZLRtyx8l0ie94L5zzvGvVmeiNSXMNlSJ4BYpvQTDoFjynbfJx0iKLzhA4yF69kNi86Q7knhWCKAG2bGAaNysZ338KkngsAtA/6BzPjsi1KhgvtZ8CKUejXu9L9LkpsdI7FtPzY0erPsxJQTrZL9wLIjcUYu+BkXNfrxxXAvmzKwOea+QasNZMklyNY1ytugQsDzVEbaH75eb3P+nM/BNPEi2k/0wgpnTWDj40OX/QqqnnkCOKDOPMEh93fFJJEnFSCIuwUZCFgbGMgGXJ5Xii1SOMI6GBP+l0S2fB7AdhAqrC1YhbFnTJIkerp145yDzn5vnguLM7UEZt2MKVb1RwQY3aJHO9JAWd81qaci+61ANRQ5pLtCx9eOGMXSa+/bpb4lV5KRX2tTKwwWpL1uy389JSudO/zQu/x+DuwIzbgCBdDww9n1jPRxpJLTdZfMbCpR0+bewI5vyJYUZ0rn/UHT37/PDSMkgywnKplKAXYqDTOwASwkbygB3PGEyAGNDp1aG5Ox+mFgQS8vOOZHEf94GeWADQXBgIuUvYMHfokIYJ+FlItfO8hJm2IToFmL4xR3t+YgNfR+DK6pnhcU8HeP4IXZN5MNPf+Cev+xYFKeYVWXvH4ULumgOahrrjIQ+IH5DIdCrF5dJp8VeInKNYBV9bfz7qjJrNTlxvyXq9/TbMeSOozB7m9iWmmw4vi0SSbgRCZBzs456gpkAeX3/iyCVDDYVuKGtehayjSBOEpKJHdrniG8TN07VpmdcGFk/k4SbyBst0Wnf7kZWdWOLHR2XT3KZzClvA4DF4Htk/FvQIrZpzMpNxfvrnTv8o9CzacApjXQNlNULXCIcYs0z0SgwPJWmyLq/uXnV60wUZ7TbLDnT2Dg6BrZDLSlfUDSWHZ6Uk8NnXY5gpn1TnGIEhi067YeslRTgbrnXb11RNDB5uFeW/FY6rwAZNNznnqSgZk1QzAmTM1rcFKwg0BoazXOU4IjQpvdzT2N0nK9QVWDk5LtItOseSilaZFaqedWDFYZRzPL8c0LhooBcPj/ag8yjJ6n9cPxmuSce7vnkWRL+m+kUaszDXYqY9dnZq38h7vgt24JtW6ahGehRmVI4Y/8YmhXVP8php26iG63WxEdKAiFdrTlfRGlc1cHgJdNvXTDqlLdOqcA/L9NLCKcmPBiR0sfXAcKx3sKF8Fggaf3i6HTFJqOV5ABZXonOLYOQBno6OJIcFYc0osdjRx2bhZB4P6QUVQR9aU9StqvDV5/NJZdzQUDcZGHJT2hjjSM9hjnWB0ZLaF2kv7+xRwwQMqzrQgBAdhYuYdWubqoSRrTj7rx5/rT37q7Bt62mCMk/ZvrNAM8TAKZiPax9BByo8aIHZ2rKzGkGsc8cKiwu16fInj0tRkUTNxiDlxzYk5JT1b2bwWJNV9Eq81OamYywXy/PIRbF9UsEWAH3uh1tnzy/Rr7+J2SeqSkz70WOVrRvqBKwwp1o+PFNVyzmcXDQwzUDuKmBFxnPxy3SC45BZwYXw9C2ylExo6HlQImHcrWC1WUGf4kOABzB7JU4edXOL5SmKO4sI2vrRtnfxZjiQCQlM3andngNmAKxjls3igkQxnn6JK2hw8qSHO4RNBAwkMqVhzT0ztsjlUEg2VHyAyXEeikqj0z0VSqPMZA3xw5ijHN57sfm3r4i630TlwlY+R/tDFjjH7pGzWxWYw10OgA4VY65RrA6jXXwAw1CJ5EHU9tYpPTPqEkz3jGzswcJtfdguxkCgI7pKEDx25wkViECSfb8hTt4ZpT8Yg7RWRr8EndOY9VJWnb1OVwRA2dUJzgOVwXHo3cCRKenhpNjALoQZscrZXyHyVbhs/telxsT/AEvcYNhfdF0ixS/1T17oXNUgwK57+CXm+GSRBozrcn5jEcwhLTdYFLOW25eSBSrw3w86OJZU67AgcCJoj/eOTcyxAAlOqj0OXGiiR2S/d1E0lfsrp1V9VKrl/lkOIkHVhGcTdILtBfA6NXfVXcJN3YLpeMQ9WlHLXRcEocX9s9alWfWEcHv0zR/hJpWjaxNxCp/D3OpUzltqRH1Sd91cpwJCVNk8T7FyHi6S84arr9SsABj8SWvupkZNa4nPuzGt84ZIPL7XEWmKb9JQ7DFB9q5AUwvdBWduKHM/pb6x6gGUBiWeWan9Yv3GTjnrKi4caMJ5F2p+HJhjS6gXMkjhONpundWoaW4ZJKy5lmfWx0RzehHqQwNeEISLmBMaQih02kRhHD7Xs9BnVbRquU0rXrsi/0N9Yxc0HgwLuHzYAJRfK11iF8Y1lQtGc1g8/YDgw7RfvYX0keQ8eLbGuWuMI1ryYSO9XyFfYZ5cSl7D+hhQ/8Upjrn0YgcyxFxrW87lmhfYbVvWpQ+flCrD0T3v75WStt7P+ejCxZtJ+DT0nBUwii/fM1Zg4Utdg7ZvBChq4Bixz8biiOOEmKR1+0hVab+TDx1GKHFhihG3K6PoOrmRuEHnNk1rWRl2+yYCLb2KykeF27Tw5sT+T+hkVHnpPUcybrVhzycD2nk28AUoQw0aw65jQRVZQJbKOXmu44FAjah2S0dQX6rIX3BgTBw0cZ5nrTm1mMxaS9JedOSG7slcUjJl8PQlV49m/aI33nEp2/+JBkfP70BghIurXJRSBkngwtA5jCZZ0rPCpIX22G6tc+hFD7Ksgzw4rSmJtRriMB7dSPY/jOgWXeuM4VaLNNgop3xdsPOs5A46jJGbmn3H2bfY/XKQk0IMz6+09Vt77Lw2sX9LM/pVzvugq3Yoc0g8k+koSX95+pr9nqGe9PXO0su7oNaQwg5h1I9FOERsYA8ap+UYspucqp2nEVW1Wph5Ixx+skBIwfU1UDGyMHxUQJSbbz27eNdUdOshXHCx8GSqP8nCjPZlwyc1Hc9LogyjQMRk1kiEz7gAzFMZF5fsZrvo2N8VFgIIXmfP2hYKzuIwBPIrm+tedVfkjbO0bc2i/2E+vv3hm30HdbXxdSAzO3tOKX9ocUpkvX7GaxMZhKVfXLwI4vOT0OenMDp33unjPKjivXw8oNBLuvLRY0XV2jczMkDWqfAXZRJLejArmYvWcZdAQMzdrwR2kPocHKVxuAseacB86faPhjAQe383lmJNVSzzP0MRmHj+SHuSrvAmcq2Bm7joZxMAEl9msiQNG68ha3Wdwkuu+wfvO3C8m4Yj7yUmNe8if2vMkFmB0gEWY/llf1kQ6PNgpx44Ea0oB8iQ268CS95Nd9b7UK5zo3MTRyTHD+cGQXvnqBjYxfzjJTk3vAbMB0SowsStll0O64+Qk7SvJNTJ3gPIZOJimH3k4WgqQtN3hmKf82MyWTWEt9Ce3TsrJz2tm7FygQEynU2sbhROo9wqMDvelWAIUMUaa9SO+IB5i9XfPlVrnKjRXERLyy43COZwGqS2shxj2+QYwXHkgc/3g/FeZalAegL4+Arq/8FnL3Ke0z/opn2tKDXGPXHOjshcdz9zhMEiOpMpspH96knOpDDQHBXe4Ac/TcnKBsfVvFQCU4FvaWO7cINcrHIiblO/Xhaukzz2cJzvWwVFjGY/PUVAb2Ti465r0hmUINsK2MNQjqbPtq+Gwa+cDuvHCOO6Chc2590wB3yDq5zqdcpEZoZtXIbHzfjEXtcYXzoo4QY4CeA2F50PthH2S0Rdf+H5QFAYcfSPcwHkm5c8JINmfhlXtSupcc/gJQzV+UJCknp5S5uACKtZ7J3cKGLAItmuIFX/6LMCOTdz3rpN1Uu360beMFoj3fIcJEs9meZCaJhcGsGuLAOWhhfNemWDFwDKYF1F2bvoqP2z8an7k71gK4IM2vrR9xRzSKTdZtVxxnJK+AeSzPM9nIwCCZUuRip8L12viYhYUTZybh3dWKPT1lu0LWLjZqnnI1c3ShMSqNjhokfjkE0s814/+7ivAvMFNYLBOGSY6ySL1PlcOxYhZk6G1/lwP+rD+fAW1rRi1LXKYn1i010Fs5IxXDGDj5O4vOcgpmcWZ0FV1IiCBA7EeTi6mE4VtW7jw9Q1DLYcSfmaDFLtiwe+FO546YJY25JU9Q2DiZ0b7OnVcBv0QYrG5QC090Iqk1uFyDhdIiWx0Y4lRXlzh95oJp4a8JHV2qiYJc1fsXH8F70CtC9I6DvyFIVbt17UgruBs7xCxAqb/vV4/BJLca55Dp9TzoHA/EtWj98aFawlOuZjgkv4vKRjKm6Q4GOM4mXmBrz0L41p04f3gUEF91XEpKS5iHtmmrx4sLo/kbFA0wwCDK7Fqo8iS7l9+8tHhYD3+UiXtTdJA8697JpaNNB3NIzULvOaEZ5nrq1DZlUZ59nWSU2D3SVIxr6v69OtY+cZVPH0ou7Y+oDGny8vnpsGn3vNjL1PnbXvfh27bUx6/bU941LY98n237aF6H4yvKG97x7a98Te27bVv3LbXvF5AeEzsMtv9ACVEPwK6aL02GpV4ft8MChRPbnDrYMnBJZU50dMm6VYK9n9JEQCFLQrmRiEWey7kjLWfOjkZkni4+5myA/uArg82Q0nbLHyXYZBApOdcwWTPFkjnJDBJDm17cjrASeIBdhPLUJ2aso2VzMy+eWq+0MxZIUgcXl9suKqGGHKi36+Hcl0zQYr7iQLyapD07P+gB23bxzxtHb9LN7PnVcl1crdu7n9/57b98M9t26teV/twmtW1xHIBqn/P0YOcuhAvLCqLdkg5rzMl4UiJeq2fFE6AWYqoiKljA3BzgxqmEwNnA8j5GUB6bljRpEvrK3EamVgae0j6H8Ingi5XfPaHxv6l+OjhnsKYdjaqOscLj430DVN2r19+48XV/etBRJJ86o1lL+sZzfjM0EQ7T0L9oBRXGvZFrw2ZezFtOD7hI7btM37vtj3i4RDcO3nYQ7btY5++jl/8lW37rh/Ztl+5S7OpHM4piXXfrEkgr0F+7p/15Vs+e3QJRxj8aNC88JH7qm9bIZMX0EVV1QTyZ3FPT+PRYWIm55jBZnpEH/KD0/lKEkbMy/CZqfoH65sEnOL+8s1rFWQQBDta7ZARDM7JcSK+BhFt9e/vDyoFPDggtgneQCbG86tP0R+qwPX6ybjBgiSHN+2VXedHv9+2ffFz18uLGb8/Nnv8fT+9bd/7U2u/4WA2JOuZa2HruBZXXjNXnJzLOfEgJ36dBEtetn9SWLYDVGejJlEGM68K08WmTmgkNfiOcSIobVO2N1mhFDV3sOR4lEoIIdFQccPC6TrsSk6Mw4nbEQ6hrjYp4YKtfM6pLd+uTtkbeJiFeL/2x65Ylctb0mukPzwzniJisu0K0zUKm486JR1HF4cV+FXeGLCIcQP8oR+4bX/207ftffR6+WYI719/5u9fD45v+X+37e3vXNfI66gGWUvPknUowBNC8tT0GsfMppGfHLjE0NQT8y/JdhKjSFwod4Q6BwSCDJGLECz52BjGE8PGKYkJFsk3lOZOcKV8JpQaAs1V2OTBdHkbFVQyoXDFh/MsM4ftGjh0uD9aCceTL5K8fkQbC2484yTmHuEQEQ/Y8M15ck2IUZP1pz+xeh7wXs8HPnzgnvqEbfsLn3XzbmbRtjzzg8X92dv2YL0mz3xoLyYLKj3zxgyc39YTLk8UacD64Qq+1x+AtJ+hTSAUAG9adgUgcfywTJu8JF/imRUYPL45scvveGHcovqlv1L7hYSDgMSDi2D2ycKMgadwedCk1vNXnhrixkIsSV0HFfA+KBdsbgzwviELg29+LSY86e8cJ0hKfGNj1xyYXDT/2hIEkrm9KfW6le99op7knINaxejveSE7yePff9u+VM/MD+6vyyfAcN/8rru3X7z7ru3N775b7xzcvj3hwe+3Pe1hj7Y9YFdMnv3/5Kdt29//3iuptRfMSIr5S1hXYglHA+nroSDxYLPX+Bzg1t/lsKcIwaX6nI3rQBlNjC/HdeFBR86ExCuWIQwlNuscrFPFr6RNsDCU8yByqIC2lSh3PcjkG0tcCT+woCA4JG7ycJhvYhTIs4hvRPmuIy4ctvevasKZ+Ozvi0bRSWZ9LyTk0aqBc5Y7pVOejB6klwV/6lO3jW/orpN3C/zCN798e8GbXr695K2/et6S7RG3P2T7pPd/yvbFj3329vSHPeY6mu0jn7Jtn/rsbXvxS/b1j1EXrwZm/TioNLM9mVnYkMYSr3o0++TQV37rPfeYOEUngoTR2fQ8E2Szw8v3Xs5VEReZmJ+tJ69sejrEKQQ1WJWvAcuZMEIuGUFMf5Ohpof1NHifPxeZlJt4SNmj/+S3DdZ3bdVUMCOQnvX2T6dgs4/Zv15/8AUMjrBDOoUjsRlgpLn/YCKf+fu27bM+Ot5V/XNve8P2P772xdsr3/7mq8lThD6f/6hnbn/tic/ZHnb75af7d75r2/76t2/bXb8p8JxbNvW+/iwGv/bSipgkdi6NY8qR9pNI1QSLRsAvAVxkpRzHzkEAGy4Pgo4owfUmyQ3M4bewiClHTWrJgcXPgX/+UpmazCWIhfgVEVG+JIfTWid/qceRmCsE0cRJaghC3jAFnK76BQBUUnzTPc+5CIIYWsSn8pGUWXPlQX/grdyxYK3L+1fc8Od434fpGfOjzhW7//2/8crtS1/x3ffqZqYK3n/2pp/b/qtXPH9707vethMNi5c1n/dxay7CvtFU2G9rjhuA9XHM60+PrH/Qrq25sAfeo+I/XvCqhtA3iAw3Y4DEatMyABp8BovuOHUUS6Ip8BAEZc8ZzUU4Bv2CR8NTvuNwFIEVgOTJSdIr2vkaxs/Y4AtX5WuDiVf/A48cZqAfNKkNhj7sn+cbdu9peruQqsVnrVyvT3aewYjRCM3rbnMTku2Ljy4/fdGf/Lu37SGXn0j10uLXtq96zYu2t9/zblrfJ/nZu9+w/Tev/lfbO99zufb3PXXbHqO3B5GsGz2vkZM1tzdRAT8BCZc1BBPfWnnw2Ois2399lALiAaTw/AghTiwXqgej9r6Imy2utbrV30OJx7xojDiD34so3zXiy8sIb1zVUD/Laes1gadeSW5WxP5JG+vsOgXjG0uh5E1BEr6AKr8q1xlc+hMxtGpyoeEGMyX7TayvzQTI9rqHThqqj3tGvKO++z3v2r7y1d+3vdObd8zdW48HxN993Y9fhPN23h/4cKVYEwid0L1HDpLYY+RYv1NsEAc3NzdwpPhIgWPPsn7/5SQSke6hIHE3l5FNdsMCO4+NMQRM6vxoK6DjDCds2/J9g4Rj1BIPDnrsYLFZDT4z5yds1sVJbxbqmtTLpzS8xjiwYiS7LzgdPtXG4PumlBaVU8bLRvxsjubQyQcJ1cfHtRi0sNlf2oCDwHoh1yJXuPuHO7hwUAIF8uTHrc9kLO94/kdveMn2+ne99Ri8H94/fuNLt199By+Wr8qzf5dmYaMkvdfYHBmytK+jgSuPGfHaXLQi1GavXGdHL2nohY0YX+S+AIpB5AunuPPBVYGHKjLsNCKNZJNDu6Ik9huCGD24MXJzmJdE5ETglh6s5io7j1TySDbiVO7+xDhq/F4fdUhm8LrEb60Cx6vYF6uadXyVr3PI8XqolcpaaWwbrT7Zs8YDp9+QUBEPPvMBS9unP2kUDfMegb/jrpeNyP0336GXK8/Xa+pL8iS9GeIf4DCnAPPw3imeudF59cL3McES7/Vjl6TebmH8Wp17IeIvwYMAsmxOuFpXR8OxS+re6pvUeZ180YTLAsJLWdvJKxac68sHG99FBBAISnVevjcj5CSGjVllrRXaBXyJOXVyuTR+ar1QcAatnu4LrjYX7aNi5F1PjSS8GNzUXns0NTrYP3qgbS937WvZ1AMjD+cT9am5S/Kyt71+e8NNeHYO979+y50xD5oH2xMfXevRTFlH1o9GmJXBwc99yhMUuGC9QGpctOooR3xDc0G6AFsJ9xkk3ZAqksIF6EYuqDql0qsNBfKeLXXuJ9zBLh/VdXbq1KTy6ZeeZY+QC8aIF18rk0cON4hIejblvDZpt67++SYxOI/h0xoJGEeFrH2hFEOIzxvSPAr6AqWoermgTudQoI1RwPPCVT0e84jOHoyXvk0fk7uJ8vK737jxmvySPEY/0MnNx1zcB9lX41kIB1I6a7VWzHULsc6KwUE8a0b7NfR5I9PMBapAz9i6QsV+Is1bXuuq0U0HD5K+e1bIA5KTYPcDRKZ7pWfpzNAaXB1SLkcjmRVArw0eJ3csfRkrm+28hwG448BwA8LrZUhTk28oWQBx1weLTwAcdZVEOUx8YmQbM+LBBgcPdjcaAPdSSuWH9V/3g5Q3vPO9f+3MKFOuewvvYQ8eM1UBc1q8oLUkm6xfBnbvmZzsv3O+CAKAk501o/1mDsUriiHTiGWHfHl1Jo+4UHhpQvRJKSlfdHIKOl44cogvghL2wcjABhvuYAmdhXq4eW+T9z3nh2J6M7J4+EWQGrhiu4eTowPcOsiRQowvjb0IyezcxExFX3398wO5CRbQD3qZTSHDNcQITgkogOQUTyolWTN7Yjt9U/M7qBnF3x+wJxlY+jyi95hg5abP+JVaiy+e8KHvmN+EkE8DYxNAc9QFYsMCTEoRY3jWclMlyCHG6EQ895cTBtryqR8QimdIEuFbxsJ/gH6b4hP1lhDfRT9WX9K4qfklz1/Wb1T81CvXh8/fnq+A1SfzcLEJIV7/Mj1n4sGSws7Gdu3kDN8sonAutnJZ17kPabj7Bw/ysaHgdSF1YPwgs7HWwPvR4CK+NnGU48P4l+SxD36fS+H3KvaoOy5/qPrut+/7nP3OyN7X6oqd9bNYr1/aWGkENffQ9QCcmM/QoCUGV7EDucuqKBvWzzwTm3oXrhNpLgLlvhmKxxdPV8oxrpiEFIN5SGwJtr+0Vx2x5zxTP4X6GP16kL6UTeHzCh+it6k4nvuR2/aP/s22/dwvrxsC3Fx8+nu91d+9wenwLFWDw7qNrXywGcs1crweYRBq7JOUhBedWcLpHhU/5AQ2RzUqKpM1XweFHQ8i+r9BvzbFJ+zO8pEPf/w59F75z9BnO677MTgzIF5rrWOuKZs999iwWpf3o+qJc/RmxhYW+PrBCk4d5BGSh0MOQxBDW8rH9VHx2OFEH2oAaKrEeHBwcDHAQkaOozkqx29XfOEnXL2ZPc84fYCegP78Z27bf6bfyEj/5qLHpf7VL/2NZ5zMgq1Do1hLrRnxC+PdFrdxnMjVgeEQp8KQtyQnZ15Y58C6cEHnOXE0B7UcCD6/SXJJnvXwx22PvePmPUt/yiOecqmNZ/iPb1BKs3DkK4xHJEZYOseK7Nd+bdjY5+CjU0uh7PXcxCYQkNCDCxbpb3wIAIJgqcOFJeaLlKSwmFXS9oHbRcIVFoqUY1sgKHnWk/UBG33I5t4KX7K+6Dl6Nv/YVeEbpYpNW/2zeGIzFPvcz6+BlfRXKSXtA4KgHni4TQYWMuWtndzrSTkuIw9iIL7INjhJPPQyOefZ2DhIKpYe6F/Qr0hdktu0GV/06GddSt3n2ENue9D2PH1Y6ZL8il4C/pZecjCe919GlpE5XQdAh/cUDL4EbHCum3HtdceoEfZ2znlmNJaTDisH9jxBNpxCp2Jzl1ZOlm90X5jCZSDfzML5BoYgdtWbtOJtA1OMnl/wB3S6H/Jp+ijjf/lcLZaHL/wigxPT6y87czpHTIfXWjYFrAuxUpJ8Yr6ZXRDA0s1T6zS/bDi6V9lSe0yA2Z/rRK8ceYCaX0D0rMd+1a9t25sv/xBv++P6GOjjbsKz9B97zEduT3hIfWjDE+ynn/4l2axDx6W1gszc3pCxDt9IALRu19f+gePGz96Yv3huT5H3wicYJLEhicAwxITxhU8a7UOx0LgpzjwAFX/C0LWtfAZ/xgdt2+P0zd/9lY/+sG37Mv2mht9Cqh4M6Zuh/Hw1svYC1s1zsSdDSkrtF2WFO+eLGBz9sEu7f+HNQ0/JjfoXZN0cC25ObvLJbT7lifPb2ZeE17x/40M+fXswnxe4n/Ls9/nA7S88Xt/QXBAegP9OP4zsGzlDSecmnjrpUPGAZX6vGZ3FBzB0eA4/+gbvBMw6AgoRA4JBk7fSKReIsjx7WAMjiObQyVgcN1vxzHnu7z6C0ufDLnxjo/B9kqc/cdu+/PO27QP0zbjHYh7IJfSe/XsfkpTO5mYualPf+6UYea91cNunaQ546Y8vyR6k76xP7dR+dh71i0Xnwc+8EH//S7ftHXnHp4HL4Ib860/+tO2hetlwX+UjHvbY7Ws/5DO2B99+ufYnXq6/5fHr+9rMXzP7nqpZvfc6eQ/Ys8Kwj8SAsRbvd9XA5etQWO+bYn5oGqOTucTgmw4mbAopkkasK74i60wc0iprTTbNwpGYa8gXxn3griP9AfBbyjdDnqQfw/61z9+2J+lHwp6LXuI/35zdi+Fqkx3Dp6YBV408AfimUzrrd5Fq14KP+kr/NIg+txlxKA9SgczxG/oZCr+RfZ38wff/0O2bnvr524c+9JHXQQ5x6L9Ar5n//lOft133Vh0f8H/BDx/KvG5qPR7zj8NPDFlT4kC09+xfavLShdrE0gXc+rQdBAh6HCZTqElIKx+ieaEcUx5pihhKTiwETnEq/CLduQFQU5AbfrlZLPf+zF8E+go9Uz+jPrhDDx5EB1HQz3DkdMRGGypNHMmcue/BYKO97lo/+AOWQOVy88NtHPXThosYp6HD5xgFEp655kHsX/74eo8e+5I88+GP3b7taV+4/Q8f9MnbR73PE3I5DlB+BetzHvn07Vuf9ke3rxLuodf8tgpFz/+32/Z6PTtnLd4Hxb0n0vZZUy3YqtZmlUJhz7n4BReironWfdtf+ZZqpSzkvnldIVuaAfK9lCuvOUFeZVc0JXQhj4BFDr6CkwMnHwVljj+sXx/iLbubKfwg5lv/9bb92C+u+bo/hmT29/w1cO3YYQHJNwf1OhoLYUmw8dHEZi0x10crmWfc5qx5KDxzNhdGCX/e6yu/cNsefoPfKwz2/v6SLPUvecW2/d3nFxNzyzzMx42X2YExow4whx+s6MbjgUnMGKnmIjTwsW/7Cm5oCEcDkgg3Mjc0zQenc5zAkTOmoytuVzljcIograrFqqogXME7XyDUM/VN4V/87AW/2efn/+j6kuz+kKshPf2TKjZfG+Hxa570v3b9AVzQUNRWrCbtVD8BRmhh4DkEj8ThTJS5rhM+Tsr3EffmN7+v47hR/BV6m/Dr/+l6zc7IbKR12Sgv5UI8N/MZ74tBITLr5DZXFR3+83p/OajNQOlaugLNL9mgwVjLBuNfwS8b35vZE6k8NskhDrtAQRzZeb1kjomX/fP6iV9+4jRobor5vI/btj/2SYsqN4NHUl/f5Fow60aSRxPKgxk7R5YM/jqZ64/t/VcveFquIev+wgNxb52I954XibGV+/nXbtv/+t16b/ju7nDTjJe9atu+QTczr5/5Ss9cnk02A3op2JK2icsxjhtLfuY1sPCpcZ0T68Q94/WC0+H3oW0XKbBwOD4cGq3OAzRM48XjgYgr0Hb5UuY37ZyubJR5AErSE/3/nL/JWJCbcv4k/YyBnyzyu3fn/tkwz5KZpJk1S7D2omrmkAztzZefB+6Zl8Ydy8VFS1Lj/YQTKbzngrfifJkOLjHDC88PW/6nf7Jtr/hVs7zXJ/r983+3bX/nn9W7KTUH89Hfa2Lc2JVP3Bt+moIHROLZW/bAkhxaScexlX/Qx3/+V3+1GxGQlFoXal4t2W5CTKDgrhTRFEzhWq+y3RWBIUWEjeCmfD77keObDGL5Zo7YzZQP1Df5/PWfn3nV/jaXx9NAbH5mQ/tGqaGxiR2+ZJ7wnjN4O+sUzoRy0emXrTRm1GKmP7af2aU9I2Ck8Mup8+B4q35694N6j/gt+qVt/uLo+XMxh7obOD//Gr1efsG2/Xi9183NxRy08lqGNk3mO+keV3HsWZ+bDd7YrSEtLvf98m9WWwG9QUWUjQTY3yhWLvVwTzsb7BhDCcBG+3V4AYnRux8Yg+DQv+oXWCCKhvDNIS8TbpXwwPnGf74eQJd6eA2VYG6vq2ac9iFXReybTfaiaqByrDC5Kco9L3/dKEXUmDLCb07FmCc2OvNFE3uI3kb+eP3kmg99fZjeq08NuUvyNj0YflrfSP9/en/7l/RSMD3RtuumZn35PgwebI+ZuXDKzl64nrgk9wmaUPOnpvqQdC8BbuOGBhxJIb5twDAhBQzGhcmNvLF1CjZp4F1XfGd8Fu5anQxj2LLh4M+5fvEn60vM5ff0J+X9sn9Tz1z/+7+ov3/sAS7QEP/t1i9MbhDWPW+kM6PbgNEGXLkogL15e0/f+IV1ygRH1vQkSjoURtFLAWMcWH/w/On6Bpxf3XqU3vvnFwTerW+guIlf9+b1x87v1EsVnqwghK+FWCQ2mNHUZuqCUQ3xeX1NU7jA3ItY8TF3vip6ceT+0jcdts48WWTvgKLZGKNFWJxrl1y1TDcFXzGUsQS6aLcnLv0aTzGigPvLDB7Mh2vj/9yn37u3oaC5r8JP1775+/QS5E5VVuPsQ3NlIAX4yjYfjNgdE25+tWNNXMDk4fNXNNYqe66XtSJuBY/svkbOHE/BE828aNcRm/ByqOEAx00CKLWxiWdGIInbxtVieDC6geo9I7HiK+V8aoyVw15kM3xjVz35rNX1+IK6Xrb+LVsah/Y7AEfCYBZVsSiTorAl3bD8Fd2JCZ+bOhB8eKswWC9cMfepoEt0wkWCBcM7H//Ld+vDN7+1cjf7zDeIf/6ztu1T9IdaIocZFWQ+HxqM2WzrFJuAn80qQN4iAzs423LAZp+dFIYch0WYvsAUXxBzKJ667l8xlyiZcjRHeuSbSoK+FwrLXK6RbgxFdXhvuHcGTl77rh85cyntmxmOGmL2cXlqCmJY4Zujcv48NDkfnLCFgtQHvo7c485zkhR8OTp74yrRmxpQ8TE0m5FiNgwIh+NlO06u6sxXNjHzSP+yPu/7t77z+s/9CvleCc9K/4Xe0uOTfpkl/RmjRU6vX8FeS82aWvDTnjjs+YDBz7qjD7U1QGLR9MgsmdE5EhLb3AlKYiOpJewHTGLoOmxUHNyUWU/c/avQrehVBcZiEyuMXdm+uVdq9a2896lsasyp/TEH+1SHn6FNxkmoblATlyJrMadO6N5k2WnimHw3BFSc5sVW43B6SAOrb+VNXqBgxWRJ/7XaVfemt27b39ZbRi/XM/atks/6/euPhPMR1OyRH3S1F3P9zMBNkfUFl73IjM7LodacsonFBndeP7HOjzriCPuDUAcXevKn1nmBw0/dxGJzcyUvtwC21vYrTx1HJA8kcynofShc+MFigw0OjtjJQ0xs+ti9HnjBCAQO7ZdLuQkNVBBybO2HJXn8xgDCF77ziVGrw1gw2AaXJoavWv1zHtfB6r8AjnY+HBTBaSmb3537hhfqx9i/UPFboD5O34jyGRB+dNz96VOzEMt6ksdvUT5jE/OFqPmxr5NLvOGfNZdwM2+7ZmQQt6Q/Nz6DjcP8+Ah5Lr4OsMYRgwNM2dakB2Ziw+++qRWeOnL0zMH9g6AckyY24+RZhO81meD88VEnXGmrWIxdBJ5g+YVYijh1UYXzTmGPfGPAqiaL9jDxKxeaWeNYeoHHVtAXgzod79LG/F8vuvEny+B8b4RvRP/7P7reAfD6iszjZHBp36DMR2JiZBPqizB8YP2OEo5k1qcf9aaF36jCVf/kSOUGIOWbjyAAbkJipYnRqyia2NeJmpLmcRMFS885jVGKPWjO4CmRHXx0eLq2+l2Mw8WDADDz49fRH/B3gAEE6DyGJAVZXDRkHrgKwDlHsxzFAamHL93PSPL9WQl6u5tKCzO//CYWDhbjWQtLsdenvt+pnyh+279ZPEV5UxUfQf1K3dR8BDVzZX3xo1lTH8yKr5PXj4+tGAc59tC1stFJTj5FLdT6wINA4hrpjjuq+CkHHqx5weuAIn1k9my2ywfnHgKnP/n0zzUJd3LU9X2Dgzi4zJwbh8HQ0r7/ZNMvNd6/iuX+ZP7DXx9lCIJTzKsTGkEbc4plcX6GAZAjReiIcvAwL0JfPhNCEB7zkyiDPGmkn8ESCxc+R9X8wH/Ytr/3L/ef+K3qm3fmPVqeqfnJIrNlRuxrJQsb6wKbemxfg+AISPzAXua6qCfb654XvPJR3lOa6IA6eLfJwNJ5zQ0ODGLs8M1R800MtVOAhB9cfN98lUs8PbwRYAFXf8zsrfnkW5hJRqCeRYH1eWiGIQtoHsRrUD/y5OJz07gEmzJOpRnYWOVYpIdRbOr0sXbhGgxOBM2RWTK128A/8jLtgyE+F/iTr9y2r9Pbevx491YIr6V5Tf3xz1gXgXndXxo7a7atBUUzaG4AYhxIYt63gc8FDq5rqi4Ld559KM5ch+ZWHG5mpCbPmNHZO/MVB1CLfNdU3DXYJHVyLRcNlzjz1xrI05c4e9J+Yak51BeWes9LDbE6qMe2xk69DH84Sb6DZ81G5hmPXEAhI59HXFizqcCdxxjiwYcfk6HgaC3D/R0Iaml6wNMi3zMpyAZEqH/lr23b39Tbeq/79URvrr5DP6n80s/Yts/56MXr9VeLw4yK4R/W5MDVOiIsO9jJ6VztSSljs+5ocNR7BgGty2++8skRc3yQOq79zJf0cHJzkWt+Eqe6xmJIwCPp5fry8yTo5On6uahOqen5sy7V+PoL54+PDg6XZmHMGNubi2/E0tRxgOHGNx4tI3EekeEn72et1ChgLAkd9EgDTLDuKwJDdPIjvHLEzIeBoNNfNovkAv+qfmT7N/SxRm7uWyV/5BO27Uueu9izJuuagQyzcBD3gU2MuSVea2z5YBNLDTGk/eJa0XWGM4f7pUba9bM/Nnlp9nxt9FKLbZ1zHZxXKLzpwzzkel3FO/PkDv0L7/WrufvTTvFw+WbH57oS5oTm0Cl+ivuXZAF4XYCq2PsgG+0bJxhpSwiZpGw3qbRVcjOGXbz0RdxDp/TJoMmbf0G9GJuzvwJzgdW2b4hf18sO3qv+mVcWyS1Qz/092/aX/vD6CCr9EW4EhHXEjibGzJnVNwnBxJXIPqzohTP16WHC5VeocwxAzIdOzhc+rN4/X3TllUtv5vKNKKBn7IKav/iMp055jrO49wi6XwF948t2Hw9XM5YNYeYxRepKJ+8frCQG0C8xEpAOCSFs+G0Drmb203jkU+MHiBwvQDhr+aNk8RJIHh5tZLC+0U1YMeVD0LzEJFyTui5+gPiCq5Y/5sin6H5AnxK7VfJ7n7q+WXy/h60OzJb+2Ei0l1ubUMrY5HMT4edIPf7hRjazTrV/cblY5qY3B6p0ehLD9sGp8n2hC9g9kx/xhKLnAwJ+avNgcH/5Ve5+tnXRWFM/q8v3HghLjHmojX1lTuX6m8I08Z2gRITBkG6OQ0wNQmxNQwk8YDnM6SAnCXV1eLDYxeUexXNsWJwZwuSiGj0zt/szgw73L+1SbNX8w+/ftn/6bz3RLTnxn0/+t39k/Q0QGly6MX1xazZsDi5msOf1w5MbGBsJ1nvJXtT6eo8V630mrbxz1S859sRH1TdO8HCxf9nDcFDjfZben0FW7IwFZw5mkHSPmsm+ANbK+8ZGA5Zk7eYgUDw2h+237QxW0HFVMB825K0JVsxBmne3Wo8JFC8C6oGYJzlpTOLOoYsnr6WCN43AaD9Dy8Dm5NomqDg5CfUW6V6b7ITh+J6f2LZv+lf6YYw+Gnkr5MmP1ScB9RswCH29trK9L7XmafNLu8wL1jc5WkfqiWFnfWe7F1g1gnqfiFMDHom2LSfbSJz+wfo6AqIvmwagjlwzfNcoxU0bMnOQq5Je/7meEkASevCSAe36of3gVW3PEeLiS9wvOTxrASAyP0DIl3IwNtq2TtHUmAe8HGxrA5YdkxR2FnnuTx6ARyqdRXs20hBwIIU59FeMB1xuiAFd61PZD+m3LL7+Bfqsr35sfiuE/9bsI568M2cGBsD2+pkRSC0se+IQuCrK+okjHcfWkZsKJy/xgisKA9suDtp2TAb93auC7lOzBYfO/sc2j53Fh+mYF1fzESzJTet5qw6bG9ftZM85iOXIXjGDseRk4K+fFNJUR4akJ3b72DVYNBhEqT7WlakA+CSrGb5DMz5w7qcy48AM8TzyM5fTOvmGDV906gySk1XLT70HUeo/3Llt//N3bNubfjNFN1fPj55mXXk2oVPsnstBEhiS0slPTc7PXOzh2Ed/eaeualk+dX55UPFg3D/10n6WHRhzVN482JeEmsqZY+C8/fQXhDngxJ7zyD1K4QimrtcOd3H0M3fh/Qy92FXozrX4IqIQrDFjSDYiwxlAA9WnqfGrrxfq4aExmULgdZRLh1VSMY9CEl/H9A0mJyHuXDT4sWDPWP7EN6eCr32Dfmn022/8h1iovT/C/3ud/WFkz6qT11+p5J1jfoBIadaTNSaGTgwd22Vjvb7JqC8uNNj0SK21E6sv5hRf25rDXPRA4NVhPhWhOVxPjnT50eB9I6afMJg5zFl++M2nGCDb1T811jqtz0OrAc38bEeRBDyHwuvAwFZRBoMkzTH7IhUGXOrNFZ8gGIqQAtWMDh16KwI34v7LXGWKgyXv+RmquNMfOOXhCG72eONb1k39s/o1/5sp/LfED3nwmjHzoJFSy5m+5veMFZuzu4YTa0TrQBmPIfHNh1E5TAQ825N9AJ5j1oNtH0D5aLsV840tez5I8lkKID7KyDOpZ6ImZJVnNmOIS/DPhwlz0Vh/2anF35+hRUKT4l8NYXZnDOUCwNbhRVceHyzkTla8FNl9o7F1GIumrmLMiHTexoqd+3vBygPxqbDNGx5p8ys/+R1MLfoWS74C0iZfzbCzZdi52ZKfNeCQ1mV4/YpbK8b6Y6OBcTSnbAvBknBk7+KnJjiIUpZZ8TnSC6zrFWyexEiW+IZsp+bTBTrPb0iayvGMaVrx9LmDjiGwLr/rRz6Lodh5GbZxEpQ2TxPUAMSZrLAeCj94UsqdNzC0QM/9c7EPdYcCV13k7f7Fyx+D/KtfsG0f/JhVc7PO/EEXPqt9XtehfzU7rOO6AdgjcrVXNkfMZfL1b+EM2O30cL3BOlV9ctZVl+vqvYZU0v2X27OkHr5zf6DkEddHyzn0A1A4TIv89Ay2ewGoPLE7UmyOQ6fFFbA98gYWCcMUbDf2gUklH+r4Liu+pg1IOjGGvCjEBUr6OtyM900V8tIfrLfY/qr+IunN+gunc96X3rl73T+hzCGfOX3TVC7YzA8UyXoxjE+gtHGDdy9Y9aR4iWDegUsfUMaU4bmwq98ZR1vwydvGj9xorurvly6Fv64+dORdlsbFn7numPEGpjraibUJwWTDDam8b7CxADdRzliAlbOenGCqVwYLdPL3rDIu9q8ecCSPrvCxfwU/Qh///Mufq99CeejC3ewzP5XMLFe4NWdm7TlZpCT7gF1b5fm9nLG+3EiNq/rGkYgMbvfDL65uUq/JCupw5vc3pz3MccZuMTmLJLPgxk5/1snr3plrR0Hjm7z2gnjmiF0Y/V5ziRL6d2KQT9AJkiUia2zlUPnmoGGF88XJZGMQ4yreFzD54CGuHuFlledQ52R4saWN4xS+8CvEH1b5M39IX6Zu0d/2+Klf0tuCr9as6X+DoXv9muss5K6MP2LGy4c+OGJ90Q1YJ+cnqHLpQU1sp068fnZX4goFzRMnKT+Y8OFXag0bvPThggqUWlLnhTlX/ZwHUv18QztXnawKnJqOyXBh6ZBlePDGJnEgqODklu0NJFWFXa8cUHyEvjjX9TdmQRqbTcpFApPY5+o/EvrC5zhyS06vfr3+RJZ+weDivNVx5jJjtCGsWeKYnjmzN96TyhkgG0xv2HiWNRYQGNTEwlF1xsUvPArpOtmBwGPOUe9Y+dTZl27uVXLwjQsGBxG3+3CS3Gj94c767+j+ZqghKhjQol1nk1ejNZni8qv8qMWTRU0OYub2NPuGwTfx5/6GT0zVu39xeg4waphZz5xf8txt+9Rnz4lurs0fQfxafbIvP4Gc/emU9Xt9YLY03QAAMDRJREFU8jNncmik18/aHJCW7frhY3YMLGBpS9V6BsWd48EBxqQ7buKxwbgO28mlu5eCiTuGU/0ML79Kj1gFU+tZmfe6+qxFeb/eTo/JXxi/hl5Xv9oWyPw6zY0gFr+HIFazwOByAhK/zWZDp8kruyBk2zFk4gRKv7m5q2ivc3/qJC5P/xVaZyX4G27/9WdvG5+Iu1XyU6/QX+F84fW/+tUXXgNkbdmMXuPYHOOFTS6+5w9OmnXXFng/SbVf9ec+nS+es298erjhmvmMm2si53Wlf7idILnPdViL8mdet7ymnrBvbkDByFzvcqRZ5XBD3huZgHIW+XNwcxaxi892/L2864OHD9h1/TNLdCjB265A8uGl5SP0A46/8rzt4v+qSv5myIt/Ztv+7xfvTD3HHrpqaebgvJ/l90XK4ohXNXjy2f+QznoutnFAq9ZlsiEyFzZu8aXniq6zcRWYdjDmTr2C0zdep8yVmvSr9issx75Oyc96rwd+0Erkmbrcrt2/KaQasqXALRuGK0GnHV5WQcAh7jp0TPiF8QKl2x49rrQaNU1bRtrRsutkmJ9g4fgzufxHQY+XvlXyHT+k/1dEfyO510T7DFxN8Wc+9gFX8/faqKF+cJlHocZMm2Cw0ulJbNpC7bMET7Ckn/3km/JU372rn314ys8MCcWH3u+WFBS/ueKMebJWzx9s5bN/KUOvbwoFCGkPoOTg3QelSpKc5y9nNuiFLfjiTxMX7RzuWRy2q6ZC7nXgpr+SxBBs5ICpHvx3cF+hZ+ZHPHxhbvaZj5/yMdQf+tnL/We/zJtY5rZf68kF9PjZAAGyNi9ZcVK1/H0jIaqa5IK35hTOwZGelJMH1tDJp2Di5xpgc8ZpQ3v25wLOXPSw1CzY1M/ZibkneuB8Q89mrgNQBMlBYFEuRPi2hYUUu1ecXOmV3PPmlUs8PWh5XX9zg5dgez7sUT9tQHx888v0mpk/ungrhD8x+w36+OnLXrPYz/3jk8VGMnfW7JhOTrMWAtL5/qN94kMcx68a6omZl3c55NDT7/HCV3mpVQOYIJjCEloXYKXMXTivhTyiGq+DekmvBS75Xmv4Uw+w8NaKOwXXyHXMwR1DaYVA73Z6Vmxd6iKlCPGANmq4sjNQiL1IOa4jGALw4USTA5cY6UtY6iS9QVWzovsZOmT2T014+e+Q/8Rz18Uy+Caf7tLHTb/2O/VJvTd6qT1z+tMuM6FjZ4zgWAtbQd6GnWV7nbVPTientEW+MXKCNcTgFcse5dpUau+lWmMgrF6YiDnrwdHzEW+SwgSrevenWMZ1uDxYu29xek9OdRMTTnpYykB5JBnrXY7K79Mo0FULHeKEvVidPETVhxi3bQMLN/HEBTrwddEgxCwspvvJJ8Qp/SlN+Rd9ov4buI8BcGuEj5t+7Xfpf0nVJ/Qis39iU/ecAIck7lDl5jc8xL185ab2+pWjPjYb4JvIZIXHhrdyh36FsyoMZOnj+PATR3PASZlt/CkkSmZd+mfOzG94yNA6XBcSAxQunbAHiKPcesmRgBjAu6imdEMFy23teOETzDcScAQPIY9IFnAYBtDEYRemUvb5RFd4jS/iQ/8i4k31P6e/kfHxH07g1sjP6uXF1+v/4OP/KMm86VSjrZssjpI9axZGAesShhBQDj9zKWC8fAd5hiwz2ljqK462OLGbFV0p5ZqXSPoXzwL5fAUniHuRTc+sKdemZwBEgcTjDDtB1+SZv3DJuTYzQTDWP+fw/ErPGPvpt+3yJaCznsQt+uS5aKQci2Fax0CUUeG1kAUha3ENVtXTAglXOMiTI941+AZf01+5h+szx3/58/QrT/psxq0S/hP4//N7999DrGVfaZc9QkfmWrwYL1LZ2rTkCae+96RJ9tygdpZ61xa2feJKhH+BA5KeiyiOyraCt/mG7dqqt6Je4Cv9whR+wCaFbNmTn5z9wgca7GHmwY3pj492QRurCYWEIh60HEMZBqm6lKM7n+AJh+tNVt4QTog4Q4ubsG05ybmmnEc/Yr0t90E3+aOf9Iy88Me27dt/MJ7mYpYMs4fXhVAu+egBsZn50bZLZ/3EerHYEriIOUdg9E/MN4Kc+LO/Y1WDbSw8JanBPefxZ94l4TI4RWssY0+zZn5qXTLy4c5Ms77a9Pov1Se2fvRNhTssbdKwKIRP3qHYyROX7XJ0+aqwOB5HecoS8wLluz51SabmnK+4Z5LNRz95j5k/nngrhJc8//DF2/ail6w50yP946MP65iJabNHBq+9sjlihsrXv4UL1om9BwDzjPzsnx7Z7PPNdKVeBaknd+7vNgQl6WudOhKVb00MUdxYafcgRCxElU/MWjELGL3sCLQHqxpjRv3+TWEIhOhi2QknFt9EBENGICDpSnlwY88niAQKH4u4JDPeD5Yif9aH6C8Vfc6t++gn/2nQ//E92/YT+tQcvbt/Bs0i5edidIq1aU2ZHyjSy5ThC5qANH/8sf+/wBGnLvW93+d6QJLgoj1XcfFnEn5T/9tBBAwpY4svdcFkYMdTQDKF1GGXXFc/86YZ9eSyT1lfePJDGDBp736n+tQdf/StihDPpr6Q7spJMsi8YQKDR1I/1tiTdJmMw83hZqse7nBGm7dPNLn1H/3kL5Z+nT5gxAeNDrPWmFZjVt+cjKYYEo3dy1PO+4SWAeZjnrZtn/x79NpfD07+C7VbLfwg6BWv3bYffan+n8Gf1J8x1k0+xXPXfL7OSmZmhdv2ehUA7/eeR27eH65NA3hlU5N6sNk7w+QjVuRku4ZY+ZO/6wt025/9O4LJaTBsQ0LcrGEvDHmHDIxTGkziZR7KkzsEKdrFEE7BSH+u3pK7lR/9/LU3r7fl0Ah70/0d2U/eN81kzB4+WqpnfMTLkP+o9922v6ifYH74LfwmdnW8/vz6N+lvaOtPONz5H4VhjZLM6RtlhQ73RuY/4873j/PFaW4XFn/i8Mv2g1sPLCAFO8wB7MBHQMIzdfY/8/PgWqRLxXXeF4nm6UK2hkFlEQ65YzUunOuxJbFTE56V9LlDYMKP0Y9mwZ53iz/HzDPy13yb/mKpLrbnOPVfk9a8lfOasv7SRngRa34wrAXNr3p99Zf8zt7MzPc4/Q8E/92f3ranP7muGzMipXv9idX8XiKY4GTOZWedzgvj68cNW/XQda7sfpaGKNzF71DZ5NK/933EDn8fOlwuEG83oekQE8lPPg3oRC6SfPsyiDWGQhevGCblqYsO/qM+dNv4s7W3SvjoJ3905i36xVbmOvdP38yTPDqxaLDE9c+LstaJZ5Av/wLd1Hpn5oEg/ImFL/vP9T/I6rMuXk/dHMzb89egjsnOGuP3a1pwoz7X1heVnAqoaYwdApLcN9RXPFjjK08ur6szHzhmQq8/1ijDxaU9sADFsYwCEDOpNLaPAhoycCThIu2a8uUuITHyBCnv/uRLqP8TnxLv5usX610MfmDCN4KX+qcjOWZBsjbj5Se+NgXAzuWc/Oc8Sx9hfSLVDxx5hF7+fN5z1zzZ/+xB1jLXVsvvfXKlgsSd0zpTF53144MBsk67du2IG4OPVFHvf/XwNShOYOuPNcpwXicvpJmLCCSAIYa4SMHChxxYKLIQoNmU6FluW6ceeJLIfpa+LD7+AwjefOGjn9/yIr07pC+Ls3/mvGFHzRyc9678w/ohIC71Bz/qhmy/Y8lP0FwP0pePrJ9ZfWQhmj/CehNOjPVR6z2oJAqsS3XqGhm2Scw4vq6BpeJnnL8aFMTE4EIs2/9PIXnHOHFAjKDLtqmT09L4k2gR7OXkkWwQBV5sxcilXWw0weDSm/Ct+Akg3/HzHwu94EfXLG4/+vccJCRZCzp24gZwGvWOCcs6WQuf+nua/lu4B6I8XL8A8dQnaVaG1aw5vE4GTgyTmy7rkklJH6lXDJn10ybX9w82AWTWp2clqZ956p0as2iLV1M0ABfZIYGxxIU+yUcrlzQ6jxzbq+SYn9yUC5gFpeeN+t/sZ+f50c97058lZd5a3r5XBGo9XhdYQmxGCbV8M9jPIEk8gPSjHqmZX71mz7VgHcjZ98WtZNZsIPtgQ6dhe++yH6VRYK+tL57cW7nvHFZx6jFir7/LIVZICc6igBz3ac97geAVn4vtAW3suZRXSd8cXkz6D645JLXn90vhub9ylz4lx3vMr9Gn5m7Yv+ahDzjEF6Z0x+Q7DR6QdD4f0z7xB7pobr5p9brq+uV+yPq8BBzlDZGdNZLrmIO7XyUuD86OEu5ZtSbgK4CJdu7UH/gJ6sj9B9/+W99FQNACUEYuOI5tYhU3jlOwFegGVdO45EuHG77UeDMHLpj5Uc1K3y+Vj37yeeZwX9s/a5bOfGmaOZXyfpBfGyNdNsqxCvFA4kfpD9Rn6bv0vrv3pObuNdX8hL00L2xgiSvmPeFeMAj0EeP7BNxKteH9n9iqtyq+fpYWjnj2Ona0/xesJLtR4alb1Wsw7FzIjk/sJKA2vrsRWPUJN58C8HYcnNE6Ve3N+KugfPTza/7x6XPMNKI3R3pe0Fl3dCD2iyMEbL4vQBGyBHDv1P/x8ou/nMoHln6b3qp81Zwta9KYmZ+Js15iHRc28RUEWHtAEQIfqvTyCJwOufBGbBeGPU19MCkPD8/2i0GICYoNkKL5qHMNQQm4YIPppkoYVljjFQMPJnXEceIfcsLhv0yv7fKTO+Pv44mPfv4t/YbJ3bqp8mzieQfP7D/Ca9Ykkxjzk3K6MFm/g8KxCSn/Af1m+ANRfuSn9dVD3yR7TmaWtD3mJ+h4vRuB3QfGXO/ZH9i5J8CQef8ktjKVA1OB3CP4OTDWDV1D1DoMiB3CeZFmjji+NYZIc6N0DfnCSBkLjliLnPi54TonLF+qv/UHOnKfjO/5MX3I6F+MzzFXo/Q7k13pL8BciwfVTGtRq9p5ERLulxTnBvJ/WJ+heAU/an4AyVt+a9te+P37GnP9rozI+lgTxw3W7/2jGPyAuq7iqIMUb+PTpzh8f6WAXKRwDum0P0MLkBnB2gZ1JbhCYHwRlQfiU2HnxXeOvKQXik3AU8RZsQ4JEP7gfubObfuuH6bw3gkPgn/w4m37Jz+48PNC2U6zQZfZPavys2bA1raQV9BriVYMDsdLpy6c36ivFHf9RqK/s/od+or19/Qy7Lf0KbzsSebPDekJWUsWqoDNsb6kvH+Jl5ayhB8HfPdxdudM3trAleNm9QMKrcO9ypZyzD/6TiIN0IllUApYYIZDM2CIjXPQyMNp8oYg/AYW6cQlf+7/XfrbF9yk/M3lG8mb9U3f39aN8yJ9ib/EG/7JYZwaoi/ljVUua/UFKnxiwRzqqWGNxfsmfXP4Nf9g215evy0+Z/hPab/+Ln0I65u37RdeVV2ZEalZl7P8rC/rQmf94JMnZhqfVEuCPH4OmV0zbHMXnnBu3tkTiu4FSOJZbCj3Z75xwQEi4Yte060c5xCaRCDXpRhAF+KsZmgvPn4w0cTB6EBiX+FeaZ8fqR/X/iH9dOtjn77+gAxf5nlr787XbduP/Lz+c81/v14vZzMO/cMz+6vZxPjCeIAF7tnAEQo+mNLBrY1ZOOAzjp39++hnbNsnPls/OHrKf6KPj+pH+6/Ux0d/TPvzQz+pPZPfs2bOrEl+ctfNn3x0cPNm7Bh04rZPD4zqFXz2PTXOp0bBWX/AiAq57U//b/fckwtJIDcAdks17hloUOTGVD74XKxo4p7bp6CWnhjjLmBSEezU5PhzuPwUjv8plpt65rM2Ypck2OQu4Xp54sBmMb3+sh0jVX0aF+KqsztqwkWcD/if/4YIPO4P76yjYPbCRy7gMss79U3fW/U578nDvHwppyy4dhR0TDlL+b1nFBHzgDumrJWT0+nwUZdg6ikizjEEmKGVw0Y6VnZi/p1CnFyIbpTKC03AnPpC0ZKbyBedKODweZKGtnGlf2eGMTlGmJuY38KOzP7EzH1N39R0/wSGJjdbe+0jZqh84sERO1xogyo/QRWnBz+9vFvH7JeNdkn17D4YkbKburCkJx95Qy/gQ8UimscEOo2AzapPTXqQI2VMOe0H7OTCNE0ZlQrSLztmfVE6b2yS0pj+hhwjAzchACdc23YGz0Y7W7jAwWC7XsbhwhYoed/0wexjTNplpw5suJ3Z58y87i9c9KF/1aDIX+nfGwBgHcHgu8bFlS8bjEs93MqBbaEX4cTQHIV3bXIUJR9I5bpExuQ61AdbmM5d8NPKGBwk3PDo8P7pSYOXBbOnc4U3BhuiqrNOiBgCX2m4XDdiK7lwYPVvUWJIDn47O6ff5UgDKntgFfeQplpFxBpDoYtXDNM9Kpb6xhePF0LpwAUTDbTSVXUv+g8+isM/OSGLnzw6sWhwxE2pRVmX35jyyXUM7IizIX59yMZI3JObo2y0pfLGV8jY2EPTa9ZjO2ajcopljipdNYUlZg40vU/9yRmATk5Bx0d/0pZgyBm0Y3sPBCR3o88zd6/CFlWPgp/1E8TvmIz970Mn4exaQz8iFfMgGVpYS/mouYhc3AN88sp2zoUqLuDs0akLudV8rzMW/pKL/UcusxpXc5Hu/tWTWDYvufjkMjcamh5BvmcyaJ3cs3jDNfGgzr5JqiZUl/o7VsUofMSh2E4oKL+gvbaAE3dfBxces+evemj9QCCZHthI+aVWrPq7LrMEqmD3HvXwZL0uwVe+sTiINPMR9wf8g6D4sBkCZCEmKibHFk83IJ/65MOr1JrExjrNoYJPPYjkO0fsUn8Wo9yl/sHDd61QX7xee/nn/t40kRAH77yb7syeX8++CBfbWNnNS4Iayay/jq9xrtj5yrWC2/PXLPHTO2tLX3Mq6f4HojWnZ62kOXTyyPQJXobt6tlx/Fr/3C8TVH0/COBKfQjiK5VQNPDep5HveVXLM78/PmpiKqspvIhDxGRQmLhJKm9gsDiFdTwFdhZHuMDFDp/LaSohlnx06II3tPAo8sGGAx2ZnMSCDZ9xIjKui4TDTnNMZpN2nJykbYxgpdOT2LRdIyyxxhMsmRfelKf6cz/7cBksjV2qcyu0f8kvv7nwUx+seFIf+nBn/1LmkllPQYqkL63feeVS1pq6kvSfXKQcrwLbivk1tGuLAEWycLJqplQ4soYr04Oeh13dgliaDWhRI1/MDiwjMW9W5Zp7YIMjhB1Mx2evqjv0r7pKiaA2qLTLZUdSS5ybrfsAABds6bQPj+s4DZxnJnSqz7O7Us2devPNmqo1h5KZK/sX/GH+8KIlqVnOfv17T5SgPlxZL3XEXD/WRayx2IXzDAPXfRWbXMGrVIk6sEUa3u5ZeftKrm8KZaQPBbNRhuhY8WeDiF+yIQwnGtzkSI1SlmCJN07B4DomNPaMX7LdP6RVMzlSQ3PWbIEXQzql7SewkFdqkjZvOZ4zfMQCkgYX7nz2Az9zGVo4UxAYR3Dk2lZ+f4YqPADFvfZRT/P0jwaHfdinWY9dAi517lm+Z6EPUnyzf2rATXsVKOZgedTHh3McHVe4beXXLBQOPAAvKrr4o7oHdWAG6Xkz8MF30yKZOEJgiBkPp0lLV01UuBpLPQQS1y1zzQaPJPnl7Tj3nfnqOy+G6zkVF6ZFfrVdWn5mSn38A45iuIrPmFMM1zV5TR4C4thVm7B1+lMs+4wDY1wVdV/iFTvXBeM0nHBHagYUcbCey86IyZ91tgsbOzrrSt+8Ju/5qpdx4ghv6v1LsnBb2jj5qVKYRg1TPIs4xMEVRToaFzy54mxc4efgO0nIqv8ouq7/XrEs42RGJ5/6bBBxf8mjR/VhVHDRxoCreNcWhjxSS1w8p/qFGGd6cUhcVzZOfHTmxWbO+NQd5MRnnADBu374ibtZ1cLfUnZ4DvH0KoznLYDtyve8ygWT0t7DkTOFgGDpG00cu/3qS9xf7UggeURnaHxjRwGxEKVuFa84dpo7rlr7LnJknYpzcrhf4QF5nlGSWHDnfLgyf0q7fwJo9QkebbsCXY/PnBewwaTW+gJe1ZaeWR4wc9rY58hAntdVCzd99yHMXHKKwjo5z7zSV+bvmjzzF861nOZ6z/7AnvdEqcP9Q+mUXKvEsyb8HDbUPznXn/xgr1u/f2PFa6hCL7i6uqimCgY3ZMRaqC8nF69z4ptcHZeROJqD2izesQLDPbGE068gra70BzvB2KzRpKvMefmE85r2SoPKgwU3Zdaburj9bC/glf4UF6b7wHuB+8BXXO4/6uFPj+wfLQ5S/O5nUmXhQBUXYe+fg2udgQbbGkxk1isWPrCulwZiaUMednLS7g+o4pjE4odrxlwPhw5/fNRJTkavBByIc8vcF5o4TZECVfkKyfGiDkGn+uR8e8sgNuNF7eS8ULbTf3Ck1hdF+VkzYGup5BVMD+vq73jlU5eewXuTK5lY909ciUNMnAh44qlLDI04PvL4E2tQuJRwnpNizTvqic+9MNfI26dcMWNpUHlCSNZvW6fuQ0ASzraJ1UwovmHLyxiHi9h15HREMushlmR06gUCR836LEcNzgIOrFWYwbNYwrYr77qKQUwuefwW4u2sARgCbBYw0m06L2/yhr9BlQ/fpbyx9MJIz/SvWDCHerA6qOk4MYWaq+rTPzzRweHHtiZQXJMbe+YNq/6Jo6/rd9jocFV9uLznkIy8+QzgJEleGHOikdQM2/MXnnBu3qwLTTmQWd9rHdwdK6wV9TpcT0DiduOHOf6mkATASzLj3gBAYYxWiPKZz2bN+ll6jrc/OMF3fPKTQAYWXPcnVbnU4w64B3YsG1Trd0ynxlacdkhqvGAClU+fxoAV2HMVLjPhIulhzRwysHMYdKO5AFIHZuJcWKeKJ9TciZfu+eUHY3rdLGikNTWnes8xMSkIHzoE5CS4OcwnJz7aUn0cr3zi4TO2cMe/Dw1SCV8EoaIrfHERwZiU8iIuRWlLsFN3MsZ1/S8S7jNmcd1/4JnNrk5ZPHhjidXwxlVd4zIXunKZ337qXSxMPVsUdF0g5ajxh3KCgy4guEsOM1U+s+DG9sxw6uBL+cy1o6DxTb58alIPNus3DCKJFTnZHPiuk578XV8g/1WlggB1vU5e1+nB4VhhgnWs+hJD4KAPM8Rm5jOW3PrRNwVDskAXEW8m2VThnyTDXZc33NPIii6OHm74mJnD3Nf0rZK1uDgnTX1aNs2IGS6fZQVHzP0JDnF+giqXHllLQ068PJue+5ii+jS//HA0t4DEDJ14CMrHBJRa++RGwObEKz17NBygnPZNtnNVekWLb7Rx/LzeWWNsyGefAoWrZxPG+wszNrUSw6u+f7BCovJeHDZELqwGYAJKvi9gdc8QA7rKijzDmduZ6gP1wGDnuHRjmV+YK/3PAwwMs8NpiHTWkjU6zqlymYdexqDIIakvfHOu7J6Xb0jVoeJPrkN9sNLnec8+7cKJbam6zOj949kxcUAU6UhfY4h7uD3fIfDIqPEshQ/PIlw4sJQZUvUHv519Dlq4CKX8Yb0V615gJcGwvv3vQ8up2fqZMYukYEoTmFl10sFEg690l+JPrAEFMmfZ7iv7Rv3NP/DpG528IbU2+uE3pvxDDOyI+wKy/toDz1RfOoOjV/LGO7DPj0sPJL3Qqe+YjYWZeRdWbbDEjEGP+dKfXDet2fEdl+9aOwAlwZCreLDmrDy5W/l55p6/5pgjMiZ+X7/yOyZj/T+FJKqykxTqaHFixbwoEgAqjut4FXWq/JkDa5nY6k88A1d6YetMLrMad6n/KDRetekf33TBwQmmerAuUu1jX+jT+eI5+yapXFPLP+Pmmtxm8sV2Qiyj/rAW5c+87nlNPeF8yfac+C7QqWpKrWj1d13ZJIzRqWs7uJKZ0SXCuR4M4uKl2d9wUIPMB2rvv3LBdT3Yqr/496FdbEZOJWle7iQNnkF6mOAKSHlw0cSy4Nj2qya4orqsVBice5ef+ZJj8cR86OS8m+601OebGjYz+OYFSo1k1tNj+guxzo5XAHv6hHu9NUv8YOf8RdMXL741s9eRJubQySPr1L1l2CYx4/j1TW3iZ1w/CGia+hDHVyqhaOC9TyPvvQWkWvZ+rt81nBC4S4A3b+LU6/AfawRXnDbchGDA2JI0c14FDIjdeGFyASa2cWbZ8R7Kp71/sOlXJVaTk0Cwsz8LMS6Fms8txlqSr9ZGto0R7P/f3Nnuxo7kMBRYzPs/8+rQPGq1kwz25xZgl0SRlMrd6eR+zJ2eLWd6xYjsv/w4Pbf7wsfypX/3S05f+xPPEro99lv+Q3nO13j1zT0r+rfXzj/c9zyRI1CEfi6fBfWNwb+pn09/eJDx4ZLY0PxH/5dntKNheaZoKlSfXxRCeA/7TPEYeM8BTKoxdceHlYf1hB/v5mzyjO2/uBMezVf/lwcHjqS7sXK14LzZtg8EZuZidbe9PtFxO7zMDPTS++mOnd7q43c11cZjis7l85P/Nb++7LPUPMnzHKIb76s3diZ0YNEzB6vYcgfyPJnh8LbvYNdLvn77zMZU3+2JX/UU9fT88WCGBuxc8jxLy/O/pBgzH9aN06Ss9LRpMTUawWFlEJPZ5e0Aw7l9/or3kHF9NNdD3/QsB00OPrsjbC5QbnDiaizHt0lmKye9JaEZA739ux/kzhVqebEAOJc8ahtP/fmEAZ0FnzX79tfj9HeOPYu6kVq7zw7LzEow3Oe3uopRUD/7l/7k9/w7P74RYDwLvjme51p84I2n/j7/9q+fHqtBj3W9/0OBWMI9uER26xNmXR6AXPB4xrSNHsne9VouegxmXd/1Gdx6SIeXvrfevnmYkMlnxb7xg8x98rbdujNZM//iYYBX/cJ5YaTR9GfSO3/iar98B7tebx7c8CtaLrhG43F1clKmxmCuzsAGDjdnSnKwya8ucbnG7j+eyW/np//VT6reeanfc1APB60BHPJZnv+fHGKA+i+BPOQqwptYfopDWh6uszROQvG11Mszh/r2utLlvTzFw22Nb3kxqwFHgHf3Hmtx9c5FHj5B/ah99aPmsudwoiNnnVycnQtfaInJ71I/2NXZ3zn3XGg1Y58rOnBW/dQ/4AdPXv3VZbaXH5ic2n5+R2IK1uJpPsTg3YlZzv9k567xQFcn/1f9aPxuE9VfpJjE9WdDNVR8wX1oPvSjCkfeu66XenXbX4C9D4YQXbQ1WD05D+YXrhy12X/hjzprZ54MWjwTNAdrnnnJWdP75lC40n+CSrJby8zlJT7zQ4zGT77youV2z/vODxdefOzDXv6dd+AsXys1csi9ErzOSx+5GMn9t/OnVu7Xed56OeJj/nlD03gKLF+8JwPoC7DAJ7A5OxdaDx+sVLwvF9h+pez2oz/cSybmycT0kaU+ObA/0/5o0DpceHddfazr7S9wfvRHXM72wfcX7y8/ZHKOHswePr87X2J0amLaGerJHMB5fgjMn/CZtzjb16pv9FPILAfLfArAXeUEmpv6fTbDAzMnxuti1OIfk/umRHhWddHHaGoHA3/e0HF/mtTz86ZWiG95tsDgve5g1K7kvlCJ/9BHN8Id/N2kvqmfHuk1notP/KP/xU5/eWhZ5nlzXOzE9nkUH83qh7s+x1N+XmTwIcHzmazv0eeF00yvU7eU+cW7z5alPwn87ZPqg+1MYiE+Nd4s+YJinyu9Gs+2Z03cgboBfdUDdLAf55frOSDfOOIHM6QP1/OGrrEHZH8PGyG4DhiMA1d0uP2xfvPV/0r0Yf+tHu7U0oqdwP4UHe6th0vt4mCPPPj13N5oWOXqv9ynuvWrIw6v+myDXTz953Z1saQvl0uv6oHjEwOS9mLHLwRus+CAA3qBg7GzGmeO8oF98zofOxbRHX1mQUCRBe/UxaO/+FDTrj8+yVMfr/o56/riM6Dvv3AH2x85Jn7eIFRKZMfgrmt88eVJaHHxyfMGvKLDzaAnl6ue0innoQXjYHh2zmBzC3ZwQlbqcD1Xd/ssB+6QMxfg8JyJlGWP7K3H/9TsE3xu4SKmLwk6Yq5Z4T3hcy8utHXx7jv/5HJiP28WdtbuaF76zHE5CvRj14DaLFKv+E1izp7VPsFbF9cv3Msbwlv/mP2Cdz7Pk9/lwFgDH0z99XlmQDzEvMjdvwgkw7l1h9b3i3+4b97lM1vmoX97OAcFteGFeHi3YWvOF1P1NumnRanPCzQ1NPkTOnnMJOn0CKZn60jyXGYzzsx4zsWnClRrmwwYbGpZzdGoh+v55bAPnBt6LvLoZr/+qy/JP/qPfqjRzy3nen1xBCsH21ik0RODscDpQ8mYmaMfMFhriwEimGXdnP19fr3370M7XNQ1euzOXWf3lna4kxP6oON9Bizta9v+X+iTULPl2hwsrMkZWx7YHjqE55b6JbVmD8+ylJcvn6bvPrEAnLX+k+ux3q2HevkImxMiVJuc2gESXv6Ub4+lQ5xk85h9vFp+0PqdNsHf572acDW/fUrSa2cbTp4vzsRoZ4X+1hcPobzlEhzscp4/WJmibz6HeGsYKhjcCczF3jt1r9/eWPL3DdTGzkE9Q3e29KtnqBPvocoJnuGe2p0xDxAYHUt9+ev5VD/1yUOpjs38en3p5c4OZ2u/5LSDHg4JqzxnzDPh01G8HOp673MDwNBrwkDkrKPJbOXrs4NUz3b1X/kmnznskVZT/zo/7QfbXiF/MN/gzg6X6xkA8YcrB4t4xrT/xYpvKovsrHKexHzANLkEG1UQv/J3qHX5DOCL8Gd//DjQXLGemy/qzbHOoRIMR51565ikxpsDTkwgzaIPy14T3rmksm+vScSDpfjBUtQXv7lY6s09o/zF67ezTZ4X3RmtxzTWz/zFs7V/dOjn2h+dyJXpeeelqL68QHLf+vLZomteabZA6gcJFzpY+WI+j52h9R85zp3z+9+HHgHG1qNvfl/chzH3y90pvj2W22AHR47eIQntX18k4Z+aOTX7s2OzI0yudXjUfulz+fDeeUzOLHB+6x+s4rSpJpBxChh8+nx5TT38NOHW9Yce+OsTjfylqfRB2z+6xhTCmdtqF3yKzhjJ8KKHw4r42Xm+eqBh+cWXOAYTTU3e6uH+pkeo19EDs5xtOYPl34fOi13CDoNi1tZOfDFN6UucvBPLw+fPxQHLT+/mhbbmgwCHn3qafpzTv7+o42GGO+X1hYpm1tX/5be8KD5+TbPteTuLub09m33jOcX0/zL6PD+L8ZhbRu55IlHfnutF3vPf5xWD6veLACP1GphPScgd+j6nU8+zhTRaPvnv+aPhxsK7C/r6iqPvZZ/wJMpDO1hgsIOjzy8KM5TNauBgd1crP9Ty2ajTzLp7rfew4nLNw6u+tjFNbHP6TAy2nBsDyp093GI3HtZnVvmAXfeFj/zltb3rnRyf5s4gZI59vuWXSr5eJmcez4r+7eXzU8a+/YkRKEI/F5pgs20M/k39fPrDm+vtBRS8wsSC9Hx52hOKZ1r9YD/0EGfJ/VP/0Fa/vw9dPAbEeVgF90FImh3MRSxn8Z1Q1uP5yb49fADukZ8eefgjBufNtn0whCe3u+31iY7b4WVmoJfeT/cprbf6+F1NtfGYonP5/OR/za8v+yw1T9IzpvDEhOj18rzowKI/5wJbLnF5meHwtu9g10v+SKfQi3hM9d2erSefop6eHxlLHTuXvC9/iJ1PzuoasDGfPCTXY9/Q9XneyCaz+0LsAOhf+OUY0+Stufnyxs+h0SRGy6CzNhd44B8ay/FtkjnhT57ekmaHp7d/94PcuUItLxYA55JHbeOp54HCY519++tx+jsHfOKv51SfiwFl1tZ8EYPFgMKs+rHbn3LwCW4MzNqzkKAP6YnJvRYfaOOpv89vD6Rqv3zRU6q3fOi7pvY+PzW50Zfss1hThAwYA/d1fgIPsFzM4/7deH1OXSsHdBj1OXTBWOZJfIZXn51ZC8h1pjy0qZl/8dDgW+9wXhhpNP5MrgE48Z1L7mDX681DFpt6LVfP2TP38ZcTyfhXCnNnYJRICDY52BSvLnG5xu6ey77+TL6vT3uFNx76ql8dNUD6zCKUu8HVtxh9dYGuvnEM57a99J56fpdjG1G4ycsAI0xY8syBua4cnmt5L0/x8PTWrGI84d3dPuLqnYs8fIL6UfvqR81lz+FER846uTg7F77QEpPfpX6wq7O/czp/6JqxzxWdniH8Mn/x0IhHdHXEe/6GYHKU77fxKVhDun5DDN6dmOX8T3buGg90dfJ/1dfbeXW7emvv5xfu6P1um9wX/P3QNWaHI09T63dIMfYcwqIFh5+cUsrl2P95Ehi0frhy1GbnNtzLnyxrZ54sbfBM8PF+Cp23Orwyf/P0mTj9J6lFdmuZ4fT5mkeNn/zlRcvtzv/OD/d6QmPlPK95n8rPs3qm9EUbg7m99a9c/r+dPzU973mK4fHFEc8QFOea5XnuWb9wOPeaJP9NISQacGHiCx2M4qzM1UYO0/QhnDt6OcJfOUImienDSH1y4P0qezdoHS68u64+1mjhHc3yqbHKyd5cfuq9ffkhq+fVg2WGqfv8rkdidPaMKWYP62v+qQWGP2Wpcnd/pDWY7fIx6BX9xKRZG0xWTqC52U8cPpi5Xhejds+/P8eiu6v+cPOMZker54/nR/2uw70wsf1/9LagIIM3uS/UDiSx+x2K+Gou1UOw2yP7aKID7wHU2VN+HnKLYttffApf2Hiy4NsnQLGv+PSHbw859meu1Lmd+X2xwsfrGCR8+cPLrOLdZ8vy/CRpJe8pP/OVbCs15LzY+YI6eqTLJelyVmvANw7NXlOgZi/gcO98N454btWTRk8w2L4uL43+8S6XjaX+x9/leMrfdxuw54FP2f0ywxvny7v1xA7J3imiozhY1ulj7ifb9q1PDtc4b6D2V+cuj9w4O0D113tnaj1b51LHzhmuDl7OMdxdZz658Y/Bw48nPPwQqqcATu7VejQnjnf5wL55b08sosMT0qzMkiBp+ix2cLAvfGppd/4wJw7l1S1+v/XirP/z82Pw6zsxnvGlxpp9P6EZNMvOTRefnOZf6+Q56Mnlqqd0yntIHnrw9g9vbst1rjZOHUy8u32ghcM+QeYCHJ4zkbLskb311T6U7RN8buFSoy8JOmKuWeE94XMvLrR18e47/+RyYj9vFnbW7mhe+sxxOQr0Y9eA2ixSr/hNYs6e1T7BWxfXL9zLG8Jb/5j9gnc+z2Mf+eLmqdOr/d77/lffCiDkTTBKd2r7wJcI+OF4OHnu0Bki/edGTAI/nMbA4YV4eBRcraFLP3Jjm/TTotR42mv/Uk6Ld8ZtcT3Lc2ZSY/vjwafCrW0yYPhr/uS/zn84hPjlbLN5tOiKf8CpQyiJM0phT2luOevriyNYOXKDvebGg1mYydhn6ow/9BBziGogNI/G+mDxmrLeULOoGbNXn+fw1k/OB0v+6HuHqzgPaGL3HFKDct6bD+eNk2eAFtbml2GZl7or/XuIxQguqQV7eJaljP76cuib6+vDio7bkPRY77ZG/8U/OSFCtclfDVOLSaoPpf2oLb3J5tJrLvcxeIotycyLfPVXE67F2Q0z/CR67fnBBoTHLd+ZJozn5ODRVNitAkTlEsSEoOuVr89fuDr38vIjBwOz7k7s9dsbS/6+gTzEngLD55JDjmcoreEDDic4t9acZzmUqLHUlx+ttVufOJTW2Myv15de7uzved+5raInYVXnjHl+fDqKl0PdvuGAZ7jHI3qh4WYdTWYpX5/HcJjw52ILhWDWV77JZ44lwZ3613mLba+QPxzf4Nu7+numLz/6z9pzPOkADwa+a+J7DnsAXs9/bHZN8wYcJw2+jAeX64sQ/hnOIVIH7zAY+qLibU54h1pdCp85wkfIm4M9JpBmtf/2GujOJZV9e00i7pmuPkV98ZuLpd48veEBeFaIzVNvnhddjnVq9qF2fOjFim7wnOmcHyrLmdZnMH2oy4v16S/+4/z0DRn1Z33pB/5Tj0S9Z/grh1tOZPKKJ+08OdOcH+/EcFjV//j3oVNr8fSIxppGedinOXiwI/RBWzOPobzZseHKmpzS5sQk5eu1dfGIP7zwW9vS5G9dZiqYNtfPOIXHW/3XWQYUd870/EMP/PWJRh7B3Krp9qAUB4iuMYVw5rbaBctvLZKJ4S+XhAVnQHHOxfKLL3EMJoILwFI/4a/6w9nX72j2+dkPPmvy+5pQXn1j6sHLZ2Ou5x9rnIBiSBNEDGEnn+SvdfjoMUKndD3Ap5zLevlapz9ffbN4mPLXlwKaWdSeoSf+w295BLP0e7Lnjndm7Czmcu/86rafAPvoMz8+Ga79JgbiVjhBYgoXJ+/5xd+8/SKoZ3gaHz8hd+h3bvE8W5LR/j/8fWZ/UctIvgeYLdds7plfvIfhLP/4gvVMOXQOiRbBWeTwxY3NQ229PTJA4uMVnyEv58aAcme3J9iN6WX/5QN23Rc+li/99m6/5PRtrqeQOfb53ZJSydfLBFGXZ838g20f4kmos9aDQD07V7Hfzp/6cJTtrofeL6+Bn54VsGVp8PLcmYbkmaKp8Ie+dnL/1Jf3r3qKnd9nBsSfKMf/nPW/mhQ1G1V0l2MAAAAASUVORK5CYII="

const MANIFEST = JSON.stringify({
  name: "opencode remote",
  short_name: "opencode",
  start_url: "/",
  display: "standalone",
  background_color: "#0a0c10",
  theme_color: "#0a0c10",
  icons: [
    { src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
    { src: "/icon.png", sizes: "180x180", type: "image/png", purpose: "any maskable" },
  ],
})

const SW_JS = [
  "self.addEventListener('install',function(e){self.skipWaiting()});",
  "self.addEventListener('activate',function(e){e.waitUntil(clients.claim())});",
  "self.addEventListener('push',function(e){",
  "  var data={title:'opencode',body:'',tag:'oc'};",
  "  try{data=e.data.json()}catch(err){}",
  "  e.waitUntil(self.registration.showNotification(data.title||'opencode',{body:data.body||'',tag:data.tag||'oc',icon:'/icon.svg',badge:'/icon.svg'}));",
  "});",
  "self.addEventListener('notificationclick',function(e){",
  "  e.notification.close();",
  "  e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(function(list){",
  "    for(var i=0;i<list.length;i++){if('focus' in list[i])return list[i].focus();}",
  "    return clients.openWindow('/');",
  "  }));",
  "});",
].join("\n")

const PWA_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>opencode remote</title>
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.png">
<style>
:root{--bg:#0a0c10;--panel:#12151c;--card:#151a23;--card2:#1b212c;--border:#232b38;--fg:#e9edf4;--dim:#8a94a6;--dim2:#5c6678;--acc:#5b8cff;--acc2:#7c5cff;--green:#34d399;--red:#f87171;--amber:#fbbf24}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;font-size:15px;overscroll-behavior:none;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
#app::before{content:"";position:fixed;top:-220px;left:50%;transform:translateX(-50%);width:640px;height:420px;background:radial-gradient(closest-side,rgba(91,140,255,.14),transparent);pointer-events:none;z-index:0}
#app{display:flex;flex-direction:column;height:100dvh}
header{display:flex;align-items:center;gap:10px;padding:calc(env(safe-area-inset-top) + 12px) 16px 12px;background:rgba(10,12,16,.88);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
header .back{display:none;width:32px;height:32px;border-radius:10px;font-size:20px;line-height:1;color:var(--fg);background:var(--card);border:1px solid var(--border);align-items:center;justify-content:center}
.logo{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#6d9fff,var(--acc) 55%,var(--acc2));display:flex;align-items:center;justify-content:center;color:#fff;flex-shrink:0;box-shadow:0 2px 8px rgba(91,110,255,.4)}
header h1{font-size:16.5px;font-weight:700;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:-.02em}
header .dot{width:8px;height:8px;border-radius:50%;background:var(--red);flex-shrink:0;transition:background .3s}
header .dot.on{background:var(--green);box-shadow:0 0 0 0 rgba(52,211,153,.5);animation:pulse 2.4s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.45)}70%{box-shadow:0 0 0 7px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
header button.icon{background:var(--card);border:1px solid var(--border);color:var(--fg);border-radius:10px;width:34px;height:34px;font-size:15px;display:flex;align-items:center;justify-content:center}
main{flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch}
.hidden{display:none!important}
/* session list */
#sessionList{padding:10px 0 4px}
.secthead{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim2);padding:8px 20px 10px;font-weight:700}
#sessionList .sess{display:block;width:calc(100% - 28px);margin:0 14px 11px;text-align:left;background:linear-gradient(180deg,var(--card2),var(--card));border:1px solid var(--border);border-radius:18px;padding:15px 38px 15px 17px;color:var(--fg);transition:transform .08s,background .15s;position:relative;box-shadow:0 1px 0 rgba(255,255,255,.04) inset,0 6px 18px rgba(0,0,0,.28)}
#sessionList .sess:active{transform:scale(.98);background:var(--card2)}
#sessionList .sess::after{content:"›";position:absolute;right:16px;top:50%;transform:translateY(-54%);color:var(--dim2);font-size:22px;font-weight:400}
.sess .t{font-weight:650;font-size:15.5px;margin-bottom:7px;line-height:1.3;padding-right:20px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:-.01em}
.sess .m{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.sess .when{color:var(--dim2);font-size:12px}
.sess .dir{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--dim);background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:2px 9px;max-width:60%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sess .live{position:absolute;top:18px;right:34px;display:flex;gap:3px}
.sess .live i{width:5px;height:5px;border-radius:50%;background:var(--green);animation:blink 1.2s infinite ease-in-out}
.sess .live i:nth-child(2){animation-delay:.2s}.sess .live i:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,80%,100%{opacity:.25}40%{opacity:1}}
#newBtnWrap{padding:4px 12px 20px}
.bigbtn{width:100%;padding:14px;border-radius:16px;border:none;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;font-size:15px;font-weight:700;letter-spacing:-.01em;transition:transform .08s,opacity .15s;box-shadow:0 6px 20px rgba(91,110,255,.35)}
.bigbtn:active{transform:scale(.98);opacity:.85}
/* chat */
#messages{padding:14px 12px 4px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:88%;padding:10px 14px;line-height:1.5;word-wrap:break-word;overflow-wrap:break-word;font-size:14.5px}
.msg.user{align-self:flex-end;background:linear-gradient(135deg,#4a7bf0,#7c5cff);color:#fff;border-radius:18px 18px 6px 18px;box-shadow:0 4px 14px rgba(91,110,255,.28)}
.msg.assistant{align-self:flex-start;background:linear-gradient(180deg,#1a202b,#161b25);border:1px solid var(--border);border-radius:18px 18px 18px 6px;box-shadow:0 3px 10px rgba(0,0,0,.22)}
.msg pre{background:#0a0d13;border:1px solid var(--border);border-radius:10px;padding:10px;overflow-x:auto;font-size:12.5px;margin:8px 0;line-height:1.45}
.msg code{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;background:rgba(0,0,0,.35);padding:1px 6px;border-radius:6px}
.msg.assistant code{background:#0a0d13}
.msg pre code{background:none;padding:0}
.tool{align-self:flex-start;display:flex;align-items:center;gap:6px;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:#8fa0bd;background:rgba(91,140,255,.07);border:1px solid rgba(91,140,255,.18);border-radius:999px;padding:4px 12px;max-width:88%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#typing{padding:0 12px 10px}
#typing .tb{display:inline-flex;gap:5px;align-items:center;background:var(--card);border:1px solid var(--border);border-radius:18px 18px 18px 6px;padding:14px 16px}
#typing .tb span{width:7px;height:7px;border-radius:50%;background:var(--dim);animation:tb 1.2s infinite ease-in-out}
#typing .tb span:nth-child(2){animation-delay:.15s}
#typing .tb span:nth-child(3){animation-delay:.3s}
@keyframes tb{0%,60%,100%{transform:translateY(0);opacity:.35}30%{transform:translateY(-4px);opacity:1}}
/* permission banner */
#permBanner{display:none;background:#1c160a;border-top:1px solid rgba(251,191,36,.35);padding:12px 16px}
#permBanner.on{display:block}
#permBanner .pt{font-size:13.5px;margin-bottom:10px;color:var(--amber);line-height:1.4}
#permBanner .row{display:flex;gap:8px}
#permBanner button{flex:1;padding:10px;border-radius:12px;border:none;font-weight:650;font-size:13.5px}
.pb-once{background:var(--green);color:#052e1b}
.pb-always{background:var(--acc);color:#fff}
.pb-reject{background:transparent;color:var(--red);border:1px solid var(--red)!important}
/* composer */
#composer{display:none;gap:8px;padding:10px 12px calc(env(safe-area-inset-bottom) + 10px);background:rgba(10,12,16,.88);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-top:1px solid var(--border);align-items:flex-end}
#composer.on{display:flex}
#composer textarea{flex:1;background:#10141c;border:1px solid var(--border);border-radius:21px;color:var(--fg);padding:11px 16px;font-size:15px;font-family:inherit;resize:none;max-height:120px;min-height:42px;line-height:1.35;transition:border-color .15s}
#composer textarea:focus{outline:none;border-color:var(--acc)}
#composer button{border:none;border-radius:50%;width:42px;height:42px;font-weight:700;font-size:17px;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:transform .08s}
#composer button:active{transform:scale(.9)}
#sendBtn{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;box-shadow:0 4px 14px rgba(91,110,255,.4)}
#abortBtn{background:var(--red);color:#fff;display:none;font-size:13px}
/* misc */
.note{margin:12px;padding:12px 14px;background:var(--card);border:1px solid var(--border);border-radius:14px;color:var(--dim);font-size:13px;line-height:1.5;position:relative}
.note b{color:var(--fg)}
.note .x{position:absolute;top:8px;right:12px;color:var(--dim);background:none;border:none;font-size:16px}
#connectHelp{padding:48px 28px;text-align:center;color:var(--dim);line-height:1.7}
.empty{padding:48px 28px;text-align:center;color:var(--dim2);line-height:1.6}
.empty .big{font-size:34px;margin-bottom:10px}
.flash{animation:fl .6s ease}
@keyframes fl{0%{background:#13203a}100%{background:var(--bg)}}
</style>
</head>
<body>
<div id="app">
  <header>
    <button class="back" id="backBtn">‹</button>
    <div class="logo" id="logoBox"><svg viewBox="0 0 100 100" width="16" height="16" aria-hidden="true"><path d="M26 32 L48 50 L26 68" fill="none" stroke="#fff" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/><rect x="56" y="62" width="26" height="11" rx="5.5" fill="#fff"/></svg></div>
    <h1 id="title">opencode</h1>
    <span class="dot" id="connDot" title="live connection"></span>
    <button class="icon hidden" id="bellBtn">🔔</button>
    <button class="icon" id="refreshBtn">↻</button>
    <button class="icon" id="outBtn" title="disconnect"><svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M12 3v8" fill="none" stroke="#ff7b72" stroke-width="2.2" stroke-linecap="round"/><path d="M7 6.2a8 8 0 1 0 10 0" fill="none" stroke="#ff7b72" stroke-width="2.2" stroke-linecap="round"/></svg></button>
  </header>
  <main id="main">
    <div id="connectHelp" class="hidden">No access key.<br>On your Mac run:<br><b style="color:#e9edf4">~/.config/opencode/remote-control/qr.sh</b><br>and scan the QR again.</div>
    <div id="pushNote" class="note hidden">Push alerts need HTTPS. <b>brew install cloudflared</b> on your Mac, restart opencode, re-scan the QR — then alerts work even with this tab closed.<button class="x" id="noteX">×</button></div>
    <div id="sessionList"></div>
    <div id="newBtnWrap" class="hidden"><button class="bigbtn" id="newBtn">＋ New session</button></div>
    <div id="messages" class="hidden"></div>
    <div id="typing" class="hidden"><div class="tb"><span></span><span></span><span></span></div></div>
  </main>
  <div id="permBanner">
    <div class="pt" id="permTitle"></div>
    <div class="row">
      <button class="pb-once" id="pbOnce">Once</button>
      <button class="pb-always" id="pbAlways">Always</button>
      <button class="pb-reject" id="pbReject">Reject</button>
    </div>
  </div>
  <div id="composer">
    <textarea id="input" rows="1" placeholder="Prompt opencode…"></textarea>
    <button id="abortBtn">■</button>
    <button id="sendBtn"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 19V5M5 12l7-7 7 7" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
  </div>
</div>
<script>
(function(){
"use strict";
var UIV="${UI_VERSION}";
var KEY=null, view="list", cur=null, curDir=null, sessions=[], perms=[], es=null, refetchT=null, busyMap={};
var $=function(id){return document.getElementById(id)};

// --- key handling ---
var u=new URL(location.href);
var qk=u.searchParams.get("key");
if(qk){localStorage.setItem("oc_key",qk);u.searchParams.delete("key");history.replaceState(null,"",u.pathname+(u.search||""));}
KEY=localStorage.getItem("oc_key");
if(!KEY){$("connectHelp").classList.remove("hidden");$("refreshBtn").style.display="none";}

function api(path,opts){
  opts=opts||{};opts.headers=opts.headers||{};
  opts.headers["Authorization"]="Bearer "+KEY;
  if(opts.body){opts.headers["Content-Type"]="application/json";}
  return fetch(path,opts).then(function(r){
    if(r.status===401){localStorage.removeItem("oc_key");location.reload();throw new Error("unauthorized");}
    return r.json();
  });
}

// --- rendering helpers ---
function esc(s){var d=document.createElement("div");d.textContent=s;return d.innerHTML;}
function md(s){
  var out=esc(s);
  out=out.replace(/\\u0060\\u0060\\u0060([\\s\\S]*?)\\u0060\\u0060\\u0060/g,function(m,c){return "<pre><code>"+c.replace(/^\\w*\\n/,"")+"</code></pre>";});
  out=out.replace(/\\u0060([^\\u0060\\n]+)\\u0060/g,"<code>$1</code>");
  out=out.replace(/\\*\\*([^*\\n]+)\\*\\*/g,"<b>$1</b>");
  out=out.replace(/\\n/g,"<br>");
  out=out.replace(/<pre><code>([\\s\\S]*?)<\\/code><\\/pre>/g,function(m,c){return "<pre><code>"+c.replace(/<br>/g,"\\n")+"</code></pre>";});
  return out;
}
function rel(ts){
  var d=Date.now()-ts;
  if(d<60000)return "just now";
  if(d<3600000)return Math.floor(d/60000)+"m ago";
  if(d<86400000)return Math.floor(d/3600000)+"h ago";
  return Math.floor(d/86400000)+"d ago";
}

// --- busy state (synced from server; server is the source of truth) ---
function syncBusy(list){
  (list||[]).forEach(function(s){busyMap[s.id]=!!s.busy;});
  if(cur)setBusy(!!busyMap[cur]);
}
function setBusy(on){
  if(cur)busyMap[cur]=on;
  var show=!!on&&view==="chat";
  $("typing").classList.toggle("hidden",!show);
  $("abortBtn").style.display=show?"flex":"none";
  if(show)$("main").scrollTop=$("main").scrollHeight;
}
function checkVersion(){
  fetch("/version").then(function(r){return r.json()}).then(function(v){
    if(v.uiVersion&&v.uiVersion!==UIV)location.reload();
  }).catch(function(){});
}
function resync(){
  if(!KEY)return;
  api("/api/sessions").then(function(list){
    sessions=list;syncBusy(list);
    if(view==="list")renderSessions();
  }).catch(function(){});
  if(view==="chat")loadMessages();
}

// --- views ---
function showList(){
  view="list";cur=null;
  $("backBtn").style.display="none";
  $("logoBox").style.display="flex";
  $("title").textContent="opencode";
  $("messages").classList.add("hidden");
  $("typing").classList.add("hidden");
  $("sessionList").classList.remove("hidden");
  $("newBtnWrap").classList.remove("hidden");
  $("composer").classList.remove("on");
  renderPermBanner();
  loadSessions();
}
function showChat(s){
  view="chat";cur=s.id;curDir=s.directory;
  $("backBtn").style.display="flex";
  $("logoBox").style.display="none";
  $("title").textContent=s.title||"(untitled)";
  $("sessionList").classList.add("hidden");
  $("newBtnWrap").classList.add("hidden");
  $("messages").classList.remove("hidden");
  $("messages").innerHTML="<div class='tool'>loading…</div>";
  $("composer").classList.add("on");
  setBusy(!!busyMap[s.id]);
  renderPermBanner();
  loadMessages();
}
function renderSessions(){
  var el=$("sessionList");el.innerHTML="";
  var hd=document.createElement("div");hd.className="secthead";hd.textContent="Sessions";el.appendChild(hd);
  var shown=0;
  sessions.forEach(function(s){
    if(s.parentID)return;
    shown++;
    var b=document.createElement("button");
    b.className="sess";
    var liveHtml=s.busy?"<span class='live'><i></i><i></i><i></i></span>":"";
    b.innerHTML=liveHtml+"<div class='t'>"+esc(s.title||"(untitled)")+"</div><div class='m'><span class='when'>"+rel(s.updated)+"</span><span class='dir'>"+esc((s.directory||"").split("/").slice(-2).join("/"))+"</span></div>";
    b.onclick=function(){showChat(s)};
    el.appendChild(b);
  });
  if(!shown){el.innerHTML="<div class='empty'><div class='big'>📟</div>No sessions yet.<br>Create one below or start opencode in a project.</div>";}
}
function loadSessions(){
  if(!KEY)return;
  api("/api/sessions").then(function(list){
    sessions=list;syncBusy(list);renderSessions();
  }).catch(function(){});
}
function loadMessages(){
  if(!cur)return;
  api("/api/session/"+cur+"/messages?limit=150").then(function(msgs){
    var el=$("messages");el.innerHTML="";
    msgs.forEach(function(m){
      var info=m.info,parts=m.parts||[];
      var textHtml="";
      parts.forEach(function(p){
        if(p.type==="text"&&p.text&&!p.synthetic){textHtml+=md(p.text);}
        else if(p.type==="tool"){
          var chip=document.createElement("div");
          chip.className="tool";chip.textContent="🔧 "+(p.tool||"tool");
          el.appendChild(chip);
        }
      });
      if(!textHtml)return;
      var wrap=document.createElement("div");
      wrap.className="msg "+(info.role==="user"?"user":"assistant");
      wrap.innerHTML=textHtml;
      el.appendChild(wrap);
    });
    $("main").scrollTop=$("main").scrollHeight;
  }).catch(function(){});
}
function renderPermBanner(){
  var p=perms.find(function(x){return view!=="chat"||x.sessionID===cur;});
  if(p){
    $("permTitle").textContent="🔐 "+p.title;
    $("permBanner").classList.add("on");
    $("permBanner").dataset.pid=p.id;
    $("permBanner").dataset.sid=p.sessionID;
  }else{
    $("permBanner").classList.remove("on");
  }
}
function respondPerm(response){
  var pid=$("permBanner").dataset.pid,sid=$("permBanner").dataset.sid;
  if(!pid)return;
  api("/api/session/"+sid+"/permission/"+pid,{method:"POST",body:JSON.stringify({response:response})})
    .then(function(){perms=perms.filter(function(x){return x.id!==pid});renderPermBanner();})
    .catch(function(){});
}

function alertUser(){
  try{if(navigator.vibrate)navigator.vibrate([120,60,120]);}catch(e){}
  document.body.classList.remove("flash");void document.body.offsetWidth;document.body.classList.add("flash");
}

// --- SSE live events ---
function connectSSE(){
  if(!KEY)return;
  if(es)es.close();
  es=new EventSource("/api/events?key="+encodeURIComponent(KEY));
  es.onopen=function(){$("connDot").classList.add("on");resync();checkVersion();};
  es.onerror=function(){$("connDot").classList.remove("on");setTimeout(connectSSE,4000);if(es)es.close();es=null;};
  es.onmessage=function(e){
    var ev;try{ev=JSON.parse(e.data)}catch(err){return;}
    var props=ev.properties||{};
    if(ev.type==="message.updated"||ev.type==="message.part.updated"){
      var info=props.info||{};
      var sid=(info.sessionID)||(props.part&&props.part.sessionID)||props.sessionID;
      if(sid&&sid===cur){
        if(refetchT)clearTimeout(refetchT);
        refetchT=setTimeout(loadMessages,450);
      }
    }
    if(ev.type==="session.status"){
      var ssid=props.sessionID,st=props.status;
      if(ssid&&st){
        var b=st.type!=="idle";
        busyMap[ssid]=b;
        sessions.forEach(function(x){if(x.id===ssid)x.busy=b;});
        if(ssid===cur)setBusy(b);
        if(view==="list")renderSessions();
      }
    }
    if(ev.type==="session.idle"){
      var sid2=props.sessionID;
      if(sid2){busyMap[sid2]=false;if(sid2===cur){setBusy(false);loadMessages();}alertUser();}
      if(view==="list")loadSessions();
    }
    if(ev.type==="session.updated"||ev.type==="session.created"){
      if(view==="list")loadSessions();
    }
    if(ev.type==="permission.updated"){
      if(props.id){perms=perms.filter(function(x){return x.id!==props.id});perms.push({id:props.id,sessionID:props.sessionID,title:props.title||props.type||"Permission",type:props.type});renderPermBanner();alertUser();}
    }
    if(ev.type==="permission.replied"){
      perms=perms.filter(function(x){return x.id!==props.permissionID});renderPermBanner();
    }
    if(ev.type==="session.error"){
      if(props.sessionID){busyMap[props.sessionID]=false;if(props.sessionID===cur)setBusy(false);}
    }
  };
}

// resync whenever the app comes back to foreground (phone lock, tab switch)
document.addEventListener("visibilitychange",function(){
  if(document.visibilityState!=="visible"||!KEY)return;
  if(!es||es.readyState===2)connectSSE();
  resync();
});
// watchdog: while a session looks busy, double-check with the server every 6s
setInterval(function(){
  if(document.visibilityState!=="visible"||!KEY)return;
  if(cur&&busyMap[cur]){api("/api/sessions").then(syncBusy).catch(function(){});}
},6000);

// --- push notifications ---
function urlB64(b64){
  var pad="=".repeat((4-b64.length%4)%4);
  var base=(b64+pad).replace(/-/g,"+").replace(/_/g,"/");
  var raw=atob(base);var arr=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++)arr[i]=raw.charCodeAt(i);
  return arr;
}
function setupPush(){
  if(!KEY)return;
  if(!window.isSecureContext||!("serviceWorker" in navigator)||!("PushManager" in window)){
    if(!localStorage.getItem("oc_note_dismissed"))$("pushNote").classList.remove("hidden");
    return;
  }
  navigator.serviceWorker.register("/sw.js").then(function(reg){
    $("bellBtn").classList.remove("hidden");
    $("bellBtn").onclick=function(){
      Notification.requestPermission().then(function(perm){
        if(perm!=="granted")return;
        api("/api/push/vapid").then(function(v){
          if(!v.publicKey)return;
          reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlB64(v.publicKey)}).then(function(sub){
            api("/api/push/subscribe",{method:"POST",body:JSON.stringify(sub.toJSON())}).then(function(){
              $("bellBtn").textContent="✅";
            });
          });
        });
      });
    };
    reg.pushManager.getSubscription().then(function(sub){if(sub)$("bellBtn").textContent="✅";});
  }).catch(function(){});
}

// --- wire up ---
$("backBtn").onclick=showList;
$("refreshBtn").onclick=function(){resync()};
$("newBtn").onclick=function(){
  api("/api/session/new",{method:"POST",body:JSON.stringify({})}).then(function(s){
    if(s&&s.id)showChat({id:s.id,title:s.title||"new session",directory:s.directory});
  });
};
$("noteX").onclick=function(){localStorage.setItem("oc_note_dismissed","1");$("pushNote").classList.add("hidden");};
$("outBtn").onclick=function(){
  if(!KEY){location.reload();return;}
  if(!confirm("Disconnect this phone from opencode?"))return;
  var all=confirm("Also revoke ALL paired devices?\\n\\nOK = revoke everyone (new QR needed)\\nCancel = only this phone");
  var bye=function(){
    try{localStorage.removeItem("oc_key");}catch(e){}
    if("serviceWorker" in navigator){navigator.serviceWorker.getRegistration().then(function(r){
      if(r)r.pushManager.getSubscription().then(function(s){if(s)s.unsubscribe();});
    });}
    setTimeout(function(){location.reload();},300);
  };
  if(all){api("/api/revoke",{method:"POST",body:"{}"}).then(bye).catch(bye);}else{bye();}
};
$("pbOnce").onclick=function(){respondPerm("once")};
$("pbAlways").onclick=function(){respondPerm("always")};
$("pbReject").onclick=function(){respondPerm("reject")};
$("sendBtn").onclick=function(){
  var t=$("input").value.trim();
  if(!t||!cur)return;
  $("input").value="";$("input").style.height="auto";
  var el=$("messages");
  var b=document.createElement("div");b.className="msg user";b.innerHTML=md(t);el.appendChild(b);
  $("main").scrollTop=$("main").scrollHeight;
  setBusy(true);
  api("/api/session/"+cur+"/prompt",{method:"POST",body:JSON.stringify({text:t})}).catch(function(){setBusy(false)});
};
$("abortBtn").onclick=function(){
  if(!cur)return;
  api("/api/session/"+cur+"/abort",{method:"POST",body:"{}"}).then(function(){setBusy(false)});
};
$("input").addEventListener("input",function(){this.style.height="auto";this.style.height=Math.min(this.scrollHeight,120)+"px";});

if(KEY){
  showList();
  connectSSE();
  setupPush();
  api("/api/permissions").then(function(p){perms=p;renderPermBanner();}).catch(function(){});
}
})();
</script>
</body>
</html>`
