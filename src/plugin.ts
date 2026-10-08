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
  res.writeHead(code, { "Content-Type": type, "Access-Control-Allow-Origin": "*" })
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
      if (p === "/sw.js") return sendText(res, 200, "application/javascript", SW_JS)
      if (p === "/manifest.webmanifest") return sendText(res, 200, "application/manifest+json", MANIFEST)
      if (p === "/icon.svg") return sendText(res, 200, "image/svg+xml", ICON_SVG)
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
        const connectURL = (tunnelURL ?? "http://" + lanIP() + ":" + port) + "/?key=" + state.token
        return sendText(res, 200, "text/html; charset=utf-8", qrPage(connectURL, tunnelURL !== null))
      }
      if (p === "/api/state" && req.method === "GET") {
        const list = await refreshSessions()
        return sendJSON(res, 200, {
          ok: true,
          directory,
          baseUrl: tunnelURL ?? "http://" + lanIP() + ":" + port,
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
    "<p>" + (viaTunnel ? "Secure tunnel active — works from anywhere, push notifications enabled." : "Works on the same WiFi as this Mac. Tip: <b>brew install cloudflared</b> then restart opencode for access from anywhere + push notifications.") + "</p>" +
    "<p><code>" + safe + "</code></p>" +
    "<script src='/vendor/qrcode.js'></script>" +
    "<script>try{var qr=qrcode(0,'M');qr.addData(\"" + safe + "\");qr.make();document.getElementById('qr').innerHTML=qr.createSvgTag({cellSize:7,margin:0});}catch(e){document.getElementById('qr').textContent='QR lib missing — type the URL below manually';}</script>" +
    "</body></html>"
  )
}

const ICON_SVG =
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='22' fill='#0d1117'/><text x='50' y='64' font-size='46' text-anchor='middle' fill='#e6edf3' font-family='monospace'>oc</text><circle cx='78' cy='24' r='10' fill='#3fb950'/></svg>"

const MANIFEST = JSON.stringify({
  name: "opencode remote",
  short_name: "opencode",
  start_url: "/",
  display: "standalone",
  background_color: "#0d1117",
  theme_color: "#0d1117",
  icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }],
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
<link rel="apple-touch-icon" href="/icon.svg">
<style>
:root{--bg:#0a0c10;--panel:#12151c;--card:#151a23;--card2:#1b212c;--border:#232b38;--fg:#e9edf4;--dim:#8a94a6;--dim2:#5c6678;--acc:#5b8cff;--acc2:#7c5cff;--green:#34d399;--red:#f87171;--amber:#fbbf24}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;font-size:15px;overscroll-behavior:none}
#app{display:flex;flex-direction:column;height:100dvh}
header{display:flex;align-items:center;gap:10px;padding:calc(env(safe-area-inset-top) + 12px) 16px 12px;background:rgba(10,12,16,.88);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
header .back{display:none;width:32px;height:32px;border-radius:10px;font-size:20px;line-height:1;color:var(--fg);background:var(--card);border:1px solid var(--border);align-items:center;justify-content:center}
.logo{width:28px;height:28px;border-radius:9px;background:linear-gradient(135deg,var(--acc),var(--acc2));display:flex;align-items:center;justify-content:center;font-family:ui-monospace,Menlo,monospace;font-size:12px;font-weight:700;color:#fff;flex-shrink:0}
header h1{font-size:16px;font-weight:650;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:-.01em}
header .dot{width:8px;height:8px;border-radius:50%;background:var(--red);flex-shrink:0;transition:background .3s}
header .dot.on{background:var(--green);box-shadow:0 0 0 0 rgba(52,211,153,.5);animation:pulse 2.4s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.45)}70%{box-shadow:0 0 0 7px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
header button.icon{background:var(--card);border:1px solid var(--border);color:var(--fg);border-radius:10px;width:34px;height:34px;font-size:15px;display:flex;align-items:center;justify-content:center}
main{flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch}
.hidden{display:none!important}
/* session list */
#sessionList{padding:10px 0 4px}
#sessionList .sess{display:block;width:calc(100% - 24px);margin:0 12px 10px;text-align:left;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:14px 16px;color:var(--fg);transition:transform .08s,background .15s;position:relative}
#sessionList .sess:active{transform:scale(.98);background:var(--card2)}
.sess .t{font-weight:600;font-size:15px;margin-bottom:6px;line-height:1.3;padding-right:34px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sess .m{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.sess .when{color:var(--dim2);font-size:12px}
.sess .dir{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--dim);background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:2px 9px;max-width:60%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sess .live{position:absolute;top:16px;right:14px;display:flex;gap:3px}
.sess .live i{width:5px;height:5px;border-radius:50%;background:var(--green);animation:blink 1.2s infinite ease-in-out}
.sess .live i:nth-child(2){animation-delay:.2s}.sess .live i:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,80%,100%{opacity:.25}40%{opacity:1}}
#newBtnWrap{padding:4px 12px 20px}
.bigbtn{width:100%;padding:14px;border-radius:16px;border:none;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;font-size:15px;font-weight:650;transition:transform .08s,opacity .15s}
.bigbtn:active{transform:scale(.98);opacity:.85}
/* chat */
#messages{padding:14px 12px 4px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:88%;padding:10px 14px;line-height:1.5;word-wrap:break-word;overflow-wrap:break-word;font-size:14.5px}
.msg.user{align-self:flex-end;background:linear-gradient(135deg,#3b6fe0,#6d4fe0);color:#fff;border-radius:18px 18px 6px 18px}
.msg.assistant{align-self:flex-start;background:var(--card);border:1px solid var(--border);border-radius:18px 18px 18px 6px}
.msg pre{background:#0a0d13;border:1px solid var(--border);border-radius:10px;padding:10px;overflow-x:auto;font-size:12.5px;margin:8px 0;line-height:1.45}
.msg code{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;background:rgba(0,0,0,.35);padding:1px 6px;border-radius:6px}
.msg.assistant code{background:#0a0d13}
.msg pre code{background:none;padding:0}
.tool{align-self:flex-start;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--dim);background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:3px 11px;max-width:88%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
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
#composer textarea{flex:1;background:var(--card);border:1px solid var(--border);border-radius:21px;color:var(--fg);padding:11px 16px;font-size:15px;font-family:inherit;resize:none;max-height:120px;min-height:42px;line-height:1.35}
#composer textarea:focus{outline:none;border-color:var(--acc)}
#composer button{border:none;border-radius:50%;width:42px;height:42px;font-weight:700;font-size:17px;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:transform .08s}
#composer button:active{transform:scale(.9)}
#sendBtn{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
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
    <div class="logo" id="logoBox">oc</div>
    <h1 id="title">opencode</h1>
    <span class="dot" id="connDot" title="live connection"></span>
    <button class="icon hidden" id="bellBtn">🔔</button>
    <button class="icon" id="refreshBtn">↻</button>
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
    <button id="sendBtn">↑</button>
  </div>
</div>
<script>
(function(){
"use strict";
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
  es.onopen=function(){$("connDot").classList.add("on");resync();};
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
