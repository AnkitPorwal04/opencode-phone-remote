# opencode-phone-remote

Control any [opencode](https://opencode.ai) session from your phone. Scan a QR code, send prompts, watch answers stream in live, approve permission requests, and get push alerts when the agent finishes or needs you.

No app install — it's a PWA served directly by the plugin. Everything runs on your machine; your phone talks to opencode over your own network.

## Features

- **QR pairing** — type `/remote` in the opencode TUI (or run `qr.sh`) and scan with your phone camera
- **Full session control** — list sessions, create new ones, send prompts, abort runs
- **Live answers** — responses stream to your phone in real time (SSE), with an accurate busy indicator
- **Permission approvals** — approve/reject tool permission requests (Once / Always / Reject) from the phone
- **Alerts** — web push notifications on `session.idle` (agent finished), permission requests, and session errors
- **Works with every opencode instance** — the plugin auto-starts with each one; the TUI and your phone share the same session state
- **Secure by default** — 48-hex random token, timing-safe comparison, all API routes gated; token lives only on your machine and in the QR

## Install

### Option A — npm plugin (one line)

Add to `~/.config/opencode/opencode.json`:

```json
{
  "plugin": ["opencode-phone-remote"]
}
```

Restart opencode. This installs the phone server + PWA + alerts.

For the instant `/remote` QR command in the TUI, also add to `~/.config/opencode/tui.json`:

```json
{
  "$schema": "https://opencode.ai/tui.json",
  "plugin": ["opencode-phone-remote/tui"]
}
```

### Option B — install script

```sh
git clone https://github.com/AnkitPorwal04/opencode-phone-remote.git
cd opencode-phone-remote
./install.sh
```

Copies the plugins into `~/.config/opencode/` and wires up `tui.json` for you.

## Usage

1. Restart opencode (any project).
2. Type `/remote` (alias `/qr`) in the TUI — a QR dialog appears instantly.
3. Scan it with your phone camera and open the link.
4. You're in: pick a session, prompt it, watch the answer arrive.

Other ways to connect:

- `~/.config/opencode/remote-control/qr.sh` — opens the QR page in your browser
- `~/.config/opencode/remote-control/last-url.txt` — plain-text connect URL + ASCII QR

## Alerts / push notifications

In-app alerts work out of the box over your LAN.

Browser **push** notifications (screen-off alerts) require HTTPS. Install [cloudflared](https://developers.cloudflare.com/cloudflare-tunnel/) and the plugin automatically opens a tunnel, upgrades the QR to an HTTPS URL, and enables push — plus you can then control sessions from anywhere, not just your WiFi:

```sh
brew install cloudflared   # macOS
```

Then tap the bell icon on the phone UI to subscribe.

## How it works

- A tiny HTTP server (Node `http`, ports 7777–7787) starts inside each opencode process via the plugin API
- It proxies to opencode's own server API (`prompt_async`, messages, permissions, `/event` SSE)
- The phone UI is a single embedded PWA — dark theme, chat bubbles, tool chips, typing indicator
- State (token, VAPID keys, push subscriptions) lives in `~/.config/opencode/remote-control/state.json`

### Architecture

```mermaid
flowchart LR
    subgraph Phone["📱 Your Phone"]
        PWA["PWA (embedded web app)<br/>chat UI · sessions · permissions"]
        SW["Service Worker<br/>web-push notifications"]
    end

    subgraph Mac["💻 Your Computer — opencode process"]
        subgraph Plugin["remote-control plugin"]
            HTTP["HTTP server<br/>ports 7777–7787<br/>token auth (SHA-256)"]
            SSE["SSE broadcaster<br/>/api/events"]
            PUSH["web-push sender<br/>(VAPID)"]
            QR["QR / URL generator<br/>last-url.txt · qr.sh · /remote"]
        end
        CORE["opencode core server<br/>sessions · messages · permissions<br/>/event bus"]
        TUI["opencode TUI<br/>(same process, live view)"]
    end

    CF["☁️ cloudflared tunnel<br/>(optional, HTTPS)"]

    PWA -- "REST: prompt / messages /<br/>abort / permissions" --> HTTP
    HTTP -- "SDK client calls" --> CORE
    CORE -- "event bus<br/>(session.status, message.updated,<br/>permission.updated …)" --> SSE
    SSE -- "live stream" --> PWA
    PUSH -- "push notification<br/>(idle · permission · error)" --> SW
    CORE <--> TUI
    PWA -. "same WiFi (HTTP)" .-> HTTP
    PWA -. "anywhere (HTTPS)" .-> CF -.-> HTTP
    QR -- "scan to connect" --> PWA
```

### Prompt round-trip (what happens when you send a message)

```mermaid
sequenceDiagram
    autonumber
    participant P as 📱 Phone PWA
    participant RC as 🔌 Plugin server (7777)
    participant OC as ⚙️ opencode core
    participant LLM as 🤖 Model
    participant TUI as 🖥️ TUI

    P->>RC: POST /api/session/:id/prompt (Bearer token)
    RC->>RC: verify token (timingSafeEqual)
    RC->>OC: promptAsync(parts) — fire & forget
    RC-->>P: 202 accepted
    OC->>LLM: run the agent
    OC-->>TUI: message appears live in terminal too
    loop while the agent works
        OC-->>RC: event bus: message.part.updated / session.status busy
        RC-->>P: SSE → typing dots + live refresh
    end
    OC-->>RC: session.status idle + session.idle
    RC-->>P: SSE → busy cleared, final answer rendered
    RC-->>P: 🔔 web-push "Session finished" (if subscribed)
```

### Permission approval flow

```mermaid
sequenceDiagram
    autonumber
    participant OC as ⚙️ opencode core
    participant RC as 🔌 Plugin server
    participant P as 📱 Phone

    OC-->>RC: event: permission.updated (agent wants to run a tool)
    RC-->>P: SSE → amber banner appears
    RC-->>P: 🔔 push "Permission needed"
    P->>RC: POST /api/session/:id/permission/:pid {once | always | reject}
    RC->>OC: permission response
    OC->>OC: agent continues (or aborts)
    OC-->>RC: event: permission.replied
    RC-->>P: SSE → banner dismissed
```

### Connection & pairing flow

```mermaid
flowchart TD
    A["opencode starts"] --> B["plugin auto-loads from<br/>~/.config/opencode/plugin/"]
    B --> C["bind first free port 7777–7787<br/>on 0.0.0.0"]
    C --> D{"cloudflared<br/>installed?"}
    D -- yes --> E["start quick tunnel<br/>→ https://xxx.trycloudflare.com"]
    D -- no --> F["LAN only<br/>http://192.168.x.x:PORT"]
    E --> G["write last-url.txt + qr.sh<br/>+ ASCII QR"]
    F --> G
    G --> H["type /remote in TUI<br/>→ QR dialog"]
    H --> I["scan QR with phone camera"]
    I --> J["URL carries ?key=TOKEN<br/>→ stored in localStorage,<br/>stripped from URL bar"]
    J --> K["📱 connected — full remote control"]
    K --> L{"⏻ disconnect?"}
    L -- "this phone" --> M["clear local key"]
    L -- "revoke ALL" --> N["POST /api/revoke<br/>→ new token minted,<br/>all phones + push subs dropped,<br/>new QR generated"]
```

## Security

- Every API route requires the token (`?key=` or `Bearer`), compared with SHA-256 + `timingSafeEqual`
- The QR code *is* the password — only show it to yourself
- To rotate the token: delete `~/.config/opencode/remote-control/state.json` and restart opencode
- Without cloudflared, traffic is plain HTTP on your LAN — fine at home, use the tunnel on untrusted networks

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Phone can't connect | Phone and computer must be on the same WiFi (or use cloudflared) |
| 401 unauthorized | Re-scan the QR; token may have rotated |
| `/remote` not found | Restart opencode; check `tui.json` has the plugin entry |
| No push notifications | Push needs HTTPS — install cloudflared and re-subscribe via the bell |
| Port already in use | The plugin tries 7777–7787 automatically; each instance gets its own port |

## License

MIT
