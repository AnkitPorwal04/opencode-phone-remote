// TUI companion for the remote-control server plugin.
// Registers /remote — instantly shows the connect QR in a dialog (no LLM round-trip).
import type { TuiPlugin, TuiPluginModule } from "@opencode-ai/plugin/tui"
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

const RC_DIR = join(homedir(), ".config", "opencode", "remote-control")
const PORT_START = 7777
const PORT_END = 7787

type RcState = { token?: string }

function readToken(): string | undefined {
  try {
    const state = JSON.parse(readFileSync(join(RC_DIR, "state.json"), "utf8")) as RcState
    return state.token
  } catch {
    return undefined
  }
}

async function findLiveServer(token: string): Promise<{ baseUrl: string; tunnelUrl?: string } | undefined> {
  const probes = []
  for (let port = PORT_START; port <= PORT_END; port++) {
    probes.push(
      fetch(`http://127.0.0.1:${port}/api/state?key=${token}`, { signal: AbortSignal.timeout(600) })
        .then(async (res) => {
          if (!res.ok) return undefined
          const data = (await res.json()) as { baseUrl?: string; lanUrl?: string; tunnelUrl?: string }
          const stable = data.lanUrl ?? data.baseUrl
          return stable ? { baseUrl: stable, tunnelUrl: data.tunnelUrl ?? undefined } : undefined
        })
        .catch(() => undefined),
    )
  }
  const results = await Promise.all(probes)
  return results.find((r) => r !== undefined)
}

async function buildQr(url: string): Promise<string | undefined> {
  try {
    const mod = await import("qrcode-generator")
    const qrcode = (mod as { default?: unknown }).default ?? mod
    const qr = (qrcode as (typeNumber: number, level: string) => {
      addData(data: string): void
      make(): void
      createASCII(cellSize?: number, margin?: number): string
    })(0, "M")
    qr.addData(url)
    qr.make()
    return qr.createASCII(1, 1)
  } catch {
    return undefined
  }
}

const tui: TuiPlugin = async (api) => {
  const show = (title: string, message: string) => {
    api.ui.dialog.replace(() => api.ui.DialogAlert({ title, message }))
    api.ui.dialog.setSize("large")
  }

  const open = () => {
    const token = readToken()
    if (!token) {
      show("Remote Control", "Not initialized yet.\nRestart opencode to start the remote-control server.")
      return
    }
    void (async () => {
      const live = await findLiveServer(token)
      if (!live) {
        show(
          "Remote Control",
          "Server not reachable on ports 7777-7787.\nRestart opencode, then run /remote again.",
        )
        return
      }
      const connectUrl = `${live.baseUrl}/?key=${token}`
      const qr = await buildQr(connectUrl)
      const away = live.tunnelUrl ? `\n\nAway from home (changes each restart):\n${live.tunnelUrl}/?key=${token}` : ""
      const body = qr
        ? `Scan with your phone camera (stable home-WiFi link):\n\n${qr}\n${connectUrl}${away}`
        : `Open this on your phone:\n\n${connectUrl}${away}`
      show("Remote Control", body)
    })()
  }

  api.command.register(() => [
    {
      title: "Remote Control: Show QR",
      value: "remote.qr",
      description: "Connect your phone",
      category: "Remote",
      slash: { name: "remote", aliases: ["qr"] },
      onSelect: open,
    },
  ])
}

const plugin: TuiPluginModule & { id: string } = {
  id: "remote-control-tui",
  tui,
}

export default plugin
