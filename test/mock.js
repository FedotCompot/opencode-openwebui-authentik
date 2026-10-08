const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url")
const jwt = (claims) => `${b64({ alg: "RS256", kid: "k" })}.${b64(claims)}.sig`

export function createMocks() {
  const state = {
    deviceScript: ["authorization_pending", "ok"],
    deviceInterval: 5,
    deviceExpiresIn: 600,
    devices: new Map(),
    cliAccess: new Set(),
    refresh: new Map(),
    proxy: new Set(),
    owuiTokens: new Set(),
    mintFail: false,
    refreshDelayMs: 0,
    offline: true,
    outpostDown: false,
    userinfoDown: false,
    counts: { discover: 0, device: 0, poll: 0, refresh: 0, mint: 0, signin: 0, chat: 0, userinfo: 0 },
    log: [],
    seq: 0,
  }
  const id = (prefix) => `${prefix}-${++state.seq}`
  const json = (body, status = 200) => Response.json(body, { status })
  const err = (error, status = 400) => json({ error, error_description: `${error} desc` }, status)

  const issueCli = () => {
    const access = jwt({ sub: "u1", email: "user@example.com", exp: Math.floor(Date.now() / 1000) + 300, n: ++state.seq })
    state.cliAccess.add(access)
    const body = { access_token: access, token_type: "Bearer", expires_in: 300, scope: "openid email profile offline_access" }
    if (state.offline) {
      const refresh = id("rt")
      state.refresh.set(refresh, { revoked: false })
      body.refresh_token = refresh
    }
    return body
  }

  const authentik = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url)
      const form = req.method === "POST" ? new URLSearchParams(await req.text()) : new URLSearchParams()
      state.log.push({ path: url.pathname, form: Object.fromEntries(form) })
      if (url.pathname === "/application/o/device/") {
        state.counts.device++
        if (form.get("client_id") !== "cli-client") return err("invalid_client")
        const code = id("dc")
        state.devices.set(code, { script: [...state.deviceScript] })
        return json({
          device_code: code,
          verification_uri: `${url.origin}/device`,
          verification_uri_complete: `${url.origin}/device?code=USER-${code}`,
          user_code: `USER-${code}`,
          expires_in: state.deviceExpiresIn,
          interval: state.deviceInterval,
        })
      }
      if (url.pathname === "/flow")
        return new Response("<!doctype html><html>authentik login</html>", { headers: { "content-type": "text/html; charset=utf-8" } })
      if (url.pathname === "/application/o/userinfo/") {
        state.counts.userinfo++
        if (state.userinfoDown) return new Response("unavailable", { status: 503 })
        const auth = req.headers.get("authorization") ?? ""
        if (auth.startsWith("Bearer ") && state.proxy.has(auth.slice(7))) return json({ sub: "u1", email: "user@example.com" })
        return new Response(null, { status: 401, headers: { "www-authenticate": 'Bearer error="invalid_token"' } })
      }
      if (url.pathname !== "/application/o/token/") return new Response("nope", { status: 404 })
      const grant = form.get("grant_type")
      if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
        state.counts.poll++
        if (form.get("client_id") !== "cli-client") return err("invalid_client")
        const device = state.devices.get(form.get("device_code"))
        if (!device) return err("invalid_grant")
        const step = device.script.shift() ?? "authorization_pending"
        if (step !== "ok") return err(step)
        state.devices.delete(form.get("device_code"))
        return json(issueCli())
      }
      if (grant === "refresh_token") {
        state.counts.refresh++
        if (state.refreshDelayMs) await Bun.sleep(state.refreshDelayMs)
        const rt = state.refresh.get(form.get("refresh_token"))
        if (form.get("client_id") !== "cli-client" || !rt || rt.revoked) return err("invalid_grant")
        rt.revoked = true
        return json(issueCli())
      }
      if (grant === "client_credentials") {
        state.counts.mint++
        if (form.get("client_id") !== "proxy-client") return err("invalid_client")
        if (form.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
          return err("invalid_grant")
        if (!state.cliAccess.has(form.get("client_assertion"))) return err("invalid_grant")
        if (form.get("scope") !== "openid email profile ak_proxy") return err("invalid_scope")
        if (state.mintFail) return err("invalid_grant")
        const access = jwt({ sub: "u1", email: "user@example.com", n: ++state.seq })
        state.proxy.add(access)
        return json({ access_token: access, token_type: "Bearer", expires_in: 43200, scope: "openid email profile ak_proxy" })
      }
      return err("unsupported_grant_type")
    },
  })

  const sse = (text) =>
    [
      `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index: 0, delta: { role: "assistant", content: text }, finish_reason: null }] })}`,
      `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}`,
      "data: [DONE]",
      "",
      "",
    ].join("\n\n")

  const forwardAuth = (req) => {
    const auth = req.headers.get("authorization") ?? ""
    return !state.outpostDown && auth.startsWith("Bearer ") && state.proxy.has(auth.slice(7))
  }

  const openwebui = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url)
      if (!forwardAuth(req)) {
        if (url.pathname === "/" && req.method === "GET") {
          state.counts.discover++
          const location = state.discoverLocation ?? `${authentik.url.origin}/application/o/authorize/?client_id=proxy-client&response_type=code`
          return new Response(null, { status: 302, headers: { location } })
        }
        return new Response(null, { status: 302, headers: { location: `${authentik.url.origin}/flow` } })
      }
      if (url.pathname === "/api/v1/auths/signin" && req.method === "POST") {
        state.counts.signin++
        const body = await req.json()
        if (body.email !== "" || body.password !== "") return json({ detail: "bad form" }, 422)
        const token = jwt({ id: "owui-user", n: ++state.seq })
        state.owuiTokens.add(token)
        return json({ token, token_type: "Bearer", expires_at: Math.floor(Date.now() / 1000) + 2419200 })
      }
      if (url.pathname === "/api/chat/completions") {
        state.counts.chat++
        const token = req.headers.get("x-open-webui-token")
        state.log.push({ path: url.pathname, owui: token })
        if (!token || !state.owuiTokens.has(token)) return json({ detail: "Invalid token" }, 401)
        return new Response(sse("pong from mock"), { headers: { "content-type": "text/event-stream" } })
      }
      if (url.pathname === "/api/models") return json({ data: [{ id: "m", object: "model" }] })
      return json({ detail: "not found" }, 404)
    },
  })

  return { state, authentik, openwebui, jwt, stop: () => (authentik.stop(true), openwebui.stop(true)) }
}
