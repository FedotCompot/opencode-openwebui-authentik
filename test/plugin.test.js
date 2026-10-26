import { afterAll, afterEach, beforeEach, describe, expect, test } from "bun:test"
import plugin from "../index.js"
import { createMocks } from "./mock.js"

const realNow = Date.now
let clockOffset = 0
Date.now = () => realNow() + clockOffset

const realSetTimeout = globalThis.setTimeout
const delays = []
globalThis.setTimeout = (fn, ms, ...args) => {
  if (ms < 1000) return realSetTimeout(fn, ms, ...args)
  delays.push(ms)
  return realSetTimeout(() => {
    clockOffset += ms
    fn(...args)
  }, ms / 1000)
}

const mocks = createMocks()
afterAll(() => mocks.stop())

const FIVE_MINUTES = 5 * 60 * 1000

const CONFIGURED_MODELS = {
  openwebui: { m: { name: "configured m", limit: { context: 1000 } }, gone: { name: "gone" } },
}

const marked = (id = "openwebui", marker = true, baseURL = `${mocks.openwebui.url.origin}/api`) => ({
  id,
  settings: { baseURL, openwebuiAuthentik: marker },
})

// mirrors opencode core integration semantics
function fakeCtx(options, providerList = [marked()]) {
  const integrations = new Map()
  const integrationTransforms = []
  const credentials = []
  const hooks = { "http.request": [], "http.response": [], retry: [] }
  const statuses = []
  const editor = {
    list: () => [...integrations.keys()].map((id) => ({ id, name: id })),
    get: (id) => (integrations.has(id) ? { id, name: id } : undefined),
    update: () => {},
    remove: (id) => integrations.delete(id),
    method: {
      list: (id) => integrations.get(id)?.methods ?? [],
      update: (input) => {
        const entry = integrations.get(input.integrationID) ?? { methods: [], impl: new Map() }
        integrations.set(input.integrationID, entry)
        const index = entry.methods.findIndex((m) => m.type === input.method.type && m.id === input.method.id)
        if (index === -1) entry.methods.push(input.method)
        else entry.methods[index] = input.method
        if (input.method.type === "oauth") entry.impl.set(input.method.id, input)
      },
      remove: (id, method) => {
        const entry = integrations.get(id)
        if (!entry) return
        const index = entry.methods.findIndex(
          (m) => m.type === method.type && (method.type !== "oauth" || m.id === method.id),
        )
        if (index !== -1) entry.methods.splice(index, 1)
      },
    },
  }
  const rebuildIntegrations = () => {
    integrations.clear()
    for (const { id } of providerList)
      integrations.set(id, { methods: [{ type: "key", label: "Manually enter API Key" }], impl: new Map() })
    for (const transform of integrationTransforms) transform(editor)
  }
  rebuildIntegrations()
  const modelTransforms = []
  const providers = new Map()
  const reloads = { count: 0 }
  const rebuild = () => {
    providers.clear()
    for (const [id, models] of Object.entries(CONFIGURED_MODELS))
      providers.set(
        id,
        new Map(Object.entries(models).map(([model, info]) => [model, { id: model, ...structuredClone(info) }])),
      )
    const modelEditor = {
      list: (id) => [...(providers.get(id)?.values() ?? [])],
      update: (id, model, fn) => {
        const models = providers.get(id)
        if (!models) return
        const info = structuredClone(models.get(model) ?? { id: model, name: model })
        fn(info)
        models.set(model, info)
      },
      remove: (id, model) => providers.get(id)?.delete(model),
    }
    for (const transform of modelTransforms) transform(modelEditor)
  }
  const listeners = new Set()
  const subscribe = ({ signal } = {}) =>
    (async function* () {
      const queue = []
      let wake
      const listener = (event) => {
        queue.push(event)
        wake?.()
      }
      listeners.add(listener)
      signal?.addEventListener("abort", () => wake?.(), { once: true })
      try {
        while (!signal?.aborted) {
          if (!queue.length) await new Promise((resolve) => (wake = resolve))
          while (queue.length && !signal?.aborted) yield queue.shift()
        }
      } finally {
        listeners.delete(listener)
      }
    })()
  const emit = (event) => listeners.forEach((listener) => listener(event))
  const ctx = {
    options,
    provider: {
      list: async () => ({ location: { directory: "/" }, data: structuredClone(providerList) }),
    },
    model: {
      transform: async (callback) => {
        modelTransforms.push(callback)
        rebuild()
        return {
          dispose: async () => {
            modelTransforms.splice(modelTransforms.indexOf(callback), 1)
            rebuild()
          },
        }
      },
      reload: async () => {
        reloads.count++
        rebuild()
      },
    },
    event: { subscribe },
    integration: {
      transform: async (callback) => {
        integrationTransforms.push(callback)
        rebuildIntegrations()
        return {
          dispose: async () => {
            integrationTransforms.splice(integrationTransforms.indexOf(callback), 1)
            rebuildIntegrations()
          },
        }
      },
      connection: {
        active: async (id) => {
          const saved = credentials.filter((c) => c.integrationID === id)
          const last = saved.at(-1)
          return last ? { type: "credential", id: last.id, label: last.label, method: last.value.type } : undefined
        },
        resolve: async (connection) => {
          const credential = credentials.find((c) => c.id === connection.id)
          if (!credential) return undefined
          if (credential.value.type === "key") return credential.value
          const impl = integrations.get(credential.integrationID)?.impl.get(credential.value.methodID)
          if (!impl?.refresh) return credential.value
          if (credential.value.expires > Date.now() + FIVE_MINUTES) return credential.value
          const value = await impl.refresh(credential.value)
          credential.value = value
          return value
        },
        status: async (input) => {
          statuses.push(input)
        },
      },
    },
    session: {
      hook: async (name, callback, opts) => {
        const hook = { callback, opts }
        hooks[name].push(hook)
        return { dispose: async () => hooks[name].splice(hooks[name].indexOf(hook), 1) }
      },
    },
  }
  const store = (value, integrationID = "openwebui") => {
    const entry = { id: `cred_${credentials.length + 1}`, integrationID, label: integrationID, value }
    credentials.push(entry)
    return entry
  }
  const trigger = async (name, event) => {
    for (const hook of hooks[name]) {
      if (hook.opts?.providerID && hook.opts.providerID !== event.model?.providerID) continue
      await hook.callback(event)
    }
    return event
  }
  const setProviders = (list) => {
    providerList = list
    rebuildIntegrations()
    emit({ type: "provider.updated" })
  }
  return { ctx, integrations, credentials, store, hooks, statuses, trigger, providers, reloads, emit, setProviders }
}

const options = () => ({
  authentikURL: mocks.authentik.url.origin,
  cliClientID: "cli-client",
  proxyClientID: "proxy-client",
  modelsRefreshMinutes: 0,
})

const running = []
afterEach(() => running.splice(0).forEach((fake) => fake.cleanup()))

async function setup(overrides = {}, providerList) {
  const fake = fakeCtx({ ...options(), ...overrides }, providerList)
  fake.cleanup = await plugin.setup(fake.ctx)
  running.push(fake)
  return fake
}

async function login(fake, providerID = "openwebui") {
  const impl = fake.integrations.get(providerID).impl.get("authentik")
  const authorization = await impl.authorize({})
  return { authorization, credential: await authorization.callback }
}

const chatRequest = (fake, access) =>
  new Request(`${mocks.openwebui.url.origin}/api/chat/completions`, {
    method: "POST",
    headers: { authorization: `Bearer ${access}`, "content-type": "application/json" },
    body: JSON.stringify({ model: "m", messages: [] }),
  })

const until = async (check) => {
  for (let i = 0; i < 400 && !check(); i++) await Bun.sleep(5)
  expect(check()).toBe(true)
}

const scope = { sessionID: "ses_1", agent: "build", model: { providerID: "openwebui", id: "m" }, kind: "primary" }

beforeEach(() => {
  clockOffset = 0
  delays.length = 0
  Object.assign(mocks.state, {
    deviceScript: ["authorization_pending", "ok"],
    deviceInterval: 5,
    deviceExpiresIn: 600,
    mintFail: false,
    refreshDelayMs: 0,
    offline: true,
    outpostDown: false,
    userinfoDown: false,
    discoverLocation: undefined,
    models: [{ id: "m", object: "model" }],
  })
  for (const key of Object.keys(mocks.state.counts)) mocks.state.counts[key] = 0
  mocks.state.log.length = 0
})

describe("registration", () => {
  test("registers the oauth method on the provider's integration, drops the key method, scopes hooks", async () => {
    const fake = await setup()
    expect(fake.integrations.get("openwebui").methods).toEqual([
      { id: "authentik", type: "oauth", label: "authentik (device login)" },
    ])
    for (const name of ["http.request", "http.response", "retry"])
      expect(fake.hooks[name].map((h) => h.opts)).toEqual([{ providerID: "openwebui" }])
    expect(typeof fake.cleanup).toBe("function")
  })
})

describe("providers", () => {
  const hooked = (fake) => fake.hooks["http.request"].map((h) => h.opts.providerID)
  const oauth = [{ id: "authentik", type: "oauth", label: "authentik (device login)" }]
  const key = [{ type: "key", label: "Manually enter API Key" }]

  test("manages only marked providers, with settings from their marker", async () => {
    const fake = await setup({}, [
      marked("openwebui-ks"),
      marked("home-ai", { cliClientID: "other-cli" }),
      { id: "dgx", settings: {} },
    ])
    expect(fake.integrations.get("openwebui-ks").methods).toEqual(oauth)
    expect(fake.integrations.get("home-ai").methods).toEqual(oauth)
    expect(fake.integrations.get("dgx").methods).toEqual(key)
    expect(hooked(fake)).toEqual(["openwebui-ks", "home-ai"])
    await expect(login(fake, "home-ai")).rejects.toThrow(/device authorization failed.*invalid_client/)
    await login(fake, "openwebui-ks")
    const home = { ...scope, model: { providerID: "home-ai", id: "m" }, request: chatRequest(fake, "") }
    await expect(fake.trigger("http.request", home)).rejects.toThrow(
      /run: opencode auth login home-ai --method authentik/,
    )
  })

  test("adopts providers marked later and releases unmarked ones", async () => {
    const fake = await setup({}, [])
    expect(hooked(fake)).toEqual([])
    fake.setProviders([marked(), marked("home-ai")])
    await until(() => hooked(fake).length === 2)
    expect(fake.integrations.get("home-ai").methods).toEqual(oauth)
    fake.setProviders([
      { id: "openwebui", settings: { baseURL: `${mocks.openwebui.url.origin}/api` } },
      marked("home-ai"),
    ])
    await until(() => hooked(fake).length === 1)
    expect(hooked(fake)).toEqual(["home-ai"])
    expect(fake.integrations.get("openwebui").methods).toEqual(key)
  })

  test("a changed marker re-registers the provider, an unchanged one does not", async () => {
    const fake = await setup()
    const first = fake.hooks.retry[0]
    fake.emit({ type: "provider.updated" })
    await Bun.sleep(20)
    expect(fake.hooks.retry).toEqual([first])
    fake.setProviders([marked("openwebui", { cliClientID: "other-cli" })])
    await until(() => fake.hooks.retry[0] !== first)
    expect(hooked(fake)).toEqual(["openwebui"])
    await expect(login(fake)).rejects.toThrow(/invalid_client/)
  })

  test("providers missing from the list stay managed", async () => {
    const fake = await setup()
    fake.setProviders([])
    await Bun.sleep(20)
    expect(hooked(fake)).toEqual(["openwebui"])
  })
})

describe("configuration", () => {
  test("without options, uses the provider's baseURL and discovers authentik from its redirect", async () => {
    const fake = await setup({ authentikURL: undefined, proxyClientID: undefined })
    const { credential } = await login(fake)
    expect(mocks.state.proxy.has(credential.access)).toBe(true)
    expect(mocks.state.counts.discover).toBe(1)
    fake.store(credential)
    const sent = await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })
    expect(mocks.state.owuiTokens.has(sent.request.headers.get("x-open-webui-token"))).toBe(true)
    const request = new Request("https://evil.example/api/chat/completions", { method: "POST", body: "{}" })
    await expect(fake.trigger("http.request", { ...scope, request })).rejects.toThrow(/Refusing to send/)
  })

  test("a marked provider without a baseURL fails with a hint", async () => {
    const fake = await setup({ authentikURL: undefined }, [marked("other", true, null)])
    await expect(login(fake, "other")).rejects.toThrow(/Set settings.baseURL on the other provider/)
  })

  test("marker settings override the plugin options", async () => {
    const fake = await setup({ cliClientID: "wrong" }, [marked("openwebui", { cliClientID: "cli-client" })])
    const { credential } = await login(fake)
    expect(mocks.state.proxy.has(credential.access)).toBe(true)
  })
})

describe("device login", () => {
  test("happy path: verification_uri_complete, polls, mints proxy token", async () => {
    const fake = await setup()
    const { authorization, credential } = await login(fake)
    expect(authorization.mode).toBe("auto")
    expect(authorization.url).toMatch(/\/device\?code=USER-dc-\d+$/)
    expect(authorization.instructions).toContain("USER-dc-")
    expect(authorization.instructions).toMatch(/^Approve only if you started this login yourself/)
    expect(authorization.instructions).toContain(`${mocks.authentik.url.origin}/device`)
    expect(authorization.expiresAt).toBeGreaterThan(Date.now() + 580_000)
    expect(Object.keys(credential).sort()).toEqual(["access", "expires", "methodID", "refresh", "type"])
    expect(credential.type).toBe("oauth")
    expect(credential.methodID).toBe("authentik")
    expect(credential.refresh).toMatch(/^rt-/)
    expect(mocks.state.proxy.has(credential.access)).toBe(true)
    expect(Number.isInteger(credential.expires)).toBe(true)
    expect(credential.expires).toBeGreaterThan(Date.now() + 43_000_000)
    expect(mocks.state.counts.poll).toBe(2)
    expect(delays).toEqual([5000, 5000])
    const device = mocks.state.log.find((e) => e.path === "/application/o/device/")
    expect(device.form).toEqual({ client_id: "cli-client", scope: "openid email profile offline_access" })
    const mint = mocks.state.log.find((e) => e.form.grant_type === "client_credentials")
    expect(mocks.state.cliAccess.has(mint.form.client_assertion)).toBe(true)
    expect(mint.form.client_id).toBe("proxy-client")
    expect(fake.integrations.get("openwebui").impl.get("authentik").label(credential)).toBe("user@example.com")
  })

  test("slow_down adds 5s to the polling interval for all later polls", async () => {
    const fake = await setup()
    mocks.state.deviceScript = ["slow_down", "authorization_pending", "ok"]
    await login(fake)
    expect(delays).toEqual([5000, 10000, 10000])
  })

  test("expired_token fails the attempt with a re-login hint", async () => {
    const fake = await setup()
    mocks.state.deviceScript = ["authorization_pending", "expired_token"]
    await expect(login(fake)).rejects.toThrow(/device code expired.*opencode auth login openwebui/)
  })

  test("local deadline stops polling without another request", async () => {
    const fake = await setup()
    mocks.state.deviceScript = ["authorization_pending", "authorization_pending", "authorization_pending"]
    mocks.state.deviceExpiresIn = 8
    await expect(login(fake)).rejects.toThrow(/device code expired/)
    expect(mocks.state.counts.poll).toBe(1)
  })

  test("access_denied and missing refresh token fail clearly", async () => {
    const fake = await setup()
    mocks.state.deviceScript = ["access_denied"]
    await expect(login(fake)).rejects.toThrow(/denied/)
    mocks.state.deviceScript = ["ok"]
    mocks.state.offline = false
    await expect(login(fake)).rejects.toThrow(/no refresh token/)
  })

  test("mint failure during login fails the login", async () => {
    const fake = await setup()
    mocks.state.mintFail = true
    await expect(login(fake)).rejects.toThrow(/refused to mint.*invalid_grant/)
  })
})

describe("refresh", () => {
  test("rotation: expired credential refreshes, stores the rotated refresh token", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    const saved = fake.store({ ...credential, expires: Date.now() + 60_000 })
    const connection = await fake.ctx.integration.connection.active("openwebui")
    const value = await fake.ctx.integration.connection.resolve(connection)
    expect(mocks.state.counts.refresh).toBe(1)
    expect(value.refresh).not.toBe(credential.refresh)
    expect(mocks.state.refresh.get(credential.refresh).revoked).toBe(true)
    expect(mocks.state.refresh.get(value.refresh).revoked).toBe(false)
    expect(value.access).not.toBe(credential.access)
    expect(saved.value).toEqual(value)
    await fake.ctx.integration.connection.resolve(connection)
    expect(mocks.state.counts.refresh).toBe(1)
  })

  test("mint failure after refresh keeps the new refresh token and retries after the grace window", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    const saved = fake.store({ ...credential, expires: 0 })
    mocks.state.mintFail = true
    const connection = await fake.ctx.integration.connection.active("openwebui")
    const failed = await fake.ctx.integration.connection.resolve(connection)
    expect(failed.refresh).not.toBe(credential.refresh)
    expect(failed.access).toBe("authentik-mint-failed")
    expect(failed.expires).toBe(0)
    expect(saved.value.refresh).toBe(failed.refresh)
    expect(mocks.state.refresh.get(failed.refresh).revoked).toBe(false)

    const request = { ...scope, request: chatRequest(fake, "") }
    await expect(fake.trigger("http.request", request)).rejects.toThrow(
      /Could not get an Open WebUI token.*invalid_grant/,
    )
    expect(mocks.state.counts.refresh).toBe(1)

    mocks.state.mintFail = false
    clockOffset += 31_000
    const recovered = await fake.ctx.integration.connection.resolve(connection)
    expect(mocks.state.counts.refresh).toBe(2)
    expect(mocks.state.proxy.has(recovered.access)).toBe(true)
    expect(mocks.state.refresh.get(failed.refresh).revoked).toBe(true)
    expect(saved.value.refresh).toBe(recovered.refresh)
  })

  test("concurrent refreshes are single-flight; stale callers reuse the result within grace", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    const stale = { ...credential, expires: 0 }
    fake.store(stale)
    mocks.state.refreshDelayMs = 150
    const connection = await fake.ctx.integration.connection.active("openwebui")
    const results = await Promise.all(
      Array.from({ length: 5 }, () => fake.ctx.integration.connection.resolve(connection)),
    )
    expect(mocks.state.counts.refresh).toBe(1)
    expect(new Set(results.map((r) => r.refresh)).size).toBe(1)
    const impl = fake.integrations.get("openwebui").impl.get("authentik")
    clockOffset += 20_000
    expect((await impl.refresh(stale)).refresh).toBe(results[0].refresh)
    expect(mocks.state.counts.refresh).toBe(1)
  })

  test("invalid_grant adopts a refresh token another process rotated", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    const saved = fake.store(credential)
    const other = await setup()
    const rotated = await other.integrations
      .get("openwebui")
      .impl.get("authentik")
      .refresh({ ...credential, expires: 0 })
    saved.value = rotated
    const mints = mocks.state.counts.mint
    const impl = fake.integrations.get("openwebui").impl.get("authentik")
    expect(await impl.refresh({ ...credential, expires: 0 })).toEqual(rotated)
    expect(mocks.state.counts.refresh).toBe(2)
    expect(mocks.state.counts.mint).toBe(mints)
  })

  test("invalid_grant without a newer stored token fails with a login hint after re-reading", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store({ ...credential, expires: 0 })
    mocks.state.refresh.get(credential.refresh).revoked = true
    const connection = await fake.ctx.integration.connection.active("openwebui")
    await expect(fake.ctx.integration.connection.resolve(connection)).rejects.toThrow(
      /refused to refresh.*invalid_grant.*opencode auth login/,
    )
    expect(mocks.state.counts.refresh).toBe(1)
    expect(delays.filter((ms) => ms === 1000).length).toBe(10)
  })
})

describe("proxy client discovery", () => {
  test("without proxyClientID, reads client_id from the outpost redirect once", async () => {
    const fake = await setup({ proxyClientID: undefined })
    const { credential } = await login(fake)
    expect(mocks.state.proxy.has(credential.access)).toBe(true)
    expect(mocks.state.counts.discover).toBe(1)
    const impl = fake.integrations.get("openwebui").impl.get("authentik")
    await impl.refresh({ ...credential, expires: 0 })
    expect(mocks.state.counts.mint).toBe(2)
    expect(mocks.state.counts.discover).toBe(1)
  })

  test("an explicit proxyClientID skips discovery", async () => {
    const fake = await setup()
    await login(fake)
    expect(mocks.state.counts.discover).toBe(0)
  })

  test("refuses a redirect to another origin or path", async () => {
    for (const location of [
      "https://evil.example/application/o/authorize/?client_id=x",
      `${mocks.authentik.url.origin}/flow?client_id=x`,
    ]) {
      mocks.state.discoverLocation = location
      const fake = await setup({ proxyClientID: undefined })
      await expect(login(fake)).rejects.toThrow(/Could not find the Open WebUI authentik client/)
    }
  })

  test("invalid_client forgets the discovered client and rediscovers", async () => {
    mocks.state.discoverLocation = `${mocks.authentik.url.origin}/application/o/authorize/?client_id=stale`
    const fake = await setup({ proxyClientID: undefined })
    await expect(login(fake)).rejects.toThrow(/invalid_client/)
    mocks.state.discoverLocation = undefined
    await login(fake)
    expect(mocks.state.counts.discover).toBe(2)
  })
})

describe("request hook", () => {
  test("sets Authorization to the proxy token and X-Open-WebUI-Token to a cached signin JWT", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    const first = await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "ignored") })
    expect(first.request.headers.get("authorization")).toBe(`Bearer ${credential.access}`)
    const token = first.request.headers.get("x-open-webui-token")
    expect(mocks.state.owuiTokens.has(token)).toBe(true)
    const second = await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "ignored") })
    expect(second.request.headers.get("x-open-webui-token")).toBe(token)
    expect(mocks.state.counts.signin).toBe(1)
    const response = await fetch(second.request)
    expect(response.status).toBe(200)
  })

  test("concurrent first requests share one signin", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    await Promise.all(
      Array.from({ length: 4 }, () => fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })),
    )
    expect(mocks.state.counts.signin).toBe(1)
  })

  test("throws with a login hint when no credential is active", async () => {
    const fake = await setup()
    await expect(fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })).rejects.toThrow(
      /No authentik login is active for openwebui; run: opencode auth login openwebui --method authentik/,
    )
  })

  test("throws when the active credential is a stored API key", async () => {
    const fake = await setup()
    fake.store({ type: "key", key: "sk-123" })
    await expect(fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })).rejects.toThrow(
      /No authentik login is active/,
    )
  })

  test("refuses to send tokens to another origin", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    const request = new Request("https://evil.example/api/chat/completions", { method: "POST", body: "{}" })
    await expect(fake.trigger("http.request", { ...scope, request })).rejects.toThrow(/Refusing to send/)
  })

  test("signin redirected by authentik reports needs_auth and throws", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    mocks.state.proxy.delete(credential.access)
    await expect(fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })).rejects.toThrow(
      /authentik rejected the Open WebUI credential \(got a redirect, HTTP 302\)/,
    )
    expect(fake.statuses.at(-1).status.status).toBe("needs_auth")
  })

  test("signin redirect for a token authentik still accepts is transient", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    mocks.state.outpostDown = true
    await expect(fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })).rejects.toThrow(
      /could not verify the Open WebUI credential.*try again shortly/,
    )
    mocks.state.userinfoDown = true
    await expect(fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })).rejects.toThrow(
      /could not verify/,
    )
    expect(mocks.state.counts.userinfo).toBe(2)
    expect(fake.statuses).toEqual([])
  })
})

describe("response hook", () => {
  const respond = async (fake, response, request, overrides = {}) =>
    fake.trigger("http.response", { ...scope, ...overrides, request, response })
  const redirect = () => new Response(null, { status: 302, headers: { location: "https://authentik/flow" } })
  const ok = () => new Response("data: x\n\n", { status: 200, headers: { "content-type": "text/event-stream" } })
  const unauthorized = () => Response.json({ detail: "Invalid token" }, { status: 401 })
  const retryEvent = (overrides = {}) => ({
    ...scope,
    error: { type: "provider.auth", message: "Invalid token", status: 401 },
    attempt: 2,
    decision: { retry: false },
    ...overrides,
  })

  test("authentik redirect becomes a 401 JSON error with a login hint", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    mocks.state.proxy.delete(credential.access)
    const event = await respond(fake, redirect(), chatRequest(fake, credential.access))
    expect(event.response.status).toBe(401)
    const body = await event.response.json()
    expect(body.error.type).toBe("authentication_error")
    expect(body.error.message).toMatch(/HTTP 302.*opencode auth login openwebui/)
    expect(fake.statuses.at(-1)).toMatchObject({ integrationID: "openwebui", status: { status: "needs_auth" } })
    const retry = retryEvent()
    await fake.trigger("retry", retry)
    expect(retry.decision).toEqual({ retry: false })
  })

  test("unverified redirect skips needs_auth and retries once after 2s", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    const event = await respond(fake, redirect(), chatRequest(fake, credential.access))
    expect(event.response.status).toBe(401)
    expect((await event.response.json()).error.message).toMatch(/could not verify.*try again shortly/)
    expect(fake.statuses).toEqual([])
    const retry = retryEvent()
    await fake.trigger("retry", retry)
    expect(retry.decision).toEqual({ retry: true, delay: 2000 })
  })

  test("the next successful response clears needs_auth once", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    mocks.state.proxy.delete(credential.access)
    await respond(fake, redirect(), chatRequest(fake, credential.access))
    await respond(fake, ok(), chatRequest(fake, credential.access))
    await respond(fake, ok(), chatRequest(fake, credential.access))
    expect(fake.statuses).toHaveLength(2)
    expect(fake.statuses[0].status.status).toBe("needs_auth")
    expect(fake.statuses[1]).toStrictEqual({ ...fake.statuses[0], status: undefined })
  })

  test("authentik rejection drops the cached JWT so it is not sent again", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    const sent = await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })
    mocks.state.proxy.delete(credential.access)
    const followed = await fetch(sent.request.clone())
    expect(followed.headers.get("content-type")).toContain("text/html")
    await respond(fake, followed, sent.request)
    await expect(fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })).rejects.toThrow(
      /authentik rejected the Open WebUI credential/,
    )
    expect(mocks.state.counts.signin).toBe(1)
  })

  test("followed redirect to an HTML login page becomes a 401", async () => {
    const fake = await setup()
    const event = await respond(
      fake,
      new Response("<html>login</html>", { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }),
      chatRequest(fake, "x"),
    )
    expect(event.response.status).toBe(401)
  })

  test("non-auth responses pass through untouched", async () => {
    const fake = await setup()
    for (const response of [
      new Response("data: x\n\n", { status: 200, headers: { "content-type": "text/event-stream" } }),
      new Response("<html>bad gateway</html>", { status: 502, headers: { "content-type": "text/html" } }),
    ]) {
      const event = await respond(fake, response, chatRequest(fake, "x"))
      expect(event.response).toBe(response)
    }
  })

  test("Open WebUI 401 drops the cached JWT, next request re-signs in, retry hook retries once", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    const sent = await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })
    const oldToken = sent.request.headers.get("x-open-webui-token")
    mocks.state.owuiTokens.delete(oldToken)
    const upstream = await fetch(sent.request.clone())
    expect(upstream.status).toBe(401)
    const event = await respond(fake, upstream, sent.request)
    expect(event.response.status).toBe(401)

    const retry = {
      ...scope,
      error: { type: "provider.auth", message: "Invalid token", status: 401 },
      attempt: 2,
      decision: { retry: false },
    }
    await fake.trigger("retry", retry)
    expect(retry.decision).toEqual({ retry: true, delay: 0 })
    const again = { ...retry, attempt: 3, decision: { retry: false } }
    await fake.trigger("retry", again)
    expect(again.decision).toEqual({ retry: false })

    const next = await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })
    const newToken = next.request.headers.get("x-open-webui-token")
    expect(newToken).not.toBe(oldToken)
    expect(mocks.state.counts.signin).toBe(2)
    expect((await fetch(next.request)).status).toBe(200)
  })

  test("a 401 for an older JWT does not drop a newer cached one", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })
    const request = chatRequest(fake, credential.access)
    request.headers.set("x-open-webui-token", "older.jwt.token")
    await respond(fake, Response.json({ detail: "Invalid token" }, { status: 401 }), request)
    await fake.trigger("http.request", { ...scope, request: chatRequest(fake, "") })
    expect(mocks.state.counts.signin).toBe(1)
  })
  test("401 retry is one-shot per session until a request succeeds", async () => {
    const fake = await setup()
    const retried = async (sessionID) => {
      const retry = retryEvent({ sessionID })
      await fake.trigger("retry", retry)
      return retry.decision.retry
    }
    await respond(fake, unauthorized(), chatRequest(fake, "x"))
    expect(await retried("ses_1")).toBe(true)
    await respond(fake, unauthorized(), chatRequest(fake, "x"))
    expect(await retried("ses_1")).toBe(false)
    await respond(fake, unauthorized(), chatRequest(fake, "x"), { sessionID: "ses_2" })
    expect(await retried("ses_2")).toBe(true)
    await respond(fake, ok(), chatRequest(fake, "x"))
    await respond(fake, unauthorized(), chatRequest(fake, "x"))
    expect(await retried("ses_1")).toBe(true)
  })

  test("title requests never queue a retry", async () => {
    const fake = await setup()
    await respond(fake, unauthorized(), chatRequest(fake, "x"), { kind: "title" })
    const retry = retryEvent()
    await fake.trigger("retry", retry)
    expect(retry.decision).toEqual({ retry: false })
  })
})

describe("model sync", () => {
  const models = (fake) => Object.fromEntries(fake.providers.get("openwebui"))

  test("syncs served models into the provider once a login exists", async () => {
    mocks.state.models = [
      { id: "m", name: "Served m" },
      { id: "new", name: "New model" },
      { id: "bare" },
      { id: "secret", info: { meta: { hidden: true } } },
    ]
    const fake = await setup({ modelsRefreshMinutes: 5 })
    await Bun.sleep(20)
    expect(fake.reloads.count).toBe(0)
    expect(Object.keys(models(fake))).toEqual(["m", "gone"])
    const { credential } = await login(fake)
    fake.store(credential)
    fake.emit({ type: "credential.switched", data: { integrationID: "openwebui" } })
    await until(() => fake.reloads.count === 1)
    expect(models(fake)).toEqual({
      m: { id: "m", name: "configured m", limit: { context: 1000 } },
      new: { id: "new", name: "New model" },
      bare: { id: "bare", name: "bare" },
    })
  })

  test("turns each model's effort control into variants", async () => {
    const control = (...options) => ({
      label: "Control",
      options: Object.fromEntries(options.map((option) => [option, { label: option }])),
    })
    const variant = (model, key, option) => ({
      id: option,
      body: { params: { model_controls: { [model]: { [key]: option } } } },
    })
    mocks.state.models = [
      { id: "m", info: { params: { model_controls: { thinking: control("none", "high") } } } },
      {
        id: "pick",
        name: "Pick",
        info: { params: { model_controls: { verbosity: control("short"), thinking: control("low", "max") } } },
      },
      { id: "single", name: "Single", info: { params: { model_controls: { effort: control("low", "high") } } } },
      { id: "ambiguous", name: "Ambiguous", info: { params: { model_controls: { a: control("x"), b: control("y") } } } },
    ]
    const fake = await setup({ modelsRefreshMinutes: 5 })
    const { credential } = await login(fake)
    fake.store(credential)
    fake.emit({ type: "credential.switched" })
    await until(() => fake.reloads.count === 1)
    expect(models(fake)).toEqual({
      m: {
        id: "m",
        name: "configured m",
        limit: { context: 1000 },
        variants: [variant("m", "thinking", "none"), variant("m", "thinking", "high")],
      },
      pick: { id: "pick", name: "Pick", variants: [variant("pick", "thinking", "low"), variant("pick", "thinking", "max")] },
      single: {
        id: "single",
        name: "Single",
        variants: [variant("single", "effort", "low"), variant("single", "effort", "high")],
      },
      ambiguous: { id: "ambiguous", name: "Ambiguous" },
    })
    mocks.state.models = [{ id: "m", info: { params: { model_controls: { thinking: control("none") } } } }]
    fake.emit({ type: "credential.switched" })
    await until(() => fake.reloads.count === 2)
    expect(models(fake).m.variants).toEqual([variant("m", "thinking", "none")])
  })

  test("syncs context and output limits and vision from the served models", async () => {
    mocks.state.models = [
      { id: "m", max_input_tokens: 500000, info: { meta: { capabilities: { vision: false } } } },
      { id: "litellm", max_input_tokens: 500000, max_output_tokens: 500000 },
      {
        id: "capped",
        max_input_tokens: 128000,
        max_output_tokens: 8192,
        info: { meta: { capabilities: { vision: false } } },
      },
      { id: "vllm", max_model_len: 65536, info: { meta: { capabilities: { vision: true } } } },
      { id: "routed", context_length: 1000000, max_model_len: 2, info: { params: { max_tokens: 4096 } } },
      { id: "ollama", owned_by: "ollama", info: { params: { num_ctx: 16384 } } },
      { id: "foreign-ctx", context_length: 8192, info: { params: { num_ctx: 16384 } } },
      { id: "preset", info: { base_model_id: "base", params: { max_tokens: 1024 } } },
      { id: "base", max_input_tokens: 32768, max_output_tokens: 2048, info: { meta: { hidden: true } } },
      { id: "plain" },
    ]
    const fake = await setup({ modelsRefreshMinutes: 5 })
    const { credential } = await login(fake)
    fake.store(credential)
    fake.emit({ type: "credential.switched" })
    await until(() => fake.reloads.count === 1)
    const synced = models(fake)
    expect(synced.m).toEqual({ id: "m", name: "configured m", limit: { context: 1000 } })
    const limits = (id) => synced[id].limit
    expect(limits("litellm")).toEqual({ context: 500000 })
    expect(limits("capped")).toEqual({ context: 128000, output: 8192 })
    expect(synced.capped.capabilities).toEqual({ input: ["text"] })
    expect(limits("vllm")).toEqual({ context: 65536 })
    expect(synced.vllm.capabilities).toEqual({ input: ["text", "image"] })
    expect(limits("routed")).toEqual({ context: 1000000, output: 4096 })
    expect(limits("ollama")).toEqual({ context: 16384 })
    expect(limits("foreign-ctx")).toEqual({ context: 8192 })
    expect(limits("preset")).toEqual({ context: 32768, output: 1024 })
    expect(synced.base).toBeUndefined()
    expect(synced.plain).toEqual({ id: "plain", name: "plain" })
  })

  test("re-syncs periodically, reloads only on change, stops on cleanup", async () => {
    const fake = await setup({ modelsRefreshMinutes: 1 })
    const { credential } = await login(fake)
    fake.store(credential)
    fake.emit({ type: "credential.updated" })
    await until(() => fake.reloads.count === 1)
    const fetched = mocks.state.counts.models
    await until(() => mocks.state.counts.models > fetched + 1)
    expect(delays).toContain(60_000)
    expect(fake.reloads.count).toBe(1)
    mocks.state.models = [{ id: "later", name: "Later" }]
    await until(() => fake.reloads.count === 2)
    expect(Object.keys(models(fake))).toEqual(["later"])
    fake.cleanup()
    await Bun.sleep(20)
    const stopped = mocks.state.counts.models
    await Bun.sleep(200)
    expect(mocks.state.counts.models).toBe(stopped)
  })

  test("a failed fetch keeps the last list and the next sync signs in again", async () => {
    const fake = await setup({ modelsRefreshMinutes: 5 })
    const { credential } = await login(fake)
    fake.store(credential)
    fake.emit({ type: "credential.switched" })
    await until(() => fake.reloads.count === 1)
    mocks.state.owuiTokens.clear()
    fake.emit({ type: "credential.switched" })
    await until(() => mocks.state.counts.models === 2)
    await Bun.sleep(20)
    expect(Object.keys(models(fake))).toEqual(["m"])
    fake.emit({ type: "credential.switched" })
    await until(() => mocks.state.counts.models === 3)
    expect(mocks.state.counts.signin).toBe(2)
    expect(fake.reloads.count).toBe(1)
  })

  test("a revoked login found by the background sync reports needs_auth", async () => {
    const fake = await setup({ modelsRefreshMinutes: 5 })
    const { credential } = await login(fake)
    fake.store(credential)
    mocks.state.proxy.delete(credential.access)
    fake.emit({ type: "credential.switched" })
    await until(() => fake.statuses.length === 1)
    expect(fake.statuses[0]).toMatchObject({ integrationID: "openwebui", status: { status: "needs_auth" } })
    expect(fake.reloads.count).toBe(0)
  })

  test("modelsRefreshMinutes 0 disables syncing", async () => {
    const fake = await setup()
    const { credential } = await login(fake)
    fake.store(credential)
    fake.emit({ type: "credential.switched" })
    await Bun.sleep(50)
    expect(mocks.state.counts.models).toBe(0)
    expect(Object.keys(models(fake))).toEqual(["m", "gone"])
  })
})
