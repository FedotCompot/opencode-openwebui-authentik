const MARKER = "openwebuiAuthentik"
const SETTINGS = ["authentikURL", "cliClientID", "proxyClientID"]
const DEFAULT_CLI_CLIENT_ID = "open-webui-cli"
const MODELS_REFRESH_MINUTES = 5
const EFFORT_CONTROL = "thinking"

const METHOD_ID = "authentik"
const AUTHORIZE_PATH = "/application/o/authorize/"
const CLI_SCOPE = "openid email profile offline_access"
const PROXY_SCOPE = "openid email profile ak_proxy"
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
const JWT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
const REFRESH_GRACE_MS = 30_000
const HTTP_TIMEOUT_MS = 30_000
const SLOW_DOWN_MS = 5_000
const REREAD_MS = 10_000
const REREAD_INTERVAL_MS = 1_000
const REJECTED_RETRY_MS = 2_000
// core rejects an empty secret before hooks run
const MINT_FAILED = "authentik-mint-failed"

export default {
  id: "openwebui-authentik",
  setup: async (ctx) => {
    const shutdown = new AbortController()
    const managed = new Map()
    const refreshMs = modelsRefreshMinutes(ctx.options) * 60_000
    const syncAll = () => refreshMs > 0 && managed.forEach((provider) => provider.sync())
    let adopting = Promise.resolve()
    const reconcile = () =>
      (adopting = adopting.then(() => adopt(ctx, managed, shutdown.signal, refreshMs > 0)).catch(() => {}))
    await reconcile()
    if (refreshMs > 0) every(refreshMs, syncAll, shutdown.signal).catch(() => {})
    onEvents(ctx, { credential: syncAll, provider: reconcile }, shutdown.signal).catch(() => {})
    return () => shutdown.abort()
  },
}

// unlisted providers stay managed; the list is partial at startup
async function adopt(ctx, managed, shutdown, sync) {
  const { data = [] } = await ctx.provider.list()
  for (const provider of data) {
    const marked = Boolean(provider.settings?.[MARKER])
    const config = marked ? configure(ctx.options, provider) : undefined
    const current = managed.get(provider.id)
    if (current?.key === config?.key) continue
    if (current) {
      managed.delete(provider.id)
      await current.dispose()
    }
    if (!config) continue
    const adopted = await manage(ctx, config, shutdown)
    managed.set(provider.id, adopted)
    if (sync) adopted.sync()
  }
}

async function manage(ctx, settings, shutdown) {
  const stop = new AbortController()
  const signal = AbortSignal.any([shutdown, stop.signal])
  const config = {
    ...settings,
    origin: async () => {
      if (!settings.openwebuiOrigin) throw new Error(`Set settings.baseURL on the ${settings.providerID} provider`)
      return settings.openwebuiOrigin
    },
  }
  const registrations = []
  const relogin = `run: opencode auth login ${config.providerID} --method ${METHOD_ID}`
  const reread = async () => {
    const connection = await ctx.integration.connection.active(config.providerID)
    return connection && ctx.integration.connection.resolve(connection)
  }
  const authentik = createAuthentik(config, relogin, signal, reread)
  const openwebui = createOpenWebUI(config, signal, authentik.rejection)
  const pending = new Map()
  const retried = new Set()
  let flagged
  let models
  let syncing = Promise.resolve()

  registrations.push(
    await ctx.integration.transform((editor) => {
      editor.method.remove(config.providerID, { type: "key" })
      editor.method.update({
        integrationID: config.providerID,
        method: { id: METHOD_ID, type: "oauth", label: "authentik (device login)" },
        authorize: () => authentik.authorize(),
        refresh: (credential) => authentik.refresh(credential),
        label: (credential) => account(credential.access),
      })
    }),
  )

  registrations.push(
    await ctx.model.transform((editor) => {
      if (!models) return
      const configured = new Set(editor.list(config.providerID).map((model) => model.id))
      for (const id of configured) if (!models.has(id)) editor.remove(config.providerID, id)
      for (const [id, served] of models) {
        if (configured.has(id) && !served.variants.length) continue
        editor.update(config.providerID, id, (model) => {
          if (!configured.has(id)) applyServed(model, served)
          if (served.variants.length) model.variants = structuredClone(served.variants)
        })
      }
    }),
  )

  const current = async () => {
    const connection = await ctx.integration.connection.active(config.providerID)
    if (connection?.type !== "credential" || connection.method !== "oauth")
      throw new Error(`No authentik login is active for ${config.providerID}; ${relogin}`)
    const credential = await ctx.integration.connection.resolve(connection)
    if (credential?.type !== "oauth" || credential.methodID !== METHOD_ID)
      throw new Error(`The active ${config.providerID} credential is not an authentik login; ${relogin}`)
    if (!credential.access || credential.access === MINT_FAILED)
      throw new Error(authentik.mintFailure(credential.refresh))
    return { connection, credential }
  }

  const setStatus = (connection, status) =>
    ctx.integration.connection.status({ integrationID: config.providerID, connection, status }).catch(() => {})

  const needsAuth = async (connection, message) => {
    flagged = connection
    await setStatus(connection, { status: "needs_auth", message })
  }

  const flagRevoked = (connection) => async (error) => {
    if (error instanceof AuthentikRejected && error.revoked) await needsAuth(connection, error.message)
    throw error
  }

  const healthy = async () => {
    if (!flagged) return
    const connection = flagged
    flagged = undefined
    await setStatus(connection, undefined)
  }

  const fetchModels = async () => {
    const { connection, credential } = await current()
    const served = await openwebui.models(credential.access).catch(flagRevoked(connection))
    if (models && sameModels(models, served)) return
    models = served
    await ctx.model.reload()
  }

  registrations.push(
    await ctx.session.hook(
      "http.request",
      async (event) => {
        const origin = new URL(event.request.url).origin
        const expected = await config.origin()
        if (origin !== expected)
          throw new Error(`Refusing to send authentik credentials to ${origin}; expected ${expected}`)
        const { connection, credential } = await current()
        const token = await openwebui.token(credential.access).catch(flagRevoked(connection))
        event.request.headers.set("authorization", `Bearer ${credential.access}`)
        event.request.headers.set("x-open-webui-token", token)
      },
      { providerID: config.providerID },
    ),
  )

  registrations.push(
    await ctx.session.hook(
      "http.response",
      async (event) => {
        const response = event.response
        const session = event.sessionID
        // title and generate requests never reach the retry hook
        const tracked = event.kind === "primary" || event.kind === "compaction"
        if (tracked) pending.delete(session)
        if (rejectedByAuthentik(response)) {
          await response.body?.cancel().catch(() => {})
          const proxyToken = bearer(event.request)
          await openwebui.forget(proxyToken)
          const error = await authentik.rejection(response, proxyToken)
          if (error.revoked) {
            const connection = await ctx.integration.connection.active(config.providerID).catch(() => undefined)
            if (connection) await needsAuth(connection, error.message)
          } else if (tracked) pending.set(session, REJECTED_RETRY_MS)
          event.response = Response.json(
            { error: { type: "authentication_error", message: error.message } },
            { status: 401 },
          )
          return
        }
        if (response.status === 401) {
          await openwebui.forget(bearer(event.request), event.request.headers.get("x-open-webui-token"))
          if (tracked) pending.set(session, 0)
          return
        }
        if (tracked) retried.delete(session)
        if (response.ok) await healthy()
      },
      { providerID: config.providerID },
    ),
  )

  registrations.push(
    await ctx.session.hook(
      "retry",
      (event) => {
        const delay = pending.get(event.sessionID)
        pending.delete(event.sessionID)
        if (delay === undefined || event.error.status !== 401 || retried.has(event.sessionID)) return
        retried.add(event.sessionID)
        event.decision = { retry: true, delay }
      },
      { providerID: config.providerID },
    ),
  )

  return {
    key: config.key,
    sync: () => (syncing = syncing.then(() => fetchModels().catch(() => {}))),
    dispose: async () => {
      stop.abort()
      await Promise.all(registrations.map((registration) => registration.dispose()))
      await ctx.model.reload().catch(() => {})
    },
  }
}

function configure(options, provider) {
  const marker = provider.settings[MARKER]
  const baseURL = provider.settings.baseURL
  const merged = {
    authentikURL: "",
    cliClientID: DEFAULT_CLI_CLIENT_ID,
    proxyClientID: "",
    ...strings(options),
    ...strings(isObject(marker) ? marker : {}),
  }
  return {
    ...merged,
    providerID: provider.id,
    authentikURL: merged.authentikURL.replace(/\/+$/, ""),
    openwebuiOrigin: originOf(baseURL),
    key: JSON.stringify([marker, baseURL]),
  }
}

function originOf(url) {
  try {
    return new URL(url).origin
  } catch {
    return undefined
  }
}

function strings(options) {
  return Object.fromEntries(
    SETTINGS.filter((key) => typeof options?.[key] === "string" && options[key]).map((key) => [key, options[key]]),
  )
}

function modelsRefreshMinutes(options) {
  const minutes = options?.modelsRefreshMinutes
  return Number.isFinite(minutes) && minutes >= 0 ? minutes : MODELS_REFRESH_MINUTES
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

async function every(ms, fn, signal) {
  while (true) {
    await sleep(ms, signal)
    fn()
  }
}

async function onEvents(ctx, handlers, signal) {
  for await (const event of ctx.event.subscribe({ signal })) {
    if (typeof event?.type !== "string") continue
    if (event.type.startsWith("credential.")) handlers.credential()
    else if (event.type === "provider.updated") handlers.provider()
  }
}

function sameModels(a, b) {
  return JSON.stringify([...a]) === JSON.stringify([...b])
}

function applyServed(model, served) {
  model.name = served.name
  if (Object.keys(served.limit).length) model.limit = { ...model.limit, ...served.limit }
  if (typeof served.vision === "boolean") {
    const input = (model.capabilities?.input ?? ["text"]).filter((modality) => modality !== "image")
    model.capabilities = { ...model.capabilities, input: served.vision ? [...input, "image"] : input }
  }
}

function servedLimit(model) {
  const tokens = (value) => (Number.isInteger(value) && value > 0 ? value : undefined)
  const params = model?.info?.params
  const context =
    (model?.owned_by === "ollama" ? tokens(params?.num_ctx) : undefined) ??
    tokens(model?.context_length) ??
    tokens(model?.max_model_len) ??
    tokens(model?.max_input_tokens)
  const reported = tokens(model?.max_output_tokens)
  // LiteLLM reports the whole window as output
  const output = tokens(params?.max_tokens) ?? (reported < (context ?? Infinity) ? reported : undefined)
  return Object.fromEntries(Object.entries({ context, output }).filter(([, value]) => value !== undefined))
}

function effortVariants(model) {
  const controls = model.info?.params?.model_controls
  if (!isObject(controls)) return []
  const keys = Object.keys(controls)
  const key = keys.includes(EFFORT_CONTROL) ? EFFORT_CONTROL : keys.length === 1 ? keys[0] : undefined
  const options = controls[key]?.options
  if (!isObject(options)) return []
  return Object.keys(options).map((option) => ({
    id: option,
    body: { params: { model_controls: { [model.id]: { [key]: option } } } },
  }))
}

function createAuthentik(config, relogin, shutdown, reread) {
  const flights = new Map()
  const mintErrors = new Map()
  const rereading = new Set()
  let site =
    config.authentikURL && config.proxyClientID
      ? Promise.resolve({ authentikURL: config.authentikURL, proxyClientID: config.proxyClientID })
      : undefined

  const discover = async () => {
    const origin = await config.origin()
    const response = await fetch(`${origin}/`, { redirect: "manual", signal: timeout(shutdown) })
    await response.body?.cancel().catch(() => {})
    const location = response.headers.get("location")
    const target = location ? new URL(location, origin) : undefined
    const authentikURL = target?.pathname.endsWith(AUTHORIZE_PATH)
      ? `${target.origin}${target.pathname.slice(0, -AUTHORIZE_PATH.length)}`
      : undefined
    const clientID = target?.searchParams.get("client_id")
    const downgraded = target?.protocol !== "https:" && origin.startsWith("https:")
    if (!authentikURL || !clientID || downgraded || (config.authentikURL && authentikURL !== config.authentikURL))
      throw new Error(`Could not find the Open WebUI authentik client at ${origin} (HTTP ${response.status})`)
    return { authentikURL: config.authentikURL || authentikURL, proxyClientID: config.proxyClientID || clientID }
  }

  const discovered = () => {
    site ??= discover().catch((error) => {
      site = undefined
      throw error
    })
    return site
  }

  const endpoint = async (path) => `${(await discovered()).authentikURL}/application/o/${path}/`

  const credential = (refresh, minted) => ({
    type: "oauth",
    methodID: METHOD_ID,
    refresh,
    access: minted.access,
    expires: minted.expires,
  })

  const mint = async (cliAccess) => {
    const response = await postForm(
      await endpoint("token"),
      {
        grant_type: "client_credentials",
        client_id: (await discovered()).proxyClientID,
        client_assertion_type: JWT_ASSERTION,
        client_assertion: cliAccess,
        scope: PROXY_SCOPE,
      },
      shutdown,
    )
    if (!response.ok || typeof response.body.access_token !== "string") {
      if (response.body.error === "invalid_client" && !config.proxyClientID) site = undefined
      throw new Error(`authentik refused to mint an Open WebUI token (${describe(response)})`)
    }
    return { access: response.body.access_token, expires: expiry(response.body) }
  }

  const poll = async (device, deadline) => {
    let interval = (Number.isFinite(device.interval) ? device.interval : 5) * 1000
    while (true) {
      await sleep(interval, shutdown)
      if (Date.now() >= deadline) throw new Error(`The authentik device code expired before approval; ${relogin}`)
      const response = await postForm(
        await endpoint("token"),
        { grant_type: DEVICE_GRANT, client_id: config.cliClientID, device_code: device.device_code },
        shutdown,
      )
      if (response.ok) return response.body
      const error = response.body.error
      if (error === "authorization_pending") continue
      if (error === "slow_down") {
        interval += SLOW_DOWN_MS
        continue
      }
      if (error === "expired_token") throw new Error(`The authentik device code expired before approval; ${relogin}`)
      if (error === "access_denied") throw new Error("The sign-in was denied in authentik")
      throw new Error(`authentik device login failed (${describe(response)})`)
    }
  }

  const authorize = async () => {
    const response = await postForm(
      await endpoint("device"),
      { client_id: config.cliClientID, scope: CLI_SCOPE },
      shutdown,
    )
    const device = response.body
    if (!response.ok || typeof device.device_code !== "string" || typeof device.user_code !== "string")
      throw new Error(`authentik device authorization failed (${describe(response)})`)
    const expiresAt = Date.now() + (Number.isFinite(device.expires_in) ? device.expires_in : 600) * 1000
    const callback = poll(device, expiresAt).then(async (tokens) => {
      if (typeof tokens.refresh_token !== "string" || !tokens.refresh_token)
        throw new Error("authentik issued no refresh token; the CLI provider must grant offline_access")
      return credential(tokens.refresh_token, await mint(tokens.access_token))
    })
    // core awaits it later
    callback.catch(() => {})
    return {
      mode: "auto",
      url: device.verification_uri_complete ?? device.verification_uri,
      instructions: `Approve only if you started this login yourself. The browser address bar shows the code ${device.user_code}; to type it in, open ${device.verification_uri}`,
      expiresAt,
      callback,
    }
  }

  const rotate = async (stored) => {
    if (!stored.refresh) throw new Error(`The authentik login has no refresh token; ${relogin}`)
    const response = await postForm(
      await endpoint("token"),
      { grant_type: "refresh_token", client_id: config.cliClientID, refresh_token: stored.refresh },
      shutdown,
    )
    if (response.body.error === "invalid_grant") {
      const current = await rotatedElsewhere(stored.refresh)
      if (current) return credential(current.refresh, current)
    }
    if (!response.ok || typeof response.body.access_token !== "string")
      throw new Error(`authentik refused to refresh the login (${describe(response)}); ${relogin}`)
    const refresh = response.body.refresh_token || stored.refresh
    try {
      return credential(refresh, await mint(response.body.access_token))
    } catch (error) {
      const failed = credential(refresh, { access: MINT_FAILED, expires: 0 })
      mintErrors.set(refresh, error instanceof Error ? error.message : String(error))
      remember(refresh, Promise.resolve(failed))
      return failed
    }
  }

  // another opencode process may have rotated it first
  const rotatedElsewhere = async (spent) => {
    rereading.add(spent)
    try {
      const deadline = Date.now() + REREAD_MS
      while (true) {
        const current = await reread().catch(() => undefined)
        if (current?.type === "oauth" && current.methodID === METHOD_ID && current.refresh && current.refresh !== spent)
          return current
        if (Date.now() >= deadline) return undefined
        await sleep(REREAD_INTERVAL_MS, shutdown)
      }
    } finally {
      rereading.delete(spent)
    }
  }

  const prune = () => {
    const now = Date.now()
    for (const [key, flight] of flights) {
      if (flight.settled !== undefined && now - flight.settled > REFRESH_GRACE_MS) {
        flights.delete(key)
        mintErrors.delete(key)
      }
    }
  }

  const remember = (key, promise) => {
    const flight = { promise, settled: undefined }
    flights.set(key, flight)
    promise.then(
      () => (flight.settled = Date.now()),
      () => (flight.settled = Date.now()),
    )
    return flight
  }

  const refresh = (stored) => {
    // core re-enters refresh while we re-read the spent token
    if (rereading.has(stored.refresh)) return Promise.reject(new Error("The authentik refresh token was already used"))
    prune()
    const existing = flights.get(stored.refresh)
    if (existing) return existing.promise
    return remember(stored.refresh, rotate(stored)).promise
  }

  const mintFailure = (refreshToken) => {
    const reason = mintErrors.get(refreshToken)
    return `Could not get an Open WebUI token from authentik${reason ? `: ${reason}` : ""}; it is retried after ${
      REFRESH_GRACE_MS / 1000
    }s, or ${relogin}`
  }

  const revoked = async (proxyToken) => {
    const response = await endpoint("userinfo")
      .then((url) =>
        fetch(url, {
          headers: { authorization: `Bearer ${proxyToken}`, accept: "application/json" },
          redirect: "manual",
          signal: timeout(shutdown),
        }),
      )
      .catch(() => undefined)
    await response?.body?.cancel().catch(() => {})
    return response?.status === 401 && (response.headers.get("www-authenticate") ?? "").includes("invalid_token")
  }

  const rejection = async (response, proxyToken) => {
    const seen = response.status >= 300 && response.status < 400 ? "a redirect" : "the sign-in page"
    if (await revoked(proxyToken))
      return new AuthentikRejected(
        `authentik rejected the Open WebUI credential (got ${seen}, HTTP ${response.status}); ${relogin}`,
        true,
      )
    return new AuthentikRejected(
      `authentik could not verify the Open WebUI credential (got ${seen}, HTTP ${response.status}); try again shortly`,
      false,
    )
  }

  return { authorize, refresh, mintFailure, rejection }
}

function createOpenWebUI(config, shutdown, rejection) {
  const sessions = new Map()

  const signIn = async (proxyToken) => {
    const response = await fetch(`${await config.origin()}/api/v1/auths/signin`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${proxyToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ email: "", password: "" }),
      redirect: "manual",
      signal: timeout(shutdown),
    })
    if (rejectedByAuthentik(response)) {
      await response.body?.cancel().catch(() => {})
      throw await rejection(response, proxyToken)
    }
    const body = await response.json().catch(() => ({}))
    if (!response.ok || typeof body.token !== "string")
      throw new Error(`Open WebUI sign-in failed (HTTP ${response.status}${body.detail ? `: ${body.detail}` : ""})`)
    return { token: body.token, expires: Number.isFinite(body.expires_at) ? body.expires_at * 1000 - 60_000 : Infinity }
  }

  const token = async (proxyToken) => {
    for (const key of sessions.keys()) if (key !== proxyToken) sessions.delete(key)
    const cached = sessions.get(proxyToken)
    if (cached && (cached.expires === undefined || cached.expires > Date.now())) return (await cached.promise).token
    const entry = { promise: signIn(proxyToken), expires: undefined }
    sessions.set(proxyToken, entry)
    try {
      const session = await entry.promise
      entry.expires = session.expires
      return session.token
    } catch (error) {
      if (sessions.get(proxyToken) === entry) sessions.delete(proxyToken)
      throw error
    }
  }

  const models = async (proxyToken) => {
    const session = await token(proxyToken)
    const response = await fetch(`${await config.origin()}/api/models`, {
      headers: { authorization: `Bearer ${proxyToken}`, "x-open-webui-token": session, accept: "application/json" },
      redirect: "manual",
      signal: timeout(shutdown),
    })
    if (rejectedByAuthentik(response)) {
      await response.body?.cancel().catch(() => {})
      await forget(proxyToken)
      throw await rejection(response, proxyToken)
    }
    if (response.status === 401) await forget(proxyToken, session)
    const body = await response.json().catch(() => ({}))
    if (!response.ok || !Array.isArray(body?.data))
      throw new Error(`Open WebUI model list failed (HTTP ${response.status})`)
    const listed = body.data.filter((model) => typeof model?.id === "string" && model.id)
    const byID = new Map(listed.map((model) => [model.id, model]))
    return new Map(
      listed
        .filter((model) => !model.info?.meta?.hidden)
        .map((model) => [
          model.id,
          {
            name: typeof model.name === "string" && model.name ? model.name : model.id,
            variants: effortVariants(model),
            limit: { ...servedLimit(byID.get(model.info?.base_model_id)), ...servedLimit(model) },
            vision: model.info?.meta?.capabilities?.vision,
          },
        ]),
    )
  }

  const forget = async (proxyToken, rejected) => {
    const cached = sessions.get(proxyToken)
    if (!cached) return
    const session = await cached.promise.catch(() => undefined)
    if (rejected && session && session.token !== rejected) return
    if (sessions.get(proxyToken) === cached) sessions.delete(proxyToken)
  }

  return { token, models, forget }
}

class AuthentikRejected extends Error {
  constructor(message, revoked) {
    super(message)
    this.revoked = revoked
  }
}

function rejectedByAuthentik(response) {
  if (response.status >= 300 && response.status < 400) return true
  const html = (response.headers.get("content-type") ?? "").includes("text/html")
  return html && (response.status < 300 || response.status === 401 || response.status === 403)
}

function bearer(request) {
  const value = request.headers.get("authorization") ?? ""
  return value.toLowerCase().startsWith("bearer ") ? value.slice(7) : ""
}

async function postForm(url, params, shutdown) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(params),
    redirect: "manual",
    signal: timeout(shutdown),
  })
  const body = await response.json().catch(() => ({}))
  return { ok: response.ok, status: response.status, body: body && typeof body === "object" ? body : {} }
}

function describe(response) {
  const { error, error_description: detail } = response.body
  if (typeof error !== "string") return `HTTP ${response.status}`
  return detail ? `${error}: ${detail}` : error
}

function expiry(body) {
  if (Number.isFinite(body.expires_in)) return Date.now() + Math.floor(body.expires_in * 1000)
  const exp = claims(body.access_token)?.exp
  return Number.isFinite(exp) ? exp * 1000 : Date.now()
}

function account(token) {
  const payload = claims(token)
  const name = payload?.email ?? payload?.preferred_username
  return typeof name === "string" && name ? name : undefined
}

function claims(token) {
  try {
    const payload = token.split(".")[1]
    return JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"))
  } catch {
    return undefined
  }
}

function timeout(shutdown) {
  return AbortSignal.any([shutdown, AbortSignal.timeout(HTTP_TIMEOUT_MS)])
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason)
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort)
      resolve()
    }, ms)
    const abort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener("abort", abort, { once: true })
  })
}
