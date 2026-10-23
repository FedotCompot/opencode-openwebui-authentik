const REQUIRED = ["authentikURL", "openwebuiURL"]
const SETTINGS = [...REQUIRED, "cliClientID", "proxyClientID"]
const DEFAULT_CLI_CLIENT_ID = "open-webui-cli"
const DEFAULT_PROVIDERS = { openwebui: {} }
const MODELS_REFRESH_MINUTES = 5

const METHOD_ID = "authentik"
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
    const providers = await Promise.all(configure(ctx.options).map((config) => manage(ctx, config, shutdown.signal)))
    const refreshMs = modelsRefreshMinutes(ctx.options) * 60_000
    if (refreshMs > 0) {
      const syncAll = () => providers.forEach((provider) => provider.sync())
      syncAll()
      every(refreshMs, syncAll, shutdown.signal).catch(() => {})
      onCredentialChange(ctx, syncAll, shutdown.signal).catch(() => {})
    }
    return () => shutdown.abort()
  },
}

async function manage(ctx, config, shutdown) {
  const relogin = `run: opencode auth login ${config.providerID} --method ${METHOD_ID}`
  const reread = async () => {
    const connection = await ctx.integration.connection.active(config.providerID)
    return connection && ctx.integration.connection.resolve(connection)
  }
  const authentik = createAuthentik(config, relogin, shutdown, reread)
  const openwebui = createOpenWebUI(config, shutdown, authentik.rejection)
  const pending = new Map()
  const retried = new Set()
  let flagged
  let models
  let syncing = Promise.resolve()

  await ctx.integration.transform((editor) => {
    editor.method.remove(config.providerID, { type: "key" })
    editor.method.update({
      integrationID: config.providerID,
      method: { id: METHOD_ID, type: "oauth", label: "authentik (device login)" },
      authorize: () => authentik.authorize(),
      refresh: (credential) => authentik.refresh(credential),
      label: (credential) => account(credential.access),
    })
  })

  await ctx.model.transform((editor) => {
    if (!models) return
    const configured = new Set(editor.list(config.providerID).map((model) => model.id))
    for (const id of configured) if (!models.has(id)) editor.remove(config.providerID, id)
    for (const [id, name] of models) {
      if (configured.has(id)) continue
      editor.update(config.providerID, id, (model) => {
        model.name = name
      })
    }
  })

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

  await ctx.session.hook(
    "http.request",
    async (event) => {
      const origin = new URL(event.request.url).origin
      if (origin !== config.openwebuiOrigin)
        throw new Error(`Refusing to send authentik credentials to ${origin}; expected ${config.openwebuiOrigin}`)
      const { connection, credential } = await current()
      const token = await openwebui.token(credential.access).catch(flagRevoked(connection))
      event.request.headers.set("authorization", `Bearer ${credential.access}`)
      event.request.headers.set("x-open-webui-token", token)
    },
    { providerID: config.providerID },
  )

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
  )

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
  )

  return { sync: () => (syncing = syncing.then(() => fetchModels().catch(() => {}))) }
}

function configure(options) {
  const shared = strings(options)
  const providers = isObject(options?.providers) ? options.providers : DEFAULT_PROVIDERS
  return Object.entries(providers).map(([providerID, overrides]) => {
    const merged = { cliClientID: DEFAULT_CLI_CLIENT_ID, proxyClientID: "", ...shared, ...strings(overrides) }
    const missing = REQUIRED.filter((key) => !merged[key])
    if (missing.length) throw new Error(`openwebui-authentik: provider ${providerID} needs ${missing.join(", ")}`)
    return {
      ...merged,
      providerID,
      authentikURL: merged.authentikURL.replace(/\/+$/, ""),
      openwebuiOrigin: new URL(merged.openwebuiURL).origin,
    }
  })
}

function strings(options) {
  return Object.fromEntries(
    SETTINGS
      .filter((key) => typeof options?.[key] === "string" && options[key])
      .map((key) => [key, options[key]]),
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

async function onCredentialChange(ctx, fn, signal) {
  for await (const event of ctx.event.subscribe({ signal })) {
    if (typeof event?.type === "string" && event.type.startsWith("credential.")) fn()
  }
}

function sameModels(a, b) {
  return a.size === b.size && [...a].every(([id, name]) => b.get(id) === name)
}

function createAuthentik(config, relogin, shutdown, reread) {
  const endpoint = (path) => `${config.authentikURL}/application/o/${path}/`
  const flights = new Map()
  const mintErrors = new Map()
  const rereading = new Set()
  let proxyClient = config.proxyClientID ? Promise.resolve(config.proxyClientID) : undefined

  const discover = async () => {
    const response = await fetch(`${config.openwebuiOrigin}/`, { redirect: "manual", signal: timeout(shutdown) })
    await response.body?.cancel().catch(() => {})
    const location = response.headers.get("location")
    const target = location ? new URL(location, config.openwebuiOrigin) : undefined
    const authorize = new URL(endpoint("authorize"))
    const clientID =
      target?.origin === authorize.origin && target.pathname === authorize.pathname
        ? target.searchParams.get("client_id")
        : null
    if (!clientID)
      throw new Error(`Could not find the Open WebUI authentik client at ${config.openwebuiOrigin} (HTTP ${response.status})`)
    return clientID
  }

  const proxyClientID = () => {
    proxyClient ??= discover().catch((error) => {
      proxyClient = undefined
      throw error
    })
    return proxyClient
  }

  const credential = (refresh, minted) => ({
    type: "oauth",
    methodID: METHOD_ID,
    refresh,
    access: minted.access,
    expires: minted.expires,
  })

  const mint = async (cliAccess) => {
    const response = await postForm(
      endpoint("token"),
      {
        grant_type: "client_credentials",
        client_id: await proxyClientID(),
        client_assertion_type: JWT_ASSERTION,
        client_assertion: cliAccess,
        scope: PROXY_SCOPE,
      },
      shutdown,
    )
    if (!response.ok || typeof response.body.access_token !== "string") {
      if (response.body.error === "invalid_client" && !config.proxyClientID) proxyClient = undefined
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
        endpoint("token"),
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
      endpoint("device"),
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
      endpoint("token"),
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
    const response = await fetch(endpoint("userinfo"), {
      headers: { authorization: `Bearer ${proxyToken}`, accept: "application/json" },
      redirect: "manual",
      signal: timeout(shutdown),
    }).catch(() => undefined)
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
    const response = await fetch(`${config.openwebuiOrigin}/api/v1/auths/signin`, {
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
    const response = await fetch(`${config.openwebuiOrigin}/api/models`, {
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
    return new Map(
      body.data
        .filter((model) => typeof model?.id === "string" && model.id && !model.info?.meta?.hidden)
        .map((model) => [model.id, typeof model.name === "string" && model.name ? model.name : model.id]),
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
