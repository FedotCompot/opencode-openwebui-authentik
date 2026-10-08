# opencode plugin: Open WebUI via authentik

Server plugin for opencode v2 (tested against v2.0.23). It lets opencode use
`https://openwebui.example.com` with your authentik account, so you don't need an
Open WebUI API key.

- `opencode auth login` runs the authentik device-code login (client `open-webui-cli`).
- The plugin exchanges that login for an authentik token of the Open WebUI proxy provider.
  It finds that provider's client ID in the redirect that `https://openwebui.example.com/`
  sends to logged-out clients. To skip this, use the plugin entry form
  `{ "package": "<dir>", "options": { "proxyClientID": "..." } }`.
  The exchange runs the Open WebUI access policies, so you must be in the `Open WebUI`
  group. It then signs in to Open WebUI to get a session token for your email.
- Each model request sends `Authorization: Bearer <authentik token>` and
  `X-Open-WebUI-Token: <Open WebUI token>`.
- Tokens refresh automatically. If authentik rejects a request, the plugin asks authentik
  whether the token is still valid. Only a dead token marks the login as needing a new
  sign-in; a passing glitch is retried once and clears itself.

## Install

1. Put this directory somewhere stable, for example by keeping this repo checked out.
2. In `~/.config/opencode/opencode.jsonc`, add the directory to `plugins`. The path
   must be the directory, not `index.js`; opencode ignores file paths here. Remove
   `settings.apiKey` from the `openwebui` provider:

   ```jsonc
   {
     "plugins": ["/home/<you>/code/opencode-openwebui-authentik"],
     "providers": {
       "openwebui": {
         "package": "@opencode/ai/providers/openai-compatible",
         "settings": { "baseURL": "https://openwebui.example.com/api" },
         "models": { "...": {} }
       }
     }
   }
   ```

   The provider ID must stay `openwebui`. The plugin attaches to the integration with
   the same ID. Don't also copy the directory into `~/.config/opencode/plugins/`: that
   folder is loaded automatically, so opencode would find the plugin twice and report
   the second copy as a duplicate plugin ID.
3. Check that it loaded: `opencode plugin list` should show `openwebui-authentik`.

## Log in

```sh
opencode auth login openwebui --method authentik
```

Open the URL it prints. authentik shows a consent screen every time; approve it only if
you started this login yourself. The code is in the browser's address bar, not on the
page. `opencode auth list` should then list your email under `openwebui`.

Never approve a device login from a link someone sent you. That gives them your Open
WebUI access.

## Log out

```sh
opencode auth logout openwebui
```

This deletes the stored credential on this machine. The authentik refresh token stays
valid until it expires or an admin revokes it in authentik.

## Errors

- `No authentik login is active for openwebui`: run the login command.
- `authentik rejected the Open WebUI credential`: an admin revoked your Open WebUI
  token, or it expired. Log in again.
- `authentik could not verify the Open WebUI credential`: authentik rejected the request
  but still reports the token as valid, usually because authentik was briefly unreachable.
  The plugin retries once; otherwise try again shortly.
- `Could not find the Open WebUI authentik client`: `https://openwebui.example.com/`
  did not redirect to authentik. Check the URL, or set `proxyClientID`.
- `Could not get an Open WebUI token from authentik`: the token exchange failed. Usually
  this means you aren't in the `Open WebUI` group, or your email is missing or
  duplicated. The plugin keeps your login and retries after 30 seconds.

## Removing access

authentik checks the `Open WebUI` group only when it issues an Open WebUI token. A user
removed from the group keeps access until their current token expires (up to 12 hours),
then gets the token exchange error above. To cut someone off immediately, deactivate them
in authentik (Directory > Users > user > Deactivate), which deletes all their tokens. To
keep the account active instead, remove them from the group and, under Directory > Users >
user > Credentials / Tokens, delete their `Provider for Open WebUI` entries in OAuth Access
Tokens and their `Provider for Open WebUI CLI` entries in OAuth Refresh Tokens. Revoking
sessions is not enough. The outpost can take up to a minute to notice.

## Tests

`bun test` in this directory runs the plugin against mock authentik and Open WebUI servers.

## Known limitation

If authentik rejects the token (after an admin revokes it, or when authentik is briefly
unreachable), Traefik redirects the request to authentik. opencode follows the redirect and still sends the
`X-Open-WebUI-Token` header, so that request leaks the Open WebUI token to authentik.
The plugin then drops that token and does not send it again.
