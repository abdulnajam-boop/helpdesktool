/**
 * Provider-neutral OIDC Authorization Code + PKCE flow for a public
 * (browser, no client secret) SPA client. Mirrors the backend's own
 * provider-neutral posture (helpdesktool/oidc.py): nothing here is tied to
 * a specific identity provider, only standard OIDC discovery
 * (`.well-known/openid-configuration`) and RFC 7636 PKCE.
 *
 * Trust model: `state` (CSRF) and `code_verifier` (PKCE) are generated with
 * `crypto.getRandomValues`, stored in `sessionStorage` only for the
 * duration of the redirect round-trip, and consumed exactly once on
 * callback. The token exchange sends `code_verifier` instead of a client
 * secret (a SPA cannot keep a secret) -- this is the standard, correct
 * public-client OAuth2 pattern (RFC 8252 / OAuth 2.0 Security BCP), not a
 * shortcut. The resulting `access_token` is what's sent to the backend as
 * `Authorization: Bearer` -- the backend verifies it independently
 * (signature, issuer, audience, expiry) and never trusts the frontend's
 * say-so about who the user is.
 */

export interface OidcConfig {
  issuer: string
  clientId: string
  redirectUri: string
  audience?: string
  scope: string
}

const STATE_KEY = 'oidc_state'
const VERIFIER_KEY = 'oidc_code_verifier'

export function isOidcConfigured(): boolean {
  return Boolean(import.meta.env.VITE_OIDC_ISSUER && import.meta.env.VITE_OIDC_CLIENT_ID)
}

export function getOidcConfig(): OidcConfig {
  return {
    issuer: import.meta.env.VITE_OIDC_ISSUER,
    clientId: import.meta.env.VITE_OIDC_CLIENT_ID,
    redirectUri: import.meta.env.VITE_OIDC_REDIRECT_URI || `${window.location.origin}/auth/callback`,
    audience: import.meta.env.VITE_OIDC_AUDIENCE || undefined,
    scope: import.meta.env.VITE_OIDC_SCOPE || 'openid email profile',
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function generateCodeVerifier(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)))
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64UrlEncode(new Uint8Array(digest))
}

export function generateState(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)))
}

export interface DiscoveryDocument {
  authorization_endpoint: string
  token_endpoint: string
}

export async function discover(issuer: string): Promise<DiscoveryDocument> {
  const response = await fetch(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`)
  if (!response.ok) throw new Error('Failed to load identity provider configuration')
  return response.json()
}

/** Redirects the browser to the identity provider's authorization endpoint. */
export async function beginLogin(config: OidcConfig): Promise<void> {
  const discovery = await discover(config.issuer)
  const verifier = generateCodeVerifier()
  const challenge = await generateCodeChallenge(verifier)
  const state = generateState()
  sessionStorage.setItem(VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  if (config.audience) params.set('audience', config.audience)
  window.location.href = `${discovery.authorization_endpoint}?${params.toString()}`
}

/**
 * Call from the /auth/callback route with the full callback URL
 * (including its query string). Validates `state`, exchanges the
 * authorization code for tokens via PKCE, and returns the access token to
 * store and send as `Authorization: Bearer`.
 */
export async function completeLogin(config: OidcConfig, callbackUrl: string): Promise<string> {
  const url = new URL(callbackUrl)
  const error = url.searchParams.get('error')
  if (error) throw new Error(url.searchParams.get('error_description') || error)
  const code = url.searchParams.get('code')
  const returnedState = url.searchParams.get('state')
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(VERIFIER_KEY)
  sessionStorage.removeItem(STATE_KEY)
  sessionStorage.removeItem(VERIFIER_KEY)
  if (!code) throw new Error('Identity provider did not return an authorization code')
  if (!expectedState || returnedState !== expectedState) {
    throw new Error('Login state mismatch; please try signing in again')
  }
  if (!verifier) throw new Error('Missing PKCE verifier; please try signing in again')
  const discovery = await discover(config.issuer)
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId,
      code_verifier: verifier,
    }),
  })
  if (!response.ok) throw new Error('Failed to exchange the authorization code for a token')
  const body = await response.json()
  if (typeof body.access_token !== 'string' || !body.access_token) {
    throw new Error('Identity provider response did not include an access token')
  }
  return body.access_token
}
