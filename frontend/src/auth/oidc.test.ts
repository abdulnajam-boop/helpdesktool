import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  beginLogin,
  completeLogin,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from './oidc'

const config = {
  issuer: 'https://idp.example.com',
  clientId: 'helpdesktool-web',
  redirectUri: 'https://app.example.com/auth/callback',
  scope: 'openid email profile',
}

describe('generateCodeChallenge', () => {
  it('matches the RFC 7636 Appendix B test vector', async () => {
    // https://www.rfc-editor.org/rfc/rfc7636#appendix-B
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    const challenge = await generateCodeChallenge(verifier)
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })
})

describe('generateCodeVerifier / generateState', () => {
  it('produces url-safe strings with no padding and reasonable entropy', () => {
    const verifier = generateCodeVerifier()
    const state = generateState()
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(verifier.length).toBeGreaterThanOrEqual(43) // RFC 7636 minimum length
    expect(verifier).not.toBe(generateCodeVerifier())
  })
})

describe('beginLogin', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            authorization_endpoint: 'https://idp.example.com/authorize',
            token_endpoint: 'https://idp.example.com/token',
          }),
          { status: 200 },
        ),
      ),
    )
    // jsdom doesn't implement navigation; stub window.location.href as a plain settable field.
    delete (window as any).location
    ;(window as any).location = { href: '' }
  })

  it('redirects to the discovered authorization endpoint with PKCE parameters', async () => {
    await beginLogin(config)
    const redirectUrl = new URL((window as any).location.href)
    expect(redirectUrl.origin + redirectUrl.pathname).toBe('https://idp.example.com/authorize')
    expect(redirectUrl.searchParams.get('response_type')).toBe('code')
    expect(redirectUrl.searchParams.get('client_id')).toBe('helpdesktool-web')
    expect(redirectUrl.searchParams.get('redirect_uri')).toBe(config.redirectUri)
    expect(redirectUrl.searchParams.get('code_challenge_method')).toBe('S256')
    expect(redirectUrl.searchParams.get('code_challenge')).toBeTruthy()
    expect(redirectUrl.searchParams.get('state')).toBeTruthy()
    expect(sessionStorage.getItem('oidc_state')).toBe(redirectUrl.searchParams.get('state'))
    expect(sessionStorage.getItem('oidc_code_verifier')).toBeTruthy()
  })

  it('includes an audience parameter when configured', async () => {
    await beginLogin({ ...config, audience: 'https://api.example.com' })
    const redirectUrl = new URL((window as any).location.href)
    expect(redirectUrl.searchParams.get('audience')).toBe('https://api.example.com')
  })
})

describe('completeLogin', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('rejects a callback with a state that does not match what beginLogin stored', async () => {
    sessionStorage.setItem('oidc_state', 'expected-state')
    sessionStorage.setItem('oidc_code_verifier', 'some-verifier')
    await expect(
      completeLogin(config, 'https://app.example.com/auth/callback?code=abc&state=WRONG'),
    ).rejects.toThrow(/state mismatch/i)
  })

  it('rejects a callback with no stored state at all (replay/direct-navigation)', async () => {
    await expect(
      completeLogin(config, 'https://app.example.com/auth/callback?code=abc&state=anything'),
    ).rejects.toThrow(/state mismatch/i)
  })

  it('surfaces an identity-provider error from the callback query string', async () => {
    sessionStorage.setItem('oidc_state', 's')
    sessionStorage.setItem('oidc_code_verifier', 'v')
    await expect(
      completeLogin(
        config,
        'https://app.example.com/auth/callback?error=access_denied&error_description=User+cancelled',
      ),
    ).rejects.toThrow('User cancelled')
  })

  it('rejects a callback missing an authorization code', async () => {
    sessionStorage.setItem('oidc_state', 's')
    sessionStorage.setItem('oidc_code_verifier', 'v')
    await expect(
      completeLogin(config, 'https://app.example.com/auth/callback?state=s'),
    ).rejects.toThrow(/authorization code/i)
  })

  it('exchanges a valid code via PKCE and returns the access token', async () => {
    sessionStorage.setItem('oidc_state', 'good-state')
    sessionStorage.setItem('oidc_code_verifier', 'good-verifier')
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('.well-known/openid-configuration')) {
        return new Response(
          JSON.stringify({
            authorization_endpoint: 'https://idp.example.com/authorize',
            token_endpoint: 'https://idp.example.com/token',
          }),
          { status: 200 },
        )
      }
      if (url === 'https://idp.example.com/token') {
        const body = new URLSearchParams(init?.body as string)
        expect(body.get('grant_type')).toBe('authorization_code')
        expect(body.get('code')).toBe('the-code')
        expect(body.get('code_verifier')).toBe('good-verifier')
        expect(body.get('client_id')).toBe(config.clientId)
        return new Response(JSON.stringify({ access_token: 'real-access-token' }), { status: 200 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    const token = await completeLogin(
      config,
      'https://app.example.com/auth/callback?code=the-code&state=good-state',
    )
    expect(token).toBe('real-access-token')
    expect(sessionStorage.getItem('oidc_state')).toBeNull()
    expect(sessionStorage.getItem('oidc_code_verifier')).toBeNull()
  })
})
