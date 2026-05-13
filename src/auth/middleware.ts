import type { Context, Next } from 'hono';
import type { AppEnv, OpenClawEnv } from '../types';
import { verifyAccessJWT } from './jwt';

const GATEWAY_AUTH_COOKIE = 'openclaw_gateway_auth';
const GATEWAY_AUTH_MAX_AGE_SECONDS = 60 * 60 * 24;

/**
 * Options for creating an access middleware
 */
export interface AccessMiddlewareOptions {
  /** Response type: 'json' for API routes, 'html' for UI routes */
  type: 'json' | 'html';
  /** Whether to redirect to login when JWT is missing (only for 'html' type) */
  redirectOnMissing?: boolean;
}

/**
 * Check if running in development mode (skips CF Access auth + device pairing)
 */
export function isDevMode(env: OpenClawEnv): boolean {
  return env.DEV_MODE === 'true';
}

/**
 * Check if running in E2E test mode (skips CF Access auth but keeps device pairing)
 */
export function isE2ETestMode(env: OpenClawEnv): boolean {
  return env.E2E_TEST_MODE === 'true';
}

/**
 * Extract JWT from request headers or cookies
 */
export function extractJWT(c: Context<AppEnv>): string | null {
  const jwtHeader = c.req.header('CF-Access-JWT-Assertion');
  const jwtCookie = readCookie(c.req.raw.headers.get('Cookie'), 'CF_Authorization');

  return jwtHeader || jwtCookie || null;
}

function readCookie(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;

  for (const part of cookieHeader.split(';')) {
    const [cookieName, ...valueParts] = part.trim().split('=');
    if (cookieName === name) {
      return valueParts.join('=') || null;
    }
  }

  return null;
}

function timingSafeEqual(actual: string | null, expected: string | undefined): boolean {
  if (!actual || !expected) return false;

  const encoder = new TextEncoder();
  const actualBytes = encoder.encode(actual);
  const expectedBytes = encoder.encode(expected);
  let diff = actualBytes.length ^ expectedBytes.length;
  const maxLength = Math.max(actualBytes.length, expectedBytes.length);

  for (let i = 0; i < maxLength; i += 1) {
    diff |= (actualBytes[i] ?? 0) ^ (expectedBytes[i] ?? 0);
  }

  return diff === 0;
}

type GatewayTokenSource = 'query' | 'authorization' | 'header' | 'cookie';

interface GatewayTokenCandidate {
  token: string;
  source: GatewayTokenSource;
}

/**
 * Extract a gateway token from browser bootstrap URLs, API auth headers, or
 * the session cookie this middleware sets after a successful token login.
 */
export function extractGatewayToken(c: Context<AppEnv>): GatewayTokenCandidate | null {
  const url = new URL(c.req.url);
  const queryToken = url.searchParams.get('token');
  if (queryToken) return { token: queryToken, source: 'query' };

  const authHeader = c.req.header('Authorization');
  const bearerMatch = authHeader?.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch?.[1]) {
    return { token: bearerMatch[1], source: 'authorization' };
  }

  const explicitHeader =
    c.req.header('X-OpenClaw-Gateway-Token') || c.req.header('X-Moltbot-Gateway-Token');
  if (explicitHeader) return { token: explicitHeader, source: 'header' };

  const cookieToken = readCookie(c.req.raw.headers.get('Cookie'), GATEWAY_AUTH_COOKIE);
  if (cookieToken) return { token: cookieToken, source: 'cookie' };

  return null;
}

function createGatewayAuthCookie(token: string): string {
  return [
    `${GATEWAY_AUTH_COOKIE}=${token}`,
    'Path=/',
    `Max-Age=${GATEWAY_AUTH_MAX_AGE_SECONDS}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
  ].join('; ');
}

function htmlEscape(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function gatewayLoginHtml(c: Context<AppEnv>, teamDomain?: string): string {
  const url = new URL(c.req.url);
  const action = `${url.pathname}${url.searchParams.size ? `?${url.searchParams}` : ''}`;
  const accessLoginLink = teamDomain ? `<a href="https://${htmlEscape(teamDomain)}">Cloudflare Access</a>` : '';

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OpenClaw Login</title>
    <style>
      :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: Canvas; color: CanvasText; }
      main { width: min(100% - 32px, 420px); }
      h1 { font-size: 1.4rem; margin: 0 0 1rem; }
      form { display: grid; gap: 0.75rem; }
      label { font-size: 0.9rem; }
      input, button { font: inherit; padding: 0.8rem 0.9rem; border-radius: 6px; border: 1px solid color-mix(in srgb, CanvasText 25%, Canvas); }
      button { cursor: pointer; background: ButtonFace; color: ButtonText; }
      p { color: color-mix(in srgb, CanvasText 70%, Canvas); line-height: 1.45; }
    </style>
  </head>
  <body>
    <main>
      <h1>OpenClaw</h1>
      <form method="get" action="${htmlEscape(action)}">
        <label for="token">Gateway token</label>
        <input id="token" name="token" type="password" autocomplete="current-password" autofocus required>
        <button type="submit">Continue</button>
      </form>
      ${accessLoginLink ? `<p>${accessLoginLink}</p>` : ''}
    </main>
  </body>
</html>`;
}

async function authenticateGatewayToken(
  c: Context<AppEnv>,
  next: Next,
  candidate: GatewayTokenCandidate,
): Promise<Response | void> {
  c.set('accessUser', { email: 'gateway-token@openclaw.local', name: 'Gateway Token' });

  if (candidate.source === 'query' && c.req.method === 'GET') {
    const cleanUrl = new URL(c.req.url);
    cleanUrl.searchParams.delete('token');
    const redirectTo = `${cleanUrl.pathname}${cleanUrl.search}`;

    c.header('Set-Cookie', createGatewayAuthCookie(candidate.token));
    return c.redirect(redirectTo || '/', 302);
  }

  await next();

  if (candidate.source !== 'cookie') {
    c.header('Set-Cookie', createGatewayAuthCookie(candidate.token));
  }
}

/**
 * Create a Cloudflare Access authentication middleware
 *
 * @param options - Middleware options
 * @returns Hono middleware function
 */
export function createAccessMiddleware(options: AccessMiddlewareOptions) {
  const { type, redirectOnMissing = false } = options;

  return async (c: Context<AppEnv>, next: Next) => {
    // Skip auth in dev mode or E2E test mode
    if (isDevMode(c.env) || isE2ETestMode(c.env)) {
      c.set('accessUser', { email: 'dev@localhost', name: 'Dev User' });
      return next();
    }

    const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN;
    const expectedAud = c.env.CF_ACCESS_AUD;
    const gatewayToken = extractGatewayToken(c);

    if (gatewayToken && timingSafeEqual(gatewayToken.token, c.env.MOLTBOT_GATEWAY_TOKEN)) {
      return authenticateGatewayToken(c, next, gatewayToken);
    }

    // Check if CF Access is configured
    if (!teamDomain || !expectedAud) {
      if (type === 'json') {
        return c.json(
          {
            error: 'Cloudflare Access not configured',
            hint: 'Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD environment variables',
          },
          500,
        );
      } else {
        return c.html(
          `
          <html>
            <body>
              <h1>Admin UI Not Configured</h1>
              <p>Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD environment variables.</p>
            </body>
          </html>
        `,
          500,
        );
      }
    }

    // Get JWT
    const jwt = extractJWT(c);

    if (!jwt) {
      if (type === 'html' && c.env.MOLTBOT_GATEWAY_TOKEN) {
        return c.html(gatewayLoginHtml(c, teamDomain), 401);
      }

      if (type === 'html' && redirectOnMissing) {
        return c.redirect(`https://${teamDomain}`, 302);
      }

      if (type === 'json') {
        return c.json(
          {
            error: 'Unauthorized',
            hint: 'Missing Cloudflare Access JWT or gateway token.',
          },
          401,
        );
      } else {
        return c.html(
          `
          <html>
            <body>
              <h1>Unauthorized</h1>
              <p>Missing Cloudflare Access token.</p>
              <a href="https://${teamDomain}">Login</a>
            </body>
          </html>
        `,
          401,
        );
      }
    }

    // Verify JWT
    try {
      const payload = await verifyAccessJWT(jwt, teamDomain, expectedAud);
      c.set('accessUser', { email: payload.email, name: payload.name });
      await next();
    } catch (err) {
      console.error('Access JWT verification failed:', err);

      if (type === 'json') {
        return c.json(
          {
            error: 'Unauthorized',
            details: err instanceof Error ? err.message : 'JWT verification failed',
          },
          401,
        );
      } else {
        return c.html(
          `
          <html>
            <body>
              <h1>Unauthorized</h1>
              <p>Your Cloudflare Access session is invalid or expired.</p>
              <a href="https://${teamDomain}">Login again</a>
            </body>
          </html>
        `,
          401,
        );
      }
    }
  };
}
