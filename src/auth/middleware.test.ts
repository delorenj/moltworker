import { describe, it, expect, vi, beforeEach } from 'vitest';
import { isDevMode, isE2ETestMode, extractJWT, extractGatewayToken } from './middleware';
import type { OpenClawEnv } from '../types';
import type { Context } from 'hono';
import type { AppEnv } from '../types';
import { createMockEnv } from '../test-utils';

function createMockContext(options: {
  jwtHeader?: string;
  authorization?: string;
  gatewayHeader?: string;
  cookies?: string;
  url?: string;
}): Context<AppEnv> {
  const headers = new Headers();
  if (options.jwtHeader) {
    headers.set('CF-Access-JWT-Assertion', options.jwtHeader);
  }
  if (options.authorization) {
    headers.set('Authorization', options.authorization);
  }
  if (options.gatewayHeader) {
    headers.set('X-OpenClaw-Gateway-Token', options.gatewayHeader);
  }
  if (options.cookies) {
    headers.set('Cookie', options.cookies);
  }

  return {
    req: {
      url: options.url ?? 'https://example.com/',
      header: (name: string) => headers.get(name),
      raw: {
        headers,
      },
    },
  } as unknown as Context<AppEnv>;
}

describe('isDevMode', () => {
  it('returns true when DEV_MODE is "true"', () => {
    const env = createMockEnv({ DEV_MODE: 'true' });
    expect(isDevMode(env)).toBe(true);
  });

  it('returns false when DEV_MODE is undefined', () => {
    const env = createMockEnv();
    expect(isDevMode(env)).toBe(false);
  });

  it('returns false when DEV_MODE is "false"', () => {
    const env = createMockEnv({ DEV_MODE: 'false' });
    expect(isDevMode(env)).toBe(false);
  });

  it('returns false when DEV_MODE is any other value', () => {
    const env = createMockEnv({ DEV_MODE: 'yes' });
    expect(isDevMode(env)).toBe(false);
  });

  it('returns false when DEV_MODE is empty string', () => {
    const env = createMockEnv({ DEV_MODE: '' });
    expect(isDevMode(env)).toBe(false);
  });
});

describe('isE2ETestMode', () => {
  it('returns true when E2E_TEST_MODE is "true"', () => {
    const env = createMockEnv({ E2E_TEST_MODE: 'true' });
    expect(isE2ETestMode(env)).toBe(true);
  });

  it('returns false when E2E_TEST_MODE is undefined', () => {
    const env = createMockEnv();
    expect(isE2ETestMode(env)).toBe(false);
  });

  it('returns false when E2E_TEST_MODE is "false"', () => {
    const env = createMockEnv({ E2E_TEST_MODE: 'false' });
    expect(isE2ETestMode(env)).toBe(false);
  });

  it('returns false when E2E_TEST_MODE is any other value', () => {
    const env = createMockEnv({ E2E_TEST_MODE: 'yes' });
    expect(isE2ETestMode(env)).toBe(false);
  });
});

describe('extractJWT', () => {
  it('extracts JWT from CF-Access-JWT-Assertion header', () => {
    const jwt = 'header.payload.signature';
    const c = createMockContext({ jwtHeader: jwt });
    expect(extractJWT(c)).toBe(jwt);
  });

  it('extracts JWT from CF_Authorization cookie', () => {
    const jwt = 'cookie.payload.signature';
    const c = createMockContext({ cookies: `CF_Authorization=${jwt}` });
    expect(extractJWT(c)).toBe(jwt);
  });

  it('extracts JWT from CF_Authorization cookie with other cookies', () => {
    const jwt = 'cookie.payload.signature';
    const c = createMockContext({
      cookies: `other=value; CF_Authorization=${jwt}; another=test`,
    });
    expect(extractJWT(c)).toBe(jwt);
  });

  it('prefers header over cookie', () => {
    const headerJwt = 'header.jwt.token';
    const cookieJwt = 'cookie.jwt.token';
    const c = createMockContext({
      jwtHeader: headerJwt,
      cookies: `CF_Authorization=${cookieJwt}`,
    });
    expect(extractJWT(c)).toBe(headerJwt);
  });

  it('returns null when no JWT present', () => {
    const c = createMockContext({});
    expect(extractJWT(c)).toBeNull();
  });

  it('returns null when cookie header exists but no CF_Authorization', () => {
    const c = createMockContext({ cookies: 'other=value; session=abc123' });
    expect(extractJWT(c)).toBeNull();
  });

  it('handles cookie with whitespace', () => {
    const jwt = 'spaced.payload.signature';
    const c = createMockContext({ cookies: `  CF_Authorization=${jwt}  ` });
    expect(extractJWT(c)).toBe(jwt);
  });
});

describe('extractGatewayToken', () => {
  it('extracts gateway token from query string', () => {
    const c = createMockContext({ url: 'https://example.com/?token=query-token' });
    expect(extractGatewayToken(c)).toEqual({ token: 'query-token', source: 'query' });
  });

  it('extracts gateway token from bearer authorization header', () => {
    const c = createMockContext({ authorization: 'Bearer bearer-token' });
    expect(extractGatewayToken(c)).toEqual({ token: 'bearer-token', source: 'authorization' });
  });

  it('extracts gateway token from explicit header', () => {
    const c = createMockContext({ gatewayHeader: 'header-token' });
    expect(extractGatewayToken(c)).toEqual({ token: 'header-token', source: 'header' });
  });

  it('extracts gateway token from session cookie', () => {
    const c = createMockContext({
      cookies: 'other=value; openclaw_gateway_auth=cookie-token',
    });
    expect(extractGatewayToken(c)).toEqual({ token: 'cookie-token', source: 'cookie' });
  });
});

describe('createAccessMiddleware', () => {
  // Import the function dynamically to allow mocking
  let createAccessMiddleware: typeof import('./middleware').createAccessMiddleware;

  beforeEach(async () => {
    vi.resetModules();
    const module = await import('./middleware');
    createAccessMiddleware = module.createAccessMiddleware;
  });

  // Helper to create a mock context with full implementation
  function createFullMockContext(options: {
    env?: Partial<OpenClawEnv>;
    jwtHeader?: string;
    authorization?: string;
    gatewayHeader?: string;
    cookies?: string;
    method?: string;
    url?: string;
  }): {
    c: Context<AppEnv>;
    jsonMock: ReturnType<typeof vi.fn>;
    htmlMock: ReturnType<typeof vi.fn>;
    redirectMock: ReturnType<typeof vi.fn>;
    headerMock: ReturnType<typeof vi.fn>;
    setMock: ReturnType<typeof vi.fn>;
  } {
    const headers = new Headers();
    if (options.jwtHeader) {
      headers.set('CF-Access-JWT-Assertion', options.jwtHeader);
    }
    if (options.authorization) {
      headers.set('Authorization', options.authorization);
    }
    if (options.gatewayHeader) {
      headers.set('X-OpenClaw-Gateway-Token', options.gatewayHeader);
    }
    if (options.cookies) {
      headers.set('Cookie', options.cookies);
    }

    const jsonMock = vi.fn().mockReturnValue(new Response());
    const htmlMock = vi.fn().mockReturnValue(new Response());
    const redirectMock = vi.fn().mockReturnValue(new Response());
    const headerMock = vi.fn();
    const setMock = vi.fn();

    const c = {
      req: {
        url: options.url ?? 'https://example.com/',
        method: options.method ?? 'GET',
        header: (name: string) => headers.get(name),
        raw: { headers },
      },
      env: createMockEnv(options.env),
      json: jsonMock,
      html: htmlMock,
      redirect: redirectMock,
      header: headerMock,
      set: setMock,
    } as unknown as Context<AppEnv>;

    return { c, jsonMock, htmlMock, redirectMock, headerMock, setMock };
  }

  it('skips auth and sets dev user when DEV_MODE is true', async () => {
    const { c, setMock } = createFullMockContext({ env: { DEV_MODE: 'true' } });
    const middleware = createAccessMiddleware({ type: 'json' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).toHaveBeenCalled();
    expect(setMock).toHaveBeenCalledWith('accessUser', {
      email: 'dev@localhost',
      name: 'Dev User',
    });
  });

  it('skips auth and sets dev user when E2E_TEST_MODE is true', async () => {
    const { c, setMock } = createFullMockContext({ env: { E2E_TEST_MODE: 'true' } });
    const middleware = createAccessMiddleware({ type: 'json' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).toHaveBeenCalled();
    expect(setMock).toHaveBeenCalledWith('accessUser', {
      email: 'dev@localhost',
      name: 'Dev User',
    });
  });

  it('returns 500 JSON error when CF Access not configured', async () => {
    const { c, jsonMock } = createFullMockContext({ env: {} });
    const middleware = createAccessMiddleware({ type: 'json' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'Cloudflare Access not configured' }),
      500,
    );
  });

  it('returns 500 HTML error when CF Access not configured', async () => {
    const { c, htmlMock } = createFullMockContext({ env: {} });
    const middleware = createAccessMiddleware({ type: 'html' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(htmlMock).toHaveBeenCalledWith(expect.stringContaining('Admin UI Not Configured'), 500);
  });

  it('returns 401 JSON error when JWT is missing', async () => {
    const { c, jsonMock } = createFullMockContext({
      env: { CF_ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', CF_ACCESS_AUD: 'aud123' },
    });
    const middleware = createAccessMiddleware({ type: 'json' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(jsonMock).toHaveBeenCalledWith(expect.objectContaining({ error: 'Unauthorized' }), 401);
  });

  it('returns 401 HTML error when JWT is missing', async () => {
    const { c, htmlMock } = createFullMockContext({
      env: { CF_ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', CF_ACCESS_AUD: 'aud123' },
    });
    const middleware = createAccessMiddleware({ type: 'html' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(htmlMock).toHaveBeenCalledWith(expect.stringContaining('Unauthorized'), 401);
  });

  it('shows gateway token login when HTML auth is missing and gateway token is configured', async () => {
    const { c, htmlMock } = createFullMockContext({
      env: {
        CF_ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com',
        CF_ACCESS_AUD: 'aud123',
        MOLTBOT_GATEWAY_TOKEN: 'gateway-secret',
      },
    });
    const middleware = createAccessMiddleware({ type: 'html' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(htmlMock).toHaveBeenCalledWith(expect.stringContaining('Gateway token'), 401);
  });

  it('authenticates with gateway token from bearer header', async () => {
    const { c, setMock, headerMock } = createFullMockContext({
      env: { MOLTBOT_GATEWAY_TOKEN: 'gateway-secret' },
      authorization: 'Bearer gateway-secret',
    });
    const middleware = createAccessMiddleware({ type: 'json' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).toHaveBeenCalled();
    expect(setMock).toHaveBeenCalledWith('accessUser', {
      email: 'gateway-token@openclaw.local',
      name: 'Gateway Token',
    });
    expect(headerMock).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining('openclaw_gateway_auth=gateway-secret'),
    );
  });

  it('sets a session cookie and redirects when gateway token comes from URL', async () => {
    const { c, redirectMock, headerMock } = createFullMockContext({
      env: { MOLTBOT_GATEWAY_TOKEN: 'gateway-secret' },
      url: 'https://example.com/_admin/?token=gateway-secret',
    });
    const middleware = createAccessMiddleware({ type: 'html' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(headerMock).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining('openclaw_gateway_auth=gateway-secret'),
    );
    expect(redirectMock).toHaveBeenCalledWith('/_admin/', 302);
  });

  it('rejects mismatched gateway token', async () => {
    const { c, jsonMock } = createFullMockContext({
      env: { MOLTBOT_GATEWAY_TOKEN: 'gateway-secret' },
      authorization: 'Bearer wrong-token',
    });
    const middleware = createAccessMiddleware({ type: 'json' });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'Cloudflare Access not configured' }),
      500,
    );
  });

  it('redirects when JWT is missing and redirectOnMissing is true', async () => {
    const { c, redirectMock } = createFullMockContext({
      env: { CF_ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', CF_ACCESS_AUD: 'aud123' },
    });
    const middleware = createAccessMiddleware({ type: 'html', redirectOnMissing: true });
    const next = vi.fn();

    await middleware(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(redirectMock).toHaveBeenCalledWith('https://team.cloudflareaccess.com', 302);
  });
});
