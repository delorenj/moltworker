#!/bin/bash
# Startup script for OpenClaw in Cloudflare Sandbox
# This script:
# 1. Runs openclaw onboard --non-interactive to configure from env vars
# 2. Patches config for features onboard doesn't cover (channels, gateway auth)
# 3. Starts the gateway
#
# NOTE: Persistence (backup/restore) is handled by the Sandbox SDK at the
# Worker level, not inside the container. The Worker calls createBackup()
# and restoreBackup() which use squashfs snapshots stored in R2.
# No rclone or R2 credentials are needed inside the container.
#
# Rollout marker: 2026-05-14-v7-gateway-token-refresh

set -e

GATEWAY_ALREADY_RUNNING=false
if pgrep -f "openclaw gateway" > /dev/null 2>&1; then
    echo "OpenClaw gateway is already running."
    GATEWAY_ALREADY_RUNNING=true
fi

CONFIG_DIR="/root/.openclaw"
CONFIG_FILE="$CONFIG_DIR/openclaw.json"
WORKSPACE_DIR="/root/clawd"
SKILLS_DIR="/root/clawd/skills"

echo "Config directory: $CONFIG_DIR"

mkdir -p "$CONFIG_DIR"

redact_secrets() {
    sed -E 's/tskey-auth-[A-Za-z0-9_-]+/[REDACTED]/g'
}

tailscale_is_running() {
    tailscale --socket="$1" status --json >/tmp/tailscale-status.json 2>/tmp/tailscale-status.err \
        && node -e "const fs=require('fs'); const s=JSON.parse(fs.readFileSync('/tmp/tailscale-status.json','utf8')); process.exit(s.BackendState === 'Running' ? 0 : 1);"
}

print_tailscale_endpoint() {
    tailscale --socket="$1" status --json 2>/dev/null \
        | node -e "let s=''; process.stdin.on('data', d => s += d); process.stdin.on('end', () => { try { const j=JSON.parse(s); const self=j.Self || {}; const dns=typeof self.DNSName === 'string' ? self.DNSName.replace(/[.]$/, '') : ''; const ips=Array.isArray(self.TailscaleIPs) ? self.TailscaleIPs : []; if (dns) console.log('Tailscale DNS: https://' + dns); else if (ips[0]) console.log('Tailscale IP: http://' + ips[0]); } catch {} });"
}

start_tailscale_if_configured() {
    if [ -z "$TAILSCALE_AUTHKEY" ]; then
        echo "Tailscale: disabled (TAILSCALE_AUTHKEY not set)"
        return 0
    fi

    if ! command -v tailscaled >/dev/null 2>&1 || ! command -v tailscale >/dev/null 2>&1; then
        echo "Tailscale: tailscale binaries are missing; continuing without tailnet access"
        return 0
    fi

    local tailscale_socket="${TAILSCALE_SOCKET:-/var/run/tailscale/tailscaled.sock}"
    local tailscale_state_dir="${TAILSCALE_STATE_DIR:-/home/openclaw/tailscale}"
    local tailscale_hostname="${TAILSCALE_HOSTNAME:-openclaw-dami}"
    local tailscale_serve_target="${TAILSCALE_SERVE_TARGET:-http://127.0.0.1:18789}"

    mkdir -p "$(dirname "$tailscale_socket")" "$tailscale_state_dir"
    chmod 700 "$tailscale_state_dir" 2>/dev/null || true

    if ! tailscale --socket="$tailscale_socket" status --json >/dev/null 2>&1; then
        echo "Tailscale: starting tailscaled in userspace-networking mode..."
        rm -f "$tailscale_socket" 2>/dev/null || true
        tailscaled \
            --tun=userspace-networking \
            --socket="$tailscale_socket" \
            --statedir="$tailscale_state_dir" \
            --state="$tailscale_state_dir/tailscaled.state" \
            >/tmp/tailscaled.log 2>&1 &

        for _ in $(seq 1 30); do
            [ -S "$tailscale_socket" ] && break
            sleep 0.5
        done
    else
        echo "Tailscale: tailscaled already responding"
    fi

    if [ ! -S "$tailscale_socket" ]; then
        echo "Tailscale: socket did not appear; continuing without tailnet access"
        tail -n 50 /tmp/tailscaled.log 2>/dev/null | redact_secrets || true
        return 0
    fi

    if ! tailscale_is_running "$tailscale_socket"; then
        echo "Tailscale: joining tailnet as ${tailscale_hostname}..."
        printf '%s' "$TAILSCALE_AUTHKEY" > /tmp/tailscale-authkey
        chmod 600 /tmp/tailscale-authkey
        if ! tailscale --socket="$tailscale_socket" up \
            --auth-key=file:/tmp/tailscale-authkey \
            --hostname="$tailscale_hostname" \
            --accept-dns=true \
            --timeout=45s \
            >/tmp/tailscale-up.log 2>&1; then
            echo "Tailscale: join failed; continuing without tailnet access"
            tail -n 80 /tmp/tailscale-up.log 2>/dev/null | redact_secrets || true
            rm -f /tmp/tailscale-authkey
            return 0
        fi
        rm -f /tmp/tailscale-authkey
    else
        echo "Tailscale: already joined to tailnet"
    fi

    if tailscale --socket="$tailscale_socket" serve --bg --yes "$tailscale_serve_target" >/tmp/tailscale-serve.log 2>&1; then
        echo "Tailscale: Serve forwarding to ${tailscale_serve_target}"
        print_tailscale_endpoint "$tailscale_socket" || true
    else
        echo "Tailscale: Serve setup failed; tailnet may be joined but gateway forwarding is unavailable"
        tail -n 80 /tmp/tailscale-serve.log 2>/dev/null | redact_secrets || true
    fi
}

start_tailscale_if_configured

if [ "$GATEWAY_ALREADY_RUNNING" = "true" ]; then
    echo "OpenClaw gateway is already running, exiting."
    exit 0
fi

# ============================================================
# ONBOARD (only if no config exists yet)
# ============================================================
if [ ! -f "$CONFIG_FILE" ]; then
    echo "No existing config found, running openclaw onboard..."

    # Determine auth choice — openclaw onboard reads the actual key values
    # from environment variables (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)
    # so we only pass --auth-choice, never the key itself, to avoid
    # exposing secrets in process arguments visible via ps/proc.
    AUTH_ARGS=""
    if [ -n "$CLOUDFLARE_AI_GATEWAY_AUTH_TOKEN" ] && [ "$CLOUDFLARE_AI_GATEWAY_API_KEY" = "custom-local" ]; then
        AUTH_ARGS="--auth-choice skip"
    elif [ -n "$CLOUDFLARE_AI_GATEWAY_API_KEY" ] && [ -n "$CF_AI_GATEWAY_ACCOUNT_ID" ] && [ -n "$CF_AI_GATEWAY_GATEWAY_ID" ]; then
        AUTH_ARGS="--auth-choice cloudflare-ai-gateway-api-key --cloudflare-ai-gateway-account-id $CF_AI_GATEWAY_ACCOUNT_ID --cloudflare-ai-gateway-gateway-id $CF_AI_GATEWAY_GATEWAY_ID"
    elif [ -n "$ANTHROPIC_API_KEY" ]; then
        AUTH_ARGS="--auth-choice apiKey"
    elif [ -n "$OPENAI_API_KEY" ]; then
        AUTH_ARGS="--auth-choice openai-api-key"
    fi

    openclaw onboard --non-interactive --accept-risk \
        --mode local \
        $AUTH_ARGS \
        --gateway-port 18789 \
        --gateway-bind lan \
        --skip-channels \
        --skip-skills \
        --skip-health

    echo "Onboard completed"
else
    echo "Using existing config"
fi

# ============================================================
# PATCH CONFIG (channels, gateway auth, trusted proxies)
# ============================================================
# openclaw onboard handles provider/model config, but we need to patch in:
# - Channel config (Telegram, Discord, Slack)
# - Gateway token auth
# - Trusted proxies for sandbox networking
# - Base URL override for legacy AI Gateway path
node << 'EOFPATCH'
const fs = require('fs');

const configPath = '/root/.openclaw/openclaw.json';
console.log('Patching config at:', configPath);
let config = {};

try {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
} catch (e) {
    console.log('Starting with empty config');
}

config.gateway = config.gateway || {};
config.channels = config.channels || {};

// Gateway configuration
config.gateway.port = 18789;
config.gateway.mode = 'local';
config.gateway.trustedProxies = ['10.1.0.0'];

config.gateway.controlUi = config.gateway.controlUi || {};
config.gateway.controlUi.allowedOrigins = ['*'];

if (process.env.OPENCLAW_GATEWAY_TOKEN) {
    config.gateway.auth = config.gateway.auth || {};
    config.gateway.auth.mode = 'token';
    config.gateway.auth.token = process.env.OPENCLAW_GATEWAY_TOKEN;
}

if (process.env.TAILSCALE_AUTHKEY) {
    config.gateway.auth = config.gateway.auth || {};
    config.gateway.auth.allowTailscale = true;
    config.gateway.tailscale = config.gateway.tailscale || {};
    config.gateway.tailscale.mode = 'off';
}

// Allow any origin to connect to the gateway control UI.
// The gateway runs inside a Cloudflare Container behind the Worker, which
// proxies requests from the public workers.dev domain. Without this,
// openclaw >= 2026.2.26 rejects WebSocket connections because the browser's
// origin (https://....workers.dev) doesn't match the gateway's localhost.
// Security is handled by CF Access + gateway token auth, not origin checks.
config.gateway.controlUi = config.gateway.controlUi || {};
config.gateway.controlUi.allowedOrigins = ['*'];

if (process.env.OPENCLAW_DEV_MODE === 'true') {
    config.gateway.controlUi = config.gateway.controlUi || {};
    config.gateway.controlUi.allowInsecureAuth = true;
}

// Legacy AI Gateway base URL override:
// ANTHROPIC_BASE_URL is picked up natively by the Anthropic SDK,
// so we don't need to patch the provider config. Writing a provider
// entry without a models array breaks OpenClaw's config validation.

// AI Gateway model override (CF_AI_GATEWAY_MODEL=provider/model-id)
// Adds a provider entry for any AI Gateway provider and sets it as default model.
// Examples:
//   workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast
//   openai/gpt-4o
//   anthropic/claude-sonnet-4-5
if (process.env.CF_AI_GATEWAY_MODEL) {
    const raw = process.env.CF_AI_GATEWAY_MODEL;
    const slashIdx = raw.indexOf('/');
    const gwProvider = raw.substring(0, slashIdx);
    const modelId = raw.substring(slashIdx + 1);

    const accountId = process.env.CF_AI_GATEWAY_ACCOUNT_ID;
    const gatewayId = process.env.CF_AI_GATEWAY_GATEWAY_ID;
    const apiKeyRaw = process.env.CLOUDFLARE_AI_GATEWAY_API_KEY;
    const apiKey = apiKeyRaw && apiKeyRaw !== 'custom-local' ? apiKeyRaw : undefined;
    const apiKeyMarker = apiKeyRaw === 'custom-local' ? 'CLOUDFLARE_AI_GATEWAY_API_KEY' : undefined;
    const gatewayAuthToken = process.env.CLOUDFLARE_AI_GATEWAY_AUTH_TOKEN;

    let baseUrl;
    if (accountId && gatewayId) {
        baseUrl = 'https://gateway.ai.cloudflare.com/v1/' + accountId + '/' + gatewayId + '/' + gwProvider;
        if (gwProvider === 'workers-ai') baseUrl += '/v1';
    } else if (gwProvider === 'workers-ai' && process.env.CF_ACCOUNT_ID) {
        baseUrl = 'https://api.cloudflare.com/client/v4/accounts/' + process.env.CF_ACCOUNT_ID + '/ai/v1';
    }

    if (baseUrl && (apiKey || apiKeyMarker || gatewayAuthToken)) {
        const api = gwProvider === 'anthropic' ? 'anthropic-messages' : 'openai-completions';
        const providerName = 'cf-ai-gw-' + gwProvider;
        const providerConfig = {
            baseUrl: baseUrl,
            api: api,
            models: [{ id: modelId, name: modelId, contextWindow: 131072, maxTokens: 8192 }],
        };
        if (apiKey) providerConfig.apiKey = apiKey;
        if (apiKeyMarker) providerConfig.apiKey = apiKeyMarker;
        if (gatewayAuthToken) {
            providerConfig.headers = {
                'cf-aig-authorization': 'Bearer ' + gatewayAuthToken,
            };
        }

        config.models = config.models || {};
        config.models.providers = config.models.providers || {};
        config.models.providers[providerName] = providerConfig;
        config.agents = config.agents || {};
        config.agents.defaults = config.agents.defaults || {};
        config.agents.defaults.model = { primary: providerName + '/' + modelId };
        console.log('AI Gateway model override: provider=' + providerName + ' model=' + modelId + ' via ' + baseUrl);
    } else {
        console.warn('CF_AI_GATEWAY_MODEL set but missing required config (account ID, gateway ID, or API key)');
    }
}

// Telegram configuration
// Overwrite entire channel object to drop stale keys from old R2 backups
// that would fail OpenClaw's strict config validation (see #47)
if (process.env.TELEGRAM_BOT_TOKEN) {
    const dmPolicy = process.env.TELEGRAM_DM_POLICY || 'pairing';
    config.channels.telegram = {
        botToken: process.env.TELEGRAM_BOT_TOKEN,
        enabled: true,
        dmPolicy: dmPolicy,
    };
    if (process.env.TELEGRAM_DM_ALLOW_FROM) {
        config.channels.telegram.allowFrom = process.env.TELEGRAM_DM_ALLOW_FROM.split(',');
    } else if (dmPolicy === 'open') {
        config.channels.telegram.allowFrom = ['*'];
    }
}

// Discord configuration
// Discord uses a nested dm object: dm.policy, dm.allowFrom (per DiscordDmConfig)
if (process.env.DISCORD_BOT_TOKEN) {
    const dmPolicy = process.env.DISCORD_DM_POLICY || 'pairing';
    const dm = { policy: dmPolicy };
    if (dmPolicy === 'open') {
        dm.allowFrom = ['*'];
    }
    config.channels.discord = {
        token: process.env.DISCORD_BOT_TOKEN,
        enabled: true,
        dm: dm,
    };
}

// Slack configuration
if (process.env.SLACK_BOT_TOKEN && process.env.SLACK_APP_TOKEN) {
    config.channels.slack = {
        botToken: process.env.SLACK_BOT_TOKEN,
        appToken: process.env.SLACK_APP_TOKEN,
        enabled: true,
    };
}

fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
console.log('Configuration patched successfully');
EOFPATCH

# ============================================================
# START GATEWAY
# ============================================================
echo "Starting OpenClaw Gateway..."
echo "Gateway will be available on port 18789"

rm -f /tmp/openclaw-gateway.lock 2>/dev/null || true
rm -f "$CONFIG_DIR/gateway.lock" 2>/dev/null || true

echo "Dev mode: ${OPENCLAW_DEV_MODE:-false}"

# Gateway token (if set) is already written to openclaw.json by the config
# patch above (gateway.auth.token). We deliberately avoid passing --token on
# the command line because CLI arguments are visible to all processes in the
# container via ps/proc.
if [ -n "$OPENCLAW_GATEWAY_TOKEN" ]; then
    echo "Starting gateway with token auth..."
else
    echo "Starting gateway with device pairing (no token)..."
fi
exec openclaw gateway --port 18789 --verbose --allow-unconfigured --bind lan
