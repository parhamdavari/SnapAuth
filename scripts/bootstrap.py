#!/usr/bin/env python3
"""Generate environment secrets and FusionAuth kickstart configuration."""
from __future__ import annotations

import json
import secrets
import sys
import uuid
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

ENV_FILE = Path(".env")
KICKSTART_PATH = Path("kickstart/kickstart.json")

DEFAULTS = {
    "FUSIONAUTH_BASE_URL": "http://fusionauth:9011",
    "FUSIONAUTH_TENANT_ID": "d7d09513-a3f5-401c-9685-34ab6c552453",
    "FUSIONAUTH_APPLICATION_NAME": "SnapAuth",
    "FUSIONAUTH_ADMIN_USERNAME": "admin",
    "FUSIONAUTH_ADMIN_APPLICATION_ID": "3c219e58-ed0e-4b18-ad48-f4f92793ae32",
    "FUSIONAUTH_AUTHORIZED_REDIRECT_URLS": "http://localhost:3000/oauth-callback",
    "FUSIONAUTH_APP_MEMORY": "512M",
    "FUSIONAUTH_APP_RUNTIME_MODE": "production",
    "SNAPAUTH_SERVICE_PORT": "8080",
    "DB_HOST": "db",
    "DB_PORT": "5432",
    "DB_NAME": "fusionauth",
    "DB_USER": "fusionauth",
}

GENERATED_VALUES = {
    "FUSIONAUTH_API_KEY_ID": lambda: str(uuid.uuid4()),
    "FUSIONAUTH_API_KEY": lambda: secrets.token_hex(32),
    "FUSIONAUTH_APPLICATION_ID": lambda: str(uuid.uuid4()),
    "FUSIONAUTH_CLIENT_SECRET": lambda: secrets.token_urlsafe(32),
    "FUSIONAUTH_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(24),
    "FUSIONAUTH_ADMIN_USER_ID": lambda: str(uuid.uuid4()),
    "DB_PASSWORD": lambda: secrets.token_urlsafe(24),
}

PLACEHOLDER_VALUES = {
    "changeme",
    "changeme-api-key",
    "CHANGE_ME",
    "CHANGEME",
    "replace-with-app-id",
    "replace-with-api-key",
    "password",
    "admin",
    "super-secret-secret-that-should-be-regenerated-for-production",
}

KEY_ORDER = [
    "FUSIONAUTH_BASE_URL",
    "FUSIONAUTH_TENANT_ID",
    "FUSIONAUTH_APPLICATION_NAME",
    "FUSIONAUTH_API_KEY_ID",
    "FUSIONAUTH_API_KEY",
    "FUSIONAUTH_APPLICATION_ID",
    "FUSIONAUTH_CLIENT_SECRET",
    "FUSIONAUTH_ADMIN_USERNAME",
    "FUSIONAUTH_ADMIN_PASSWORD",
    "FUSIONAUTH_ADMIN_USER_ID",
    "FUSIONAUTH_ADMIN_APPLICATION_ID",
    "FUSIONAUTH_AUTHORIZED_REDIRECT_URLS",
    "FUSIONAUTH_APP_MEMORY",
    "FUSIONAUTH_APP_RUNTIME_MODE",
    "JWT_EXPECTED_ISS",
    "JWT_EXPECTED_AUD",
    "JWKS_CACHE_TTL_SECONDS",
    "SNAPAUTH_SERVICE_PORT",
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
]

REQUIRED_KEYS = {
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
}


def parse_env(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.exists():
        return data

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def is_missing(key: str, value: str | None) -> bool:
    if value is None:
        return True
    stripped = value.strip()
    if stripped == "":
        return True
    if stripped in PLACEHOLDER_VALUES:
        return True
    if key == "DB_PASSWORD" and stripped in {"fusionauth", "password"}:
        return True
    return False


def derive_jwt_iss(base_url: str) -> str:
    base = base_url.strip()
    if not base:
        return "http://fusionauth:9011"
    parsed = urlparse(base)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return base.rstrip("/")


def write_env(path: Path, env: Dict[str, str]) -> None:
    lines: List[str] = [
        "# Managed by scripts/bootstrap.py",
        "# Re-run the script after editing values to refresh generated secrets.",
        "",
    ]

    recorded = set()
    for key in KEY_ORDER:
        if key in env:
            lines.append(f"{key}={env[key]}")
            recorded.add(key)

    extras = sorted(k for k in env if k not in recorded)
    if extras:
        lines.append("")
        lines.append("# Additional settings")
        for key in extras:
            lines.append(f"{key}={env[key]}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_kickstart(path: Path, env: Dict[str, str]) -> None:
    redirect_urls = [
        url.strip()
        for url in env.get("FUSIONAUTH_AUTHORIZED_REDIRECT_URLS", "").split(",")
        if url.strip()
    ] or ["http://localhost:3000/oauth-callback"]

    payload = {
        "variables": {
            "defaultTenantId": env["FUSIONAUTH_TENANT_ID"],
            "adminUsername": env["FUSIONAUTH_ADMIN_USERNAME"],
            "adminPassword": env["FUSIONAUTH_ADMIN_PASSWORD"],
            "applicationName": env["FUSIONAUTH_APPLICATION_NAME"],
            "applicationId": env["FUSIONAUTH_APPLICATION_ID"],
            "adminApplicationId": env["FUSIONAUTH_ADMIN_APPLICATION_ID"],
            "adminUserId": env["FUSIONAUTH_ADMIN_USER_ID"],
            "apiKeyId": env["FUSIONAUTH_API_KEY_ID"],
            "apiKey": env["FUSIONAUTH_API_KEY"],
            "clientSecret": env["FUSIONAUTH_CLIENT_SECRET"],
            "issuer": env["JWT_EXPECTED_ISS"],
        },
        "apiKeys": [
            {
                "id": "#{apiKeyId}",
                "key": "#{apiKey}",
                "description": "SnapAuth API Key",
            }
        ],
        "requests": [
            {
                "method": "PATCH",
                "url": "/api/tenant/#{defaultTenantId}",
                "body": {
                    "tenant": {
                        "issuer": "#{issuer}"
                    }
                },
            },
            {
                "method": "POST",
                "url": "/api/key/generate/#{defaultTenantId}",
                "body": {
                    "key": {
                        "algorithm": "RS256",
                        "name": "SnapAuth Signing Key",
                        "length": 2048,
                    }
                },
            },
            {
                "method": "POST",
                "url": "/api/user/#{adminUserId}",
                "body": {
                    "user": {
                        "username": "#{adminUsername}",
                        "password": "#{adminPassword}",
                        "firstName": "Admin",
                        "lastName": "User",
                    }
                },
            },
            {
                "method": "POST",
                "url": "/api/application/#{applicationId}",
                "body": {
                    "application": {
                        "id": "#{applicationId}",
                        "name": "#{applicationName}",
                        "tenantId": "#{defaultTenantId}",
                        "oauthConfiguration": {
                            "authorizedRedirectURLs": redirect_urls,
                            "clientSecret": "#{clientSecret}",
                            "enabledGrants": ["authorization_code", "refresh_token"],
                            "generateRefreshTokens": True,
                            "requireClientAuthentication": True,
                        },
                        "loginConfiguration": {
                            "generateRefreshTokens": True,
                            "allowTokenRefresh": True,
                            "requireAuthentication": True,
                        },
                        "jwtConfiguration": {
                            "enabled": True,
                            "issuer": "#{issuer}",
                            "timeToLiveInSeconds": 3600,
                            "refreshTokenTimeToLiveInMinutes": 43200,
                        },
                        "roles": [
                            {
                                "name": "user",
                                "description": "Default user role",
                                "isDefault": True,
                            },
                            {
                                "name": "admin",
                                "description": "Administrator role",
                                "isDefault": False,
                            },
                        ],
                    }
                },
            },
            {
                "method": "POST",
                "url": "/api/user/registration/#{adminUserId}",
                "body": {
                    "registration": {
                        "applicationId": "#{applicationId}",
                        "roles": ["admin"],
                    },
                },
            },
            {
                "method": "POST",
                "url": "/api/user/registration/#{adminUserId}",
                "body": {
                    "registration": {
                        "applicationId": "#{adminApplicationId}",
                        "roles": ["admin"],
                    },
                },
            },
        ],
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    env = parse_env(ENV_FILE)

    for key, default in DEFAULTS.items():
        if is_missing(key, env.get(key)):
            env[key] = default

    for key, factory in GENERATED_VALUES.items():
        if is_missing(key, env.get(key)):
            env[key] = factory()

    if is_missing("JWKS_CACHE_TTL_SECONDS", env.get("JWKS_CACHE_TTL_SECONDS")):
        env["JWKS_CACHE_TTL_SECONDS"] = "300"

    if is_missing("JWT_EXPECTED_AUD", env.get("JWT_EXPECTED_AUD")):
        env["JWT_EXPECTED_AUD"] = env["FUSIONAUTH_APPLICATION_ID"]

    if is_missing("JWT_EXPECTED_ISS", env.get("JWT_EXPECTED_ISS")):
        env["JWT_EXPECTED_ISS"] = derive_jwt_iss(env["FUSIONAUTH_BASE_URL"])

    missing_required = [key for key in REQUIRED_KEYS if is_missing(key, env.get(key))]
    if missing_required:
        joined = ", ".join(missing_required)
        raise SystemExit(f"Missing required settings: {joined}")

    write_env(ENV_FILE, env)
    render_kickstart(KICKSTART_PATH, env)

    print("Updated .env and kickstart/kickstart.json with generated secrets.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
