#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CheckPC chat Lv.2 policy, VT validation, shared cache and rate limiting.

This module intentionally accepts only:
  * MD5 / SHA-1 / SHA-256
  * public IP addresses (IPv4/IPv6; IPv4:port is normalized to IPv4)
  * syntactically valid FQDNs

URLs, file paths, bare file names, email addresses and arbitrary search strings are
rejected before any external request is made.
"""
from __future__ import annotations

import copy
import ipaddress
import re
import threading
import time
from collections import OrderedDict
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import vt_post
from ioc_utils import _KNOWN_FILE_EXTS, _is_valid_tld

LV2_POLICY_OFF = "off"
LV2_POLICY_LOCAL = "local"
LV2_POLICY_LOCAL_VT_IOC = "local_vt_ioc"
LV2_POLICIES = (LV2_POLICY_OFF, LV2_POLICY_LOCAL, LV2_POLICY_LOCAL_VT_IOC)

VT_TOOL_NAME = "vt_ioc_lookup"
CROSS_HOST_TOOL_NAME = "cross_host_search"

_HASH_RE = re.compile(r"^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
_FQDN_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})\.?$"
)
_TEXT_IOC_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.:@/\\-])"
    r"([A-Za-z0-9][A-Za-z0-9._:-]{0,511})"
    r"(?![A-Za-z0-9_.:@/\\-])"
)

_CACHE_LOCK = threading.Lock()
_CACHE: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_RATE_LOCK = threading.Lock()
_LAST_REQUEST_STARTED = 0.0


def normalize_policy(value: object, default: str = LV2_POLICY_OFF) -> str:
    text = str(value or "").strip().lower()
    if text in LV2_POLICIES:
        return text
    return default if default in LV2_POLICIES else LV2_POLICY_OFF


def allowed_lv2_tools(policy: str, *, local_enabled: bool, vt_enabled: bool) -> set[str]:
    policy = normalize_policy(policy)
    allowed: set[str] = set()
    if policy in (LV2_POLICY_LOCAL, LV2_POLICY_LOCAL_VT_IOC) and local_enabled:
        allowed.add(CROSS_HOST_TOOL_NAME)
    if policy == LV2_POLICY_LOCAL_VT_IOC and vt_enabled:
        allowed.add(VT_TOOL_NAME)
    return allowed


def proxy_dict(proxy_url: str) -> Optional[dict]:
    proxy_url = str(proxy_url or "").strip()
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def _strip_ipv4_port(value: str) -> str:
    # Only the unambiguous IPv4:port form is accepted. Bracketed IPv6 with a
    # port is deliberately rejected so a URL-like value cannot be smuggled in.
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit() and 0 < int(port) <= 65535:
            try:
                if isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address):
                    return host
            except ValueError:
                pass
    return value


def validate_vt_ioc(value: object) -> tuple[bool, dict]:
    """Validate and normalize a value before VirusTotal transmission."""
    raw = str(value or "").strip()
    if not raw:
        return False, {"error": "ioc_value は必須です", "reason": "empty"}
    if len(raw) > 512:
        return False, {"error": "IOC値が長すぎるため外部照会を拒否しました", "reason": "too_long"}
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return False, {"error": "制御文字を含むIOC値の外部照会を拒否しました", "reason": "control_character"}

    lowered = raw.lower()
    if "://" in lowered:
        return False, {"error": "URLの外部照会は禁止されています。IPまたはFQDNだけを指定してください", "reason": "url_forbidden"}
    if "\\" in raw or "/" in raw:
        return False, {"error": "ファイルパスの外部照会は禁止されています", "reason": "filepath_forbidden"}
    if "@" in raw:
        return False, {"error": "メールアドレスの外部照会は禁止されています", "reason": "email_forbidden"}
    if any(ch.isspace() for ch in raw):
        return False, {"error": "空白を含む任意文字列は外部照会できません", "reason": "arbitrary_string"}

    if _HASH_RE.fullmatch(raw):
        return True, {"ioc": raw.lower(), "ioc_type": "hash"}

    ip_candidate = _strip_ipv4_port(raw)
    try:
        addr = ipaddress.ip_address(ip_candidate)
    except ValueError:
        addr = None
    if addr is not None:
        # ipaddress treats IPv4/IPv6 multicast as is_global=True.  The external
        # lookup policy permits only global *unicast* addresses, so special-use
        # classes must be rejected explicitly rather than relying on is_global.
        if (
            not addr.is_global
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_private
        ):
            return False, {
                "error": ("プライベート・予約・マルチキャスト・ループバック等の"
                          "非グローバルユニキャストIPはVTへ送信しません"),
                "reason": "non_global_ip",
            }
        return True, {"ioc": addr.compressed, "ioc_type": "ip"}

    fqdn = raw.rstrip(".").lower()
    suffix = "." + fqdn.rsplit(".", 1)[-1] if "." in fqdn else ""
    fqdn_match = bool(_FQDN_RE.fullmatch(raw))
    # .com is both a Windows executable suffix and a public TLD. Path-like
    # values are rejected above, so a bare syntactically valid *.com token is
    # treated as an FQDN rather than a filename.
    if suffix in _KNOWN_FILE_EXTS and not (suffix == ".com" and fqdn_match):
        return False, {"error": "ファイル名の外部照会は禁止されています", "reason": "filename_or_invalid_fqdn"}
    if fqdn_match and _is_valid_tld(fqdn):
        return True, {"ioc": fqdn, "ioc_type": "fqdn"}
    if fqdn_match:
        return False, {
            "error": "実在確認済みTLDではないためFQDNの外部照会を拒否しました",
            "reason": "invalid_tld",
        }

    # A bare filename such as malware.exe reaches here. Distinguish it from a
    # malformed FQDN so the prohibition is explicit in both UI and audit logs.
    if re.search(r"\.[A-Za-z0-9]{1,8}$", raw):
        return False, {"error": "ファイル名または不正なFQDNの外部照会は禁止されています", "reason": "filename_or_invalid_fqdn"}
    return False, {
        "error": "VT照会はMD5/SHA-1/SHA-256、外部IP、FQDNだけを受け付けます",
        "reason": "unsupported_ioc",
    }


def extract_vt_iocs_from_text(text: object) -> set[str]:
    """Extract exact, normalized VT-eligible IOC tokens from analyst text.

    This intentionally does not use substring containment.  Token boundaries
    prevent a model from deriving ``evil.example`` from
    ``cdn.evil.example`` or a 32-character MD5 from the prefix of a SHA-256.
    Tokens adjacent to URL/path/email delimiters are excluded, so mentioning a
    URL, file path, or email address does not implicitly authorize its host or
    filename as a separate external lookup.
    """
    raw = str(text or "")
    found: set[str] = set()
    for match in _TEXT_IOC_TOKEN_RE.finditer(raw):
        token = match.group(1)
        candidates = [token]
        # An explicitly written FQDN:port may authorize the FQDN component.
        # IPv4:port is already normalized by validate_vt_ioc().
        if token.count(":") == 1:
            host, port = token.rsplit(":", 1)
            if port.isdigit() and 0 < int(port) <= 65535:
                candidates.append(host)
        for candidate in candidates:
            valid, payload = validate_vt_ioc(candidate)
            if valid:
                found.add(str(payload["ioc"]).lower())
                break
    return found


def _masked_proxy(proxy_url: str) -> str:
    text = str(proxy_url or "")
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        if not parts.scheme or not parts.netloc:
            return "[REDACTED_PROXY]"
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parts.port:
            netloc += f":{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return "[REDACTED_PROXY]"


def redact_text(text: object, *, api_key: str = "", proxy_url: str = "") -> str:
    out = str(text or "")
    secrets = [str(api_key or ""), str(proxy_url or "")]
    try:
        parts = urlsplit(str(proxy_url or ""))
        secrets.extend([parts.username or "", parts.password or ""])
    except Exception:
        pass
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        out = out.replace(secret, "[REDACTED]")
    if proxy_url:
        out = out.replace(_masked_proxy(proxy_url), "[PROXY]")
    # Defense in depth for common proxy credential URL patterns not exactly
    # matching the configured value.
    out = re.sub(r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@", r"\1[REDACTED]@", out)
    return out


def redact_object(value: object, *, api_key: str = "", proxy_url: str = "") -> object:
    if isinstance(value, dict):
        return {str(k): redact_object(v, api_key=api_key, proxy_url=proxy_url) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_object(v, api_key=api_key, proxy_url=proxy_url) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_object(v, api_key=api_key, proxy_url=proxy_url) for v in value)
    if isinstance(value, str):
        return redact_text(value, api_key=api_key, proxy_url=proxy_url)
    return value


def _cache_get(key: str, ttl_seconds: float) -> Optional[dict]:
    now = time.monotonic()
    with _CACHE_LOCK:
        rec = _CACHE.get(key)
        if not rec:
            return None
        saved_at, result = rec
        if ttl_seconds <= 0 or now - saved_at > ttl_seconds:
            _CACHE.pop(key, None)
            return None
        _CACHE.move_to_end(key)
        return copy.deepcopy(result)


def _cache_put(key: str, result: dict, max_entries: int) -> None:
    if max_entries <= 0:
        return
    with _CACHE_LOCK:
        _CACHE[key] = (time.monotonic(), copy.deepcopy(result))
        _CACHE.move_to_end(key)
        while len(_CACHE) > max_entries:
            _CACHE.popitem(last=False)


def clear_shared_cache() -> None:
    """Test/maintenance hook. Does not affect audit logs."""
    global _LAST_REQUEST_STARTED
    with _CACHE_LOCK:
        _CACHE.clear()
    with _RATE_LOCK:
        _LAST_REQUEST_STARTED = 0.0


def secure_vt_lookup(
    ioc_value: object,
    *,
    api_key: str,
    proxy_url: str = "",
    rate_delay: float = 0.0,
    timeout: float = 30.0,
    cache_ttl_seconds: float = 86400.0,
    cache_max_entries: int = 2048,
    retry_429_max_seconds: float = 60.0,
) -> dict:
    """Perform a policy-enforced VT lookup with shared cache/rate limiting."""
    valid, payload = validate_vt_ioc(ioc_value)
    if not valid:
        payload.update({"external_request": False, "cache_hit": False})
        return payload
    if not api_key:
        return {
            "error": "VT_API_KEY が未設定のため vt_ioc_lookup は利用できません",
            "reason": "missing_api_key",
            "external_request": False,
            "cache_hit": False,
            "ioc": payload["ioc"],
            "ioc_type": payload["ioc_type"],
        }

    normalized = payload["ioc"]
    ioc_type = payload["ioc_type"]
    cache_key = f"{ioc_type}:{normalized}"
    cached = _cache_get(cache_key, max(0.0, float(cache_ttl_seconds)))
    if cached is not None:
        cached["cache_hit"] = True
        cached["external_request"] = False
        return redact_object(cached, api_key=api_key, proxy_url=proxy_url)  # type: ignore[return-value]

    global _LAST_REQUEST_STARTED
    started = time.monotonic()
    proxies = proxy_dict(proxy_url)
    delay = max(0.0, float(rate_delay))
    request_count = 0

    with _RATE_LOCK:
        wait = delay - (time.monotonic() - _LAST_REQUEST_STARTED)
        if wait > 0:
            time.sleep(wait)
        _LAST_REQUEST_STARTED = time.monotonic()
        request_count += 1
        result = vt_post.lookup_ioc(
            normalized,
            api_key,
            proxies=proxies,
            rate_delay=0.0,
            ioc_type=ioc_type,
            timeout=max(1.0, float(timeout)),
        )

        retry_after = 0.0
        if result.get("vt_error") == "rate_limited":
            try:
                retry_after = float(result.get("retry_after") or 0)
            except (TypeError, ValueError):
                retry_after = 0.0
            retry_cap = max(0.0, float(retry_429_max_seconds))
            if 0 < retry_after <= retry_cap:
                time.sleep(retry_after)
                _LAST_REQUEST_STARTED = time.monotonic()
                request_count += 1
                result = vt_post.lookup_ioc(
                    normalized,
                    api_key,
                    proxies=proxies,
                    rate_delay=0.0,
                    ioc_type=ioc_type,
                    timeout=max(1.0, float(timeout)),
                )

    result = dict(result or {})
    result["ioc"] = normalized
    result["ioc_type"] = ioc_type
    result["cache_hit"] = False
    result["external_request"] = True
    result["external_request_count"] = request_count
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result = redact_object(result, api_key=api_key, proxy_url=proxy_url)  # type: ignore[assignment]

    # Cache normal VT responses, including not_found and controlled 4xx results,
    # but not transient transport/rate-limit failures.
    transient = str(result.get("vt_error", ""))
    if transient not in ("rate_limited", "timeout") and not transient.startswith("proxy_error"):
        _cache_put(cache_key, result, max(0, int(cache_max_entries)))
    return result
