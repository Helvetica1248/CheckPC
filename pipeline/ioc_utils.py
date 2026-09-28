#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ioc_utils.py  (v3.69-rc26)

IOC の抽出・分類・正規化の共通モジュール。vt_post.py から移設し、
analyze_section.py（Defender の決定論 IOC 抽出）と共有する。

■ 責務分離（v3.69-rc2 / 指示10）

    extract_evidence_iocs()
        構文的に妥当な IP / FQDN / URL / email / hash を「証拠」として保存する。
        既知インフラ（Microsoft / Google / GitHub / CloudFront 等）や
        プライベート IP も【削除せず】、known_infra / private のフラグを
        付けて保持する。証拠の欠落は取りこぼしに直結するため。

    should_query_vt()
        private IP・既知インフラ・skip 対象について「VT へ送るかどうかだけ」を
        判定する。スコアや証拠の有無には関与しない。

■ 後方互換

    classify_ioc() / normalize_ioc() は vt_post._classify_ioc /
    _normalize_ioc をロジック変更なしで移設したもの。移設前の挙動を
    golden fixture（test_v368_ioc_utils.py）で固定してある。
"""

import ipaddress
import os
import re
from typing import Optional

import directory_policy
from urllib.parse import urlsplit, urlunsplit

# ─────────────────────────────────────────────────────────────
# 構文パターン（vt_post.py から移設。変更なし）
# ─────────────────────────────────────────────────────────────
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
_MD5_RE    = re.compile(r'^[0-9a-fA-F]{32}$')
_SHA1_RE   = re.compile(r'^[0-9a-fA-F]{40}$')
_IPV4_BARE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
_FQDN_RE   = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)'
    r'(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))+$'
)

# v3.69-rc2 継承: email / URL
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
URL_RE   = re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s"\'<>|]+')

_VALID_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "mobi", "io", "co", "ai", "app", "dev", "xyz", "top", "online",
    "site", "shop", "cloud", "tech", "store", "live", "life", "world", "today",
    "news", "blog", "club", "fun", "vip", "work", "web", "icu", "sbs", "space",
    "website", "press", "host", "link", "click", "run", "cyou", "rest", "id",
    "asia", "cc", "tv", "me", "to", "ws", "su", "cat", "tel",
    "jp", "cn", "ru", "kr", "us", "uk", "gb", "de", "fr", "it", "es", "nl",
    "be", "ch", "at", "se", "no", "fi", "dk", "pl", "cz", "br", "mx", "ar",
    "in", "au", "nz", "ca", "tw", "hk", "sg", "my", "th", "vn", "ph", "kz",
    "ua", "tr", "za", "il", "sa", "ae", "ir", "pk", "bd", "lk", "np", "eu",
    "tk", "ml", "ga", "cf", "gq", "pw", "bid", "win", "loan", "download",
    "review", "stream", "racing", "date", "faith", "party", "trade", "men",
}

_NON_EXECUTABLE_KNOWN_FILE_EXTS = {
    ".pf", ".lnk", ".url", ".inf", ".cat", ".tmp", ".log", ".dat", ".bin",
    ".cab", ".zip", ".rar", ".7z", ".xsl", ".doc", ".docx", ".xls",
    ".xlsx", ".pdf", ".txt", ".xml", ".json", ".dotm", ".dotx",
    ".docm", ".ppt", ".pptx", ".pps", ".potm", ".pot", ".xlsm",
    ".xlsb", ".xltx", ".xlt", ".rtf", ".odt", ".ods", ".ini",
    ".toml", ".cfg", ".config", ".conf", ".reg", ".db", ".sqlite",
    ".bbx", ".cbx", ".dbx", ".dtx", ".ins", ".tex", ".sty", ".cls",
    ".htf", ".ico", ".cur", ".png", ".jpg", ".gif", ".bmp", ".svg",
    ".lst", ".bak", ".old", ".sct", ".pyd", ".whl", ".manifest",
    ".resx", ".mui", ".nls", ".pak", ".res", ".map", ".lock",
    ".evtx", ".etl", ".css", ".htm", ".html",
}
_KNOWN_FILE_EXTS = frozenset(
    directory_policy.IOC_EXECUTION_FILE_EXTS | _NON_EXECUTABLE_KNOWN_FILE_EXTS
)
_VT_FILEPATH_EXTS = frozenset(
    directory_policy.VT_EXECUTION_FILE_EXTS
    | {".dotm", ".dot", ".xlam", ".xla", ".ppam", ".xlsm"}
)

_PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_SKIP_FILEPATH_VT = {
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "msiexec.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe",
    "cmd.exe", "wmic.exe", "bitsadmin.exe", "schtasks.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "explorer.exe", "svchost.exe", "lsass.exe", "services.exe",
    "winlogon.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe",
    "csrss.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
    "ipconfig.exe", "net.exe", "netstat.exe", "tasklist.exe",
    "sc.exe", "reg.exe", "ping.exe", "nslookup.exe",
    "malwarebytes.exe", "mbamservice.exe", "mbamtray.exe",
    "mbbr.exe", "mb5uns.exe", "mbamwsc.exe",
    "firefox.exe", "chrome.exe", "msedge.exe",
}

_SKIP_FQDN_SUFFIXES = (
    ".microsoft.com", ".windows.com", ".windowsupdate.com",
    ".microsoftonline.com", ".azure.com", ".office.com", ".office365.com",
    ".live.com", ".outlook.com", ".msftncsi.com", ".msftconnecttest.com",
    ".bing.com", ".google.com", ".googleapis.com", ".gstatic.com",
    ".apple.com", ".icloud.com", ".amazon.com", ".amazonaws.com",
    ".cloudfront.net", ".cloudflare.com", ".akamai.net", ".akamaized.net",
    ".akamaiedge.net", ".edgekey.net", ".edgesuite.net",
    ".github.com", ".githubusercontent.com",
    ".mozilla.org", ".firefox.com",
    ".symantec.com", ".digicert.com", ".letsencrypt.org", ".lencr.org",
    ".zoom.us", ".slack.com", ".teams.microsoft.com",
    ".dropbox.com", ".adobe.com",
    ".trafficmanager.net", ".azurefd.net", ".cloudapp.net",
    ".windows.net", ".msedge.net",
    ".nuget.org", ".npmjs.com", ".pypi.org",
    ".ntp.org", ".nict.jp",
)
_SKIP_FQDN_EXACT = {"localhost", "wpad", "dns.google", "one.one.one.one"}


# ─────────────────────────────────────────────────────────────
# 述語（証拠判定と VT 判定の両方から使う）
# ─────────────────────────────────────────────────────────────
def _is_valid_tld(host: str) -> bool:
    """末尾ラベルが実在の一般的なTLDか（ファイル名のドメイン誤分類を防ぐ）。"""
    last = host.rstrip(".").rsplit(".", 1)[-1].lower()
    return last in _VALID_TLDS


def is_private_ip(value: str) -> bool:
    """プライベート/ループバック/リンクローカル/CGNAT/0.0.0.0/8 か。"""
    v = (value or "").strip()
    if ":" in v and not v.startswith("["):
        v = v.rsplit(":", 1)[0]
    if not _IPV4_BARE.match(v):
        return False
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def is_known_infra_fqdn(value: str) -> bool:
    """既知インフラ（Microsoft/Google/GitHub/CloudFront 等）の FQDN か。
    ★証拠からは削除しない。VT 照合をスキップする判断にのみ使う。"""
    vl = (value or "").strip().lower().rstrip(".")
    if not vl:
        return False
    if vl in _SKIP_FQDN_EXACT:
        return True
    return any(vl.endswith(s) or vl == s.lstrip(".") for s in _SKIP_FQDN_SUFFIXES)


def is_generic_filename(basename: str) -> bool:
    """VT ファイル名検索が無意味な既知の汎用ファイル名か。"""
    return (basename or "").lower() in _SKIP_FILEPATH_VT


# ─────────────────────────────────────────────────────────────
# 後方互換 API（vt_post.py から移設・ロジック変更なし）
# ─────────────────────────────────────────────────────────────
def classify_ioc(value: str) -> Optional[str]:
    """
    IOC 文字列の種別を返す（VT 照合対象としての分類）。
    戻り値: "hash" / "ip" / "fqdn" / "filepath" / None（対象外）

    ★これは「VT へ送る対象か」を含んだ従来の分類であり、
      private IP・既知インフラ FQDN・汎用ファイル名は None を返す。
      証拠抽出には classify_syntactic() / extract_evidence_iocs() を使うこと。
    """
    v = (value or "").strip()

    if is_defender_threat_name(v):
        return None

    if _SHA256_RE.match(v) or _MD5_RE.match(v) or _SHA1_RE.match(v):
        return "hash"

    ip_candidate = v
    if ":" in v and not v.startswith("["):
        ip_candidate = v.rsplit(":", 1)[0]

    if _IPV4_BARE.match(ip_candidate):
        try:
            addr = ipaddress.ip_address(ip_candidate)
            if any(addr in net for net in _PRIVATE_NETS):
                return None
            return "ip"
        except ValueError:
            pass

    if ("\\" in v or "/" in v):
        ext = os.path.splitext(v.lower())[1]
        if ext in _VT_FILEPATH_EXTS:
            basename = v.replace("/", "\\").split("\\")[-1].lower()
            if basename not in _SKIP_FILEPATH_VT:
                return "filepath"
        return None

    if "." in v:
        ext = os.path.splitext(v.lower())[1]
        # ``.com`` is both a Windows executable extension and a public TLD.
        # A path-like value was already handled above; a bare valid domain must
        # remain an FQDN so canonical executable coverage does not suppress IOC
        # and VT handling for example.com-style evidence.
        fqdn_candidate = bool(_FQDN_RE.match(v)) and _is_valid_tld(v.lower().rstrip("."))
        if ext in _KNOWN_FILE_EXTS and not (ext == ".com" and fqdn_candidate):
            return None
        if fqdn_candidate:
            vl = v.lower().rstrip(".")
            if vl in _SKIP_FQDN_EXACT:
                return None
            if any(vl.endswith(s) or vl == s.lstrip(".") for s in _SKIP_FQDN_SUFFIXES):
                return None
            return "fqdn"

    return None


def normalize_ioc(ioc_val: str, ioc_type: str) -> str:
    """vt_post._normalize_ioc から移設（ロジック変更なし）。"""
    if ioc_type == "ip" and ":" in ioc_val and not ioc_val.startswith("["):
        return ioc_val.rsplit(":", 1)[0]
    if ioc_type == "filepath":
        return ioc_val.replace("/", "\\").split("\\")[-1]
    return ioc_val


# ─────────────────────────────────────────────────────────────
# 証拠抽出（v3.69-rc2 継承・指示10）
# ─────────────────────────────────────────────────────────────
def classify_syntactic(value: str) -> Optional[str]:
    """構文だけで種別を返す（skip リストを適用しない）。
    戻り値: "hash"/"ip"/"fqdn"/"filepath"/"email"/"url"/None

    ★private IP も既知インフラ FQDN も、ここでは種別を返す
      （証拠として保持するため）。
    """
    v = (value or "").strip()
    if not v:
        return None

    if is_defender_threat_name(v):
        return "malware_name"

    if _SHA256_RE.match(v) or _MD5_RE.match(v) or _SHA1_RE.match(v):
        return "hash"
    if EMAIL_RE.fullmatch(v):
        return "email"
    if URL_RE.match(v):
        return "url"

    ip_candidate = v
    if ":" in v and not v.startswith("["):
        ip_candidate = v.rsplit(":", 1)[0]
    if _IPV4_BARE.match(ip_candidate):
        try:
            ipaddress.ip_address(ip_candidate)
            return "ip"
        except ValueError:
            pass

    if "\\" in v or "/" in v:
        # Windows パス / UNC / POSIX パスは FQDN と誤認しない
        return "filepath" if os.path.splitext(v.lower())[1] else None

    if "." in v:
        ext = os.path.splitext(v.lower())[1]
        fqdn_candidate = bool(_FQDN_RE.match(v)) and _is_valid_tld(v.lower().rstrip("."))
        if ext in _KNOWN_FILE_EXTS and not (ext == ".com" and fqdn_candidate):
            return None            # ファイル名（svchost.exe 等）
        if fqdn_candidate:
            return "fqdn"
    return None


_TOKEN_SPLIT_RE = re.compile(r"[\s\"'`,;()\[\]{}<>|]+")


def tokenize_candidates(text: str) -> list:
    """自由文/パス文字列から IOC 候補トークンを切り出す。
    パス区切り（\\ /）では分割しない（filepath 判定を分類器へ委ねるため）。"""
    if not text:
        return []
    out = []
    for t in _TOKEN_SPLIT_RE.split(text):
        t = t.strip().strip(".,;:")
        if t:
            out.append(t)
    return out


def _excerpt(text: str, needle: str, width: int = 60) -> str:
    """監査用: 元文字列のうち IOC 周辺を切り出す。"""
    i = text.find(needle)
    if i < 0:
        return text[:width]
    s = max(0, i - width // 3)
    return text[s:i + len(needle) + width // 3]


def url_host(value: str) -> str:
    """URL から host を抽出する（urllib.parse.urlsplit を使用）。"""
    try:
        h = urlsplit(value).hostname or ""
    except Exception:
        return ""
    return h




# v3.69-rc26: stable evidence IOC representation across analyzed/correlation outputs.
# Defender threat names such as ``Trojan:MSIL/Darkvigil.NWA!MTB`` contain a
# forward slash but are not file paths.  Treat them as a dedicated evidence
# kind before generic path handling so correlation output never rewrites the
# slash to a Windows path separator.
_DEFENDER_THREAT_NAME_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_.-]{1,63}:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}/"
    r"[^\\/\s]+$"
)


def is_defender_threat_name(value: str) -> bool:
    """Return True for canonical Microsoft Defender threat-name syntax.

    The leading category must contain at least two characters so a drive-like
    token such as ``C:Windows/file.exe`` is never misclassified.  URLs are also
    excluded because the token between ``:`` and ``/`` must be non-empty.
    """
    return bool(_DEFENDER_THREAT_NAME_RE.fullmatch(str(value or "").strip()))


_COMMAND_PATH_RE = re.compile(
    rf'^(?:"(?P<quoted>[A-Za-z]:[\/][^"]+?\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN}))"'
    rf'|(?P<plain>[A-Za-z]:[\/].+?\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})))'
    r'(?=\s+(?:[-/]|$)|$)', re.I)
_BRACKETED_IP_PORT_RE = re.compile(r'^\[([^]]+)\]:(\d+)$')
_BRACKETED_IP_RE = re.compile(r'^\[([^]]+)\]$')
_IPV4_PORT_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$')
_CONNECTION_PAIR_RE = re.compile(
    r"^\s*(?P<local>\[[^]]+\]:\d+|\d{1,3}(?:\.\d{1,3}){3}:\d+)"
    r"\s*(?:→|->|=>)\s*"
    r"(?P<remote>\[[^]]+\]:\d+|\d{1,3}(?:\.\d{1,3}){3}:\d+)\s*$"
)


def _parse_ip_endpoint(value: str, *, allow_zero_port: bool = False):
    """Parse IPv4:port or [IPv6]:port without accepting ambiguous bare IPv6."""
    m = _IPV4_PORT_RE.fullmatch(value) or _BRACKETED_IP_PORT_RE.fullmatch(value)
    if not m:
        return None
    try:
        ip = _canonical_ip(m.group(1))
        port = int(m.group(2))
    except (ValueError, TypeError):
        return None
    lower = 0 if allow_zero_port else 1
    if not lower <= port <= 65535:
        return None
    return ip, port




def _parse_ip_endpoint_unchecked(value: str):
    """Return canonical IP and integer port without applying range policy."""
    m = _IPV4_PORT_RE.fullmatch(value) or _BRACKETED_IP_PORT_RE.fullmatch(value)
    if not m:
        return None
    try:
        return _canonical_ip(m.group(1)), int(m.group(2))
    except (ValueError, TypeError):
        return None

def parse_connection_pair(value: str):
    """Parse ``local endpoint -> remote endpoint`` netstat-style evidence.

    The remote endpoint is the primary IOC. The local endpoint is retained as
    structured provenance; the original text is always preserved by the detail
    normalizer. Only unambiguous IPv4 or bracketed IPv6 endpoint pairs are
    accepted so ordinary free text is never rewritten heuristically.
    """
    m = _CONNECTION_PAIR_RE.fullmatch(str(value or ""))
    if not m:
        return None
    local = _parse_ip_endpoint(m.group("local"), allow_zero_port=True)
    remote = _parse_ip_endpoint(m.group("remote"), allow_zero_port=False)
    if not local or not remote:
        return None
    return {
        "local_ip": local[0], "local_port": local[1],
        "remote_ip": remote[0], "remote_port": remote[1],
    }


def _canonical_ip(value: str) -> str:
    """Canonicalize an IP while keeping IPv4-mapped IPv6 grep-friendly."""
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return f"::ffff:{address.ipv4_mapped}"
    return str(address)


def _normalize_url_scheme_host(value: str) -> str:
    """Lower-case URL scheme/host while preserving path/query/fragment case."""
    try:
        parts = urlsplit(value)
    except Exception:
        return value
    if not parts.scheme or not parts.netloc or parts.hostname is None:
        return value

    netloc = parts.netloc
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        userinfo += "@"

    port_suffix = ""
    host_text = hostport
    if hostport.startswith("["):
        close = hostport.find("]")
        if close < 0:
            return value
        host_text = hostport[1:close]
        port_suffix = hostport[close + 1:]
    elif hostport.count(":") == 1:
        candidate_host, candidate_port = hostport.rsplit(":", 1)
        if candidate_port.isdigit():
            host_text = candidate_host
            port_suffix = ":" + candidate_port

    try:
        normalized_host = _canonical_ip(host_text)
        is_ipv6 = ":" in normalized_host
    except ValueError:
        normalized_host = host_text.lower().rstrip(".")
        is_ipv6 = False
    if not normalized_host:
        return value
    rendered_host = f"[{normalized_host}]" if is_ipv6 else normalized_host
    return urlunsplit((parts.scheme.lower(), userinfo + rendered_host + port_suffix,
                       parts.path, parts.query, parts.fragment))


def normalize_evidence_ioc(value: str) -> tuple[str, Optional[int]]:
    """Return a stable IOC value and an optional separated network port.

    Full file paths are preserved. Command-line arguments are removed only when
    an executable/script path is unambiguous. URL scheme/host are normalized,
    while path/query/fragment retain their original case. Valid ports are
    1..65535; invalid port text remains untouched for auditability.
    """
    original = str(value or "").strip()
    if not original:
        return "", None

    if is_defender_threat_name(original):
        return original, None

    m = _IPV4_PORT_RE.fullmatch(original)
    if m:
        try:
            ip = _canonical_ip(m.group(1))
            port = int(m.group(2))
            if 1 <= port <= 65535:
                return ip, port
            return original, None
        except ValueError:
            pass
    m = _BRACKETED_IP_PORT_RE.fullmatch(original)
    if m:
        try:
            ip = _canonical_ip(m.group(1))
            port = int(m.group(2))
            if 1 <= port <= 65535:
                return ip, port
            return original, None
        except ValueError:
            pass
    m = _BRACKETED_IP_RE.fullmatch(original)
    if m:
        try:
            return _canonical_ip(m.group(1)), None
        except ValueError:
            pass

    try:
        return _canonical_ip(original), None
    except ValueError:
        pass

    if _SHA256_RE.fullmatch(original) or _SHA1_RE.fullmatch(original) or _MD5_RE.fullmatch(original):
        return original.lower(), None

    if URL_RE.fullmatch(original):
        return _normalize_url_scheme_host(original), None

    cmd = _COMMAND_PATH_RE.match(original)
    if cmd:
        path = cmd.group("quoted") or cmd.group("plain") or ""
        return path.replace("/", "\\"), None

    fqdn_candidate = original.rstrip(".")
    typ = classify_syntactic(fqdn_candidate)
    if typ == "fqdn":
        return fqdn_candidate.lower(), None
    if typ == "filepath":
        return original.strip('"').replace("/", "\\"), None
    return original, None


def normalize_evidence_ioc_detail(value: str) -> dict:
    """Normalize one IOC and retain raw/warning metadata when it changes."""
    original = str(value or "").strip()
    if is_defender_threat_name(original):
        return {
            "ioc": original,
            "ioc_port": None,
            "ioc_normalization_kind": "defender_threat_name",
        }
    pair = parse_connection_pair(original)
    if pair is not None:
        return {
            "ioc": pair["remote_ip"],
            "ioc_port": pair["remote_port"],
            "ioc_raw": original,
            "local_ip": pair["local_ip"],
            "local_port": pair["local_port"],
            "ioc_normalization_kind": "connection_pair",
        }

    # Preserve rejected connection pairs as raw evidence, but distinguish them
    # from arbitrary free text and account for invalid endpoint ports.
    pair_match = _CONNECTION_PAIR_RE.fullmatch(original)
    if pair_match:
        local_unchecked = _parse_ip_endpoint_unchecked(pair_match.group("local"))
        remote_unchecked = _parse_ip_endpoint_unchecked(pair_match.group("remote"))
        warning = None
        if remote_unchecked is not None and not 1 <= remote_unchecked[1] <= 65535:
            warning = "invalid_remote_port"
        elif local_unchecked is not None and not 0 <= local_unchecked[1] <= 65535:
            warning = "invalid_local_port"
        if warning:
            return {
                "ioc": original,
                "ioc_port": None,
                "ioc_raw": original,
                "ioc_normalization_kind": "connection_pair_rejected",
                "ioc_normalization_warning": warning,
            }

    normalized, port = normalize_evidence_ioc(original)
    detail = {"ioc": normalized, "ioc_port": port}
    if normalized != original or port is not None:
        detail["ioc_raw"] = original
    m = _IPV4_PORT_RE.fullmatch(original) or _BRACKETED_IP_PORT_RE.fullmatch(original)
    if m:
        try:
            port_value = int(m.group(2))
        except (TypeError, ValueError):
            port_value = -1
        if not 1 <= port_value <= 65535:
            detail["ioc_normalization_warning"] = "invalid_port"
    return detail


def normalize_entry_iocs(entry: dict) -> dict:
    """Normalize and deduplicate one analyzed entry's IOC string list."""
    if not isinstance(entry, dict):
        return entry
    values = entry.get("iocs")
    if not isinstance(values, list):
        return entry
    normalized, seen, ports = [], set(), []
    for raw in values:
        value, port = normalize_evidence_ioc(raw)
        if not value:
            continue
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            normalized.append(value)
        if port is not None and port not in ports:
            ports.append(port)
    entry["iocs"] = normalized
    if ports:
        entry["ioc_ports"] = ports
    else:
        entry.pop("ioc_ports", None)
    return entry

DEFAULT_EVIDENCE_ACCEPT = ("ip", "fqdn", "url", "email", "hash")


def extract_evidence_iocs(text: str, source_field: str = "",
                          accept: tuple = DEFAULT_EVIDENCE_ACCEPT) -> list:
    """構文的に妥当な IOC を「証拠」として抽出する。

    ★既知インフラ・private IP も削除せず known_infra / private フラグを付けて
      保持する（証拠の欠落は取りこぼしに直結するため）。
      VT へ送るかどうかは should_query_vt() が独立に判断する。

    戻り値: [{"value", "type", "source_field", "source_excerpt",
              "known_infra": bool, "private": bool}, ...]
      決定論（同一入力→同一順序）。
    """
    if not text:
        return []
    out, seen = [], set()

    def _add(val, typ):
        key = (typ, val.lower())
        if key in seen:
            return
        seen.add(key)
        rec = {
            "value": val,
            "type": typ,
            "source_field": source_field,
            "source_excerpt": _excerpt(text, val),
            "known_infra": False,
            "private": False,
        }
        if typ == "ip":
            rec["private"] = is_private_ip(val)
        elif typ == "fqdn":
            rec["known_infra"] = is_known_infra_fqdn(val)
        elif typ == "url":
            h = url_host(val)
            rec["host"] = h
            rec["known_infra"] = is_known_infra_fqdn(h)
            rec["private"] = is_private_ip(h)
        out.append(rec)

    # 1. URL（host も併せて証拠化する）
    if "url" in accept or "fqdn" in accept or "ip" in accept:
        for m in URL_RE.finditer(text):
            u = m.group(0).rstrip(".,;)")
            if "url" in accept:
                _add(u, "url")
            h = url_host(u)
            if h:
                if _IPV4_BARE.match(h) and "ip" in accept:
                    _add(h, "ip")
                elif "fqdn" in accept and _FQDN_RE.match(h) and _is_valid_tld(h):
                    _add(h, "fqdn")

    # 2. email（accept へ明示的に含める・指示10）
    if "email" in accept:
        for m in EMAIL_RE.finditer(text):
            _add(m.group(0).rstrip(".,;"), "email")

    # 3. トークン単位（ip / fqdn / hash）
    for tok in tokenize_candidates(text):
        t = classify_syntactic(tok)
        if t in ("ip", "fqdn", "hash") and t in accept:
            if t == "ip":
                _add(normalize_ioc(tok, "ip"), "ip")
            else:
                _add(tok, t)
    return out


# ─────────────────────────────────────────────────────────────
# VT 送信判定（v3.69-rc2 継承・指示10）
# ─────────────────────────────────────────────────────────────
def should_query_vt(value: str, ioc_type: str = None) -> tuple:
    """VT へ照合するかだけを判定する。証拠の採否には関与しない。

    戻り値: (bool, reason:str)
    """
    v = (value or "").strip()
    if not v:
        return False, "empty"
    t = ioc_type or classify_syntactic(v)
    if t == "url":
        h = url_host(v)
        return should_query_vt(h, None) if h else (False, "url_without_host")
    if t == "email":
        return False, "email_not_vt_target"
    if t == "malware_name":
        return False, "malware_name_not_vt_target"
    if t == "ip":
        if is_private_ip(v):
            return False, "private_ip"
        return True, "ok"
    if t == "fqdn":
        if is_known_infra_fqdn(v):
            return False, "known_infrastructure"
        if not _is_valid_tld(v.lower().rstrip(".")):
            return False, "invalid_tld"
        return True, "ok"
    if t == "hash":
        return True, "ok"
    if t == "filepath":
        base = v.replace("/", "\\").split("\\")[-1]
        if os.path.splitext(base.lower())[1] not in _VT_FILEPATH_EXTS:
            return False, "not_vt_target_ext"
        if is_generic_filename(base):
            return False, "generic_filename"
        return True, "ok"
    return False, "unclassified"
