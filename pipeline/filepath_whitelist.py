# -*- coding: utf-8 -*-
"""filepath whitelist 照合エンジン（提案B / Phase 1）。

J-CRAT 蓄積の master_filepath_whitelist（既知正規の Windows/OEM/ベンダ実行体・
DLL リスト）を読み込み、与えられたファイルパスが既知良性かを判定する。

照合仕様:
  · 完全一致パターン（env/ワイルドカードなし）は正規化文字列の集合で O(1) 照合。
  · %envvar% / * を含むパターンは正規表現へコンパイルして照合。
  · 先頭 ":\\" はドライブ非依存（[A-Za-z]:\\...）として扱う。
  · 大文字小文字は無視。パス区切りは \\ に正規化。
  · "<< ラベル << 日付" 以降と、2つ目のパス/引数は除去する。

設計方針（取りこぼし防止）:
  · 本モジュールは「既知良性か（bool）」を返すだけ。降格の可否・幅は
    呼び出し側（run_analysis 等）のポリシーで決める。
  · ファイル未在時は「WL無効（常にFalse）」で安全に動作継続する。
"""
import os
import re
from typing import Optional

# 環境変数 → 正規表現断片（小文字・\\区切り前提）
_ENV_MAP = {
    "%systemroot%":        r"[a-z]:\\windows",
    "%windir%":            r"[a-z]:\\windows",
    "%programfiles(x86)%": r"[a-z]:\\program files \(x86\)",
    "%programfiles%":      r"[a-z]:\\program files",
    "%commonprogramfiles%": r"[a-z]:\\program files\\common files",
    "%localappdata%":      r"[a-z]:\\users\\[^\\]+\\appdata\\local",
    "%appdata%":           r"[a-z]:\\users\\[^\\]+\\appdata\\roaming",
    "%programdata%":       r"[a-z]:\\programdata",
    "%systemdrive%":       r"[a-z]:",
    "%userprofile%":       r"[a-z]:\\users\\[^\\]+",
    "%temp%":              r"[a-z]:\\users\\[^\\]+\\appdata\\local\\temp",
}

DEFAULT_WL_FILENAME = "master_filepath_whitelist.txt"


def _clean_pattern(raw: str) -> str:
    """1行から照合対象のパスパターン部を取り出す（ラベル/2つ目パス除去）。"""
    s = raw.strip()
    if not s or s.startswith("#"):
        return ""
    # "<< ラベル << 日付" 以降を除去
    s = re.split(r"\s*<<\s*", s)[0].strip()
    if not s:
        return ""
    # 2つ目のパス/引数（最初の拡張子の後ろに空白＋続き）があれば切る
    m = re.match(r'("?[A-Za-z]:.*?\.[A-Za-z0-9]{1,4}"?)(\s+\S.*)?$', s)
    if m:
        s = m.group(1)
    return s.strip().strip('"')


def _normalize(path: str) -> str:
    """照合用にパスを正規化（小文字・/→\\・連続\\除去）。"""
    p = path.strip().strip('"').lower().replace("/", "\\")
    p = re.sub(r"\\+", r"\\", p)
    return p


# システムレベルの環境変数プレースホルダを具体的なドライブレターパスへ
# 解決するための対応表（ユーザー固有のパス（%appdata%等）はユーザー名が
# 不定のため対象外）。
#
# 背景（実運用で発覚）: task_scheduler のIOCは、他セクション（directory等の
# dirコマンド由来）と異なり、Windows Task Scheduler自体の仕様により
# %systemroot%\system32\pla.dll のような未解決のプレースホルダ文字列の
# ままレポートされる。一方、master_filepath_whitelist.txt のパターンは
# _pattern_to_regex() により「解決済みドライブレターパス」
# （[a-z]:\\windows\\...）を期待する正規表現に変換されるため、
# 未解決プレースホルダのままでは既存のWL登録済みエントリ（pla.dll等）に
# 一致しなかった。照合前に入力側のプレースホルダも解決することで
# この非対称性を解消する。
_ENV_RESOLVE = {
    "%systemroot%":         "c:\\windows",
    "%windir%":             "c:\\windows",
    "%programfiles(x86)%":  "c:\\program files (x86)",
    "%programfiles%":       "c:\\program files",
    "%commonprogramfiles%": "c:\\program files\\common files",
    "%systemdrive%":        "c:",
}


def _resolve_env_placeholders(path: str) -> str:
    """入力パス中の既知システム環境変数プレースホルダを解決する（小文字化込み）。"""
    p = path.lower()
    for key in sorted(_ENV_RESOLVE, key=len, reverse=True):
        p = p.replace(key, _ENV_RESOLVE[key])
    return p


def _pattern_to_regex(pat: str) -> Optional[str]:
    """WL パターンを照合用正規表現（フルマッチ）へ変換。失敗時 None。"""
    p = pat.lower().replace("/", "\\")
    has_env = "%" in p
    has_wild = "*" in p
    is_colon = p.startswith(":\\")

    tokens = []
    def _stash(frag):
        tokens.append(frag)
        return f"\x00{len(tokens)-1}\x00"

    # env 置換（長いキーから）
    for key in sorted(_ENV_MAP, key=len, reverse=True):
        if key in p:
            p = p.replace(key, _stash(_ENV_MAP[key]))
    # 先頭 ":\\" はドライブ非依存 [a-z]: に（プレースホルダを必ず連結する）
    if is_colon:
        p = _stash(r"[a-z]:") + p[1:]
    # ワイルドカード
    p = p.replace("*", _stash(r"[^\\]*"))
    # エスケープ後にプレースホルダを正規表現断片へ戻す
    p = re.escape(p)
    for i, frag in enumerate(tokens):
        p = p.replace(re.escape(f"\x00{i}\x00"), frag)

    # env/wild/ドライブ非依存が無い完全一致は set 照合に委ねる
    if not has_env and not has_wild and not is_colon:
        return None
    return "^" + p + "$"


class FilepathWhitelist:
    """master_filepath_whitelist を読み込み、パスの既知良性判定を提供する。"""

    def __init__(self, path: Optional[str] = None):
        self.exact = set()        # 完全一致（正規化済み・ドライブ有り/無し両方収録）
        self.regexes = []         # env/wildcard/ドライブ非依存パターン
        self.loaded = False
        self.source_path = path or self._default_path()
        self._load()

    @staticmethod
    def _default_path() -> str:
        # env 上書き → 同梱ファイル
        env = os.environ.get("CHECKPC_FILEPATH_WHITELIST")
        if env:
            return env
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            DEFAULT_WL_FILENAME)

    def _load(self):
        if not self.source_path or not os.path.exists(self.source_path):
            # ファイル未在 → WL 無効（常に False）。安全に継続する。
            return
        raw_patterns = []
        # UTF-8 優先、失敗時 CP932 フォールバック
        for enc in ("utf-8", "cp932"):
            try:
                with open(self.source_path, encoding=enc) as f:
                    raw_patterns = f.readlines()
                break
            except (UnicodeDecodeError, LookupError):
                continue
        pat_regexes = []
        for line in raw_patterns:
            pat = _clean_pattern(line)
            if not pat:
                continue
            # 完全一致（env/wild/ドライブ非依存なし）は set へ
            if "%" not in pat and "*" not in pat and not pat.startswith(":"):
                self.exact.add(_normalize(pat))
            else:
                rx = _pattern_to_regex(pat)
                if rx:
                    try:
                        pat_regexes.append(rx)
                    except re.error:
                        pass
        # まとめて 1 本のオルタネーションにコンパイル（高速化）
        if pat_regexes:
            combined = "|".join(f"(?:{r})" for r in pat_regexes)
            try:
                self.regexes = [re.compile(combined, re.I)]
            except re.error:
                # 分割コンパイルにフォールバック
                self.regexes = []
                for r in pat_regexes:
                    try:
                        self.regexes.append(re.compile(r, re.I))
                    except re.error:
                        pass
        self.loaded = True

    def is_whitelisted(self, path: str) -> bool:
        """path が既知良性（WL 一致）なら True。WL 未ロード時は常に False。"""
        if not self.loaded or not path:
            return False
        path = _resolve_env_placeholders(path)
        norm = _normalize(path)
        if norm in self.exact:
            return True
        # ドライブ文字を除いた後方一致（完全一致側のドライブ非依存吸収）
        no_drive = re.sub(r"^[a-z]:", "", norm)
        if no_drive in self.exact:
            return True
        for rx in self.regexes:
            if rx.search(norm):
                return True
        return False

    def stats(self) -> dict:
        return {
            "loaded": self.loaded,
            "source": self.source_path,
            "exact": len(self.exact),
            "regex_groups": len(self.regexes),
        }


# シングルトン（初回アクセス時にロード）
_WL_SINGLETON: Optional[FilepathWhitelist] = None


def get_whitelist() -> FilepathWhitelist:
    global _WL_SINGLETON
    if _WL_SINGLETON is None:
        _WL_SINGLETON = FilepathWhitelist()
    return _WL_SINGLETON


# 降格対象セクション（ファイルパスを持つもの）
_WL_TARGET_SECTIONS = (
    "directory", "prefetch", "appcompat_cache", "userassist",
    "startup_folder", "service", "system_7045", "task_scheduler",
)


def apply_whitelist_downgrade(analyzed: dict,
                              wl: Optional["FilepathWhitelist"] = None) -> int:
    """[提案B/Phase2] 既知良性パスの MEDIUM/LOW を CLEAN 降格する（in-place）。

    ポリシー（取りこぼし防止）:
      · 対象は _WL_TARGET_SECTIONS のみ。
      · HIGH は絶対に降格しない（正の悪性シグナルを WL より優先）。
      · MEDIUM/LOW のみ、パスが WL 一致した場合に CLEAN へ降格。
      · WL 未ロード時は何もしない（0 を返す）。
    戻り値: 降格した件数。
    """
    if wl is None:
        wl = get_whitelist()
    if not wl.loaded:
        return 0
    downgraded = 0
    secs = analyzed.get("sections", {})
    if not isinstance(secs, dict):
        return 0
    for sec_name in _WL_TARGET_SECTIONS:
        sd = secs.get(sec_name)
        if not isinstance(sd, dict):
            continue
        for entry in sd.get("entries", []) or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("score") not in ("MEDIUM", "LOW"):
                continue          # HIGH・CLEAN は対象外（HIGHは絶対に触らない）
            path = (entry.get("iocs", [""]) or [""])[0] or entry.get("identifier", "")
            if wl.is_whitelisted(str(path)):
                orig = entry["score"]
                entry["score"] = "CLEAN"
                entry["reason"] = (
                    f"[WL: CLEAN降格] 既知正規ファイル（filepath whitelist 一致）。"
                    f"元スコア={orig}。{entry.get('reason', '')}"
                )
                downgraded += 1
    return downgraded


if __name__ == "__main__":
    import sys
    wl = get_whitelist()
    print("stats:", wl.stats())
    for p in sys.argv[1:]:
        print(f"  {'WL一致' if wl.is_whitelisted(p) else '非該当'}: {p}")
