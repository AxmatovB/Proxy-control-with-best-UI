#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProxyTool — мультиинструмент для управления прокси (веб-интерфейс, порт 1805).

Запуск:     python proxy_tool.py
Браузер:    http://127.0.0.1:1805

Нужен только Python (стандартная библиотека) и Windows.
Данные (настройки и лог) хранятся в %APPDATA%\\ProxyTool.
"""
import argparse
import bisect
import ctypes
import difflib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import winreg
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# pythonw.exe (запуск без окна) не даёт stdout/stderr — подставляем заглушку
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

PORT = 1805
CREATE_NO_WINDOW = 0x08000000

# ═════════════════════════════════════════════════════════════════════════════
#  ХРАНИЛИЩЕ В APPDATA
# ═════════════════════════════════════════════════════════════════════════════
DATA_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ProxyTool")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
LOG_FILE = os.path.join(DATA_DIR, "proxytool.log")
AUTO_FILE = os.path.join(DATA_DIR, "auto_state.json")
CRASH_FILE = os.path.join(DATA_DIR, "crash.log")
STOP_FLAG = os.path.join(DATA_DIR, "stopped.flag")   # создаётся при остановке через ProxyTool.bat (0)
DB_FILE = os.path.join(DATA_DIR, "proxytool.db")      # история изменений (SQLite)
HOSTS_PATH = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32", "drivers", "etc", "hosts")

DEFAULT_SETTINGS = {
    "targets": [],          # список строк: "10.0.0.5", "10.0.0.1-10.0.0.50", "10.0.0.0/24", "localhost"
    "add_proxy": "1",       # "1" — кнопка «Добавить» сначала включает прокси, "0" — только добавляет
    "auto_proxy": "1",      # то же для кнопки «Запустить» (автообновление)
    "skips": [],            # IP-адреса, которые все операции обходят (отмечаются в окне интервала)
    "entries": "",          # исключения прокси (через ; или с новой строки)
    "workers": "50",
    "timeout": "5",
    "auto_every": "1",
    "auto_unit": "soat",    # soat = часы, daqiqa = минуты (внутренние значения)
    "lp_server": "",
    "lp_override": "",
    "theme": "",            # "", "light" или "dark" (пусто = как в системе)
    "sound": "1",           # "1" — звуки включены, "0" — выключены
    "watch_proxy": [],      # IP, за прокси которых ведётся наблюдение
    "watch_hosts": [],      # IP, за файлом hosts которых ведётся наблюдение
    "watch_every": "60",    # период проверки удалённых ПК, секунд
    "mon_every": "2",       # период проверки этого ПК, секунд
    "hosts_targets": [],    # свои интервалы для вкладки hosts
    "h_workers": "50",
    "h_timeout": "5",
}
_SETTINGS_LOCK = threading.Lock()


def _ensure_dir():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError:
        pass


def load_settings():
    data = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            data.update(clean_settings(saved))
    except (OSError, ValueError):
        pass
    return data


def norm_target(x):
    """Запись интервала -> строка адреса (в прошлой версии это был словарь {"addr": ...})."""
    addr = x.get("addr", "") if isinstance(x, dict) else x
    return str(addr).strip()[:200]


def clean_settings(src):
    """Оставляет только известные ключи нужного типа и размера."""
    out = {}
    for key, default in DEFAULT_SETTINGS.items():
        if key not in src:
            continue
        v = src[key]
        if key in ("targets", "hosts_targets"):
            if isinstance(v, list):
                out[key] = [t for t in (norm_target(x) for x in v[:2000]) if t]
            continue
        if isinstance(default, list):
            if isinstance(v, list):
                lim = 70000 if key in ("skips", "watch_proxy", "watch_hosts") else 2000
                out[key] = [str(x).strip()[:64] for x in v[:lim] if str(x).strip()]
        elif isinstance(v, (str, int, float)):
            out[key] = str(v)[:20000]
    if out.get("auto_unit") not in (None, "soat", "daqiqa"):
        out["auto_unit"] = "soat"
    if out.get("theme") not in (None, "", "light", "dark"):
        out["theme"] = ""
    for k in ("sound", "add_proxy", "auto_proxy"):
        if out.get(k) not in (None, "0", "1"):
            out[k] = "1"
    return out


def save_settings(new):
    """Атомарная запись: сначала во временный файл, затем замена."""
    with _SETTINGS_LOCK:
        cur = load_settings()
        before = (cur.get("watch_proxy"), cur.get("watch_hosts"), cur.get("watch_every"))
        cur.update(clean_settings(new))
        if before != (cur.get("watch_proxy"), cur.get("watch_hosts"), cur.get("watch_every")):
            MON.kick.set()
        _ensure_dir()
        try:
            fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cur, f, ensure_ascii=False, indent=2)
            os.replace(tmp, SETTINGS_FILE)
            return True
        except OSError:
            return False


# ═════════════════════════════════════════════════════════════════════════════
#  ЛОГ
# ═════════════════════════════════════════════════════════════════════════════
_LOG = deque(maxlen=5000)
_LOG_SEQ = 0
_LOG_LOCK = threading.Lock()


CONSOLE = False   # --console: дублировать журнал в чёрное окно


def _console(text):
    if not CONSOLE:
        return
    try:
        sys.stdout.write(text if text.endswith(chr(10)) else text + chr(10))
        sys.stdout.flush()
    except Exception:
        pass


def log(level, msg, kind=""):
    """level: ok | err | warn | skip | head | info; kind: '' | proxy | hosts (для разделения журналов вкладок)"""
    global _LOG_SEQ
    ts = datetime.now().strftime("%H:%M:%S")
    with _LOG_LOCK:
        _LOG_SEQ += 1
        _LOG.append({"id": _LOG_SEQ, "t": ts, "lv": level, "msg": msg, "k": kind})
    _console(f"{datetime.now():%H:%M:%S} [{level}] {msg}")
    try:
        _ensure_dir()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {msg}\n")
    except OSError:
        pass


def get_logs(since=0):
    with _LOG_LOCK:
        return [e for e in _LOG if e["id"] > since]


def clear_logs():
    with _LOG_LOCK:
        _LOG.clear()


# ═════════════════════════════════════════════════════════════════════════════
#  ЖУРНАЛ СОБЫТИЙ (SQLite в AppData) — история изменений прокси и hosts
# ═════════════════════════════════════════════════════════════════════════════
# actor:  me (вручную из интерфейса) | auto (цикл автообновления) | system (внешнее изменение)
# status: ok (применено) | err (ошибка) | skip (пропущено/без изменений) | ext (изменено извне)
_DB = None
_DB_LOCK = threading.RLock()
EV_SEQ = 0
_CHANGELOG_LOCK = threading.Lock()


def _desktop_dir():
    d = os.environ.get("PROXYTOOL_DESKTOP")        # его выставляет Desktop-bat с правами администратора
    if d and os.path.isdir(d):
        return d
    try:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buf) == 0 and buf.value:
            return buf.value
    except Exception:
        pass
    return os.path.join(os.path.expanduser("~"), "Desktop")


CHANGELOG_FILE = os.path.join(_desktop_dir(), "ProxyTool-changes.log")


def write_change_log(text):
    """Полный журнал изменений на рабочем столе (дописывается, не затирается)."""
    _console(text)
    try:
        with _CHANGELOG_LOCK, open(CHANGELOG_FILE, "a", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass


def _cut(t, n=4000):
    t = t or ""
    return t if len(t) <= n else t[:n] + f"\n… (обрезано, всего {len(t)} симв.)"


def _changelog_entry(kind, host, actor, status, protocol, old, new, detail, diff):
    who = {"me": "Вы (вручную в ProxyTool)", "auto": "Автообновление ProxyTool",
           "system": "СИСТЕМА / ВНЕШНИЙ ИСТОЧНИК (не ProxyTool)"}.get(actor, actor)
    what = {"ok": "применено", "ext": "ИЗМЕНЕНО ИЗВНЕ"}.get(status, status)
    lines = ["=" * 78,
             f"{datetime.now():%Y-%m-%d %H:%M:%S} | {'PROXY' if kind == 'proxy' else 'HOSTS'} | "
             f"{'этот ПК' if host == 'local' else host} | {what}",
             f"Кто: {who}", f"Протокол / источник: {protocol or '—'}"]
    if detail:
        lines.append(f"Подробности: {detail}")
    if diff:
        lines += ["Что изменилось:"] + [f"    {l}" for l in diff.split("\n")]
    if old or new:
        lines += ["Было:"] + [f"    {l}" for l in _cut(old).split("\n")]
        lines += ["Стало:"] + [f"    {l}" for l in _cut(new).split("\n")]
    return "\n".join(lines) + "\n\n"

PROTO_LOCAL_REG = "Реестр (локально, HKCU\\Internet Settings)"
PROTO_REMOTE_REG = "SMB/RPC: Remote Registry (reg.exe)"
PROTO_LOCAL_HOSTS = "Файл hosts (локально)"
PROTO_REMOTE_HOSTS = "SMB: административная шара ADMIN$ (copy)"


def db_init():
    global _DB, EV_SEQ
    _ensure_dir()
    try:
        _DB = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)
        _DB.execute("PRAGMA journal_mode=WAL")
        _DB.executescript("""
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, kind TEXT NOT NULL, host TEXT NOT NULL,
                actor TEXT NOT NULL, status TEXT NOT NULL, protocol TEXT DEFAULT '',
                field TEXT DEFAULT '', old TEXT DEFAULT '', new TEXT DEFAULT '',
                detail TEXT DEFAULT '', diff TEXT DEFAULT '', seen INTEGER DEFAULT 1);
            CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS ix_ev_kind ON events(kind, status, ts);
            CREATE INDEX IF NOT EXISTS ix_ev_ext ON events(status, seen);
            CREATE TABLE IF NOT EXISTS snapshots(
                kind TEXT NOT NULL, host TEXT NOT NULL, value TEXT NOT NULL, ts REAL NOT NULL,
                PRIMARY KEY(kind, host));""")
        _DB.execute("DELETE FROM events WHERE ts<?", (time.time() - 400 * 86400,))
        _DB.commit()
        EV_SEQ = _DB.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
    except sqlite3.Error as e:
        _DB = None
        log("err", f"База событий недоступна: {e}")


def _diff_tokens(kind, text):
    out = []
    for line in (text or "").split("\n"):
        if kind == "proxy":
            m = re.match(r"^(\[[^\]]+\] )?(\w+): (.*)$", line)
            if m and m.group(2) == "ProxyOverride":
                for part in m.group(3).split(";"):
                    if part.strip():
                        out.append(f"{m.group(1) or ''}ProxyOverride: {part.strip()}")
                continue
        if line.strip():
            out.append(line.rstrip())
    return out


def make_diff(kind, old, new):
    """Краткий список различий: строки '+...' (добавлено) и '-...' (убрано)."""
    a, b = _diff_tokens(kind, old), _diff_tokens(kind, new)
    if kind == "hosts":
        d = [l for l in difflib.unified_diff(a, b, lineterm="", n=0)
             if not l.startswith(("---", "+++", "@@"))]
    else:
        sa, sb = set(a), set(b)
        d = [f"-{x}" for x in a if x not in sb] + [f"+{x}" for x in b if x not in sa]
    return "\n".join(d[:300])


def record_event(kind, host, actor, status, protocol="", field="", old="", new="", detail=""):
    global EV_SEQ
    if _DB is None:
        return 0
    old, new = (old or "")[:30000], (new or "")[:30000]
    diff = make_diff(kind, old, new) if old != new else ""
    seen = 0 if status == "ext" else 1
    with _DB_LOCK:
        try:
            cur = _DB.execute(
                "INSERT INTO events(ts,kind,host,actor,status,protocol,field,old,new,detail,diff,seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), kind, host, actor, status, protocol, field, old, new,
                 (detail or "")[:2000], diff, seen))
            _DB.commit()
            EV_SEQ = cur.lastrowid
            rowid = cur.lastrowid
        except sqlite3.Error:
            return 0
    if status in ("ok", "ext"):                   # реальные изменения — ещё и в файл на рабочем столе
        write_change_log(_changelog_entry(kind, host, actor, status, protocol, old, new, detail, diff))
    return rowid


def _db_get_snapshot(kind, host):
    with _DB_LOCK:
        try:
            r = _DB.execute("SELECT value FROM snapshots WHERE kind=? AND host=?", (kind, host)).fetchone()
        except sqlite3.Error:
            return None
    return r[0] if r else None


def _db_set_snapshot(kind, host, value):
    with _DB_LOCK:
        try:
            _DB.execute("INSERT OR REPLACE INTO snapshots(kind,host,value,ts) VALUES(?,?,?,?)",
                        (kind, host, value, time.time()))
            _DB.commit()
        except sqlite3.Error:
            pass


# ── Как отличить свои изменения от внешних ───────────────────────────────────
# Перед записью счётчик версии увеличивается, после записи — снова, и снимок обновляется.
# Монитор запоминает версию до чтения и отбрасывает результат, если версия успела смениться.
_SNAP_LOCK = threading.Lock()
_WSEQ = {}


def _wseq(kind, host):
    with _SNAP_LOCK:
        return _WSEQ.get((kind, host), 0)


def begin_write(kind, host):
    with _SNAP_LOCK:
        _WSEQ[(kind, host)] = _WSEQ.get((kind, host), 0) + 1


def end_write(kind, host, value=None):
    """value — реальное состояние после записи (None — снимок не трогаем)."""
    with _SNAP_LOCK:
        _WSEQ[(kind, host)] = _WSEQ.get((kind, host), 0) + 1
        if value is not None and _DB is not None:
            _db_set_snapshot(kind, host, value)


def observe(kind, host, value, seq, protocol, detail=""):
    """Сравнивает наблюдаемое состояние со снимком. -> None | 'baseline' | 'changed'"""
    if _DB is None:
        return None
    with _SNAP_LOCK:
        if _WSEQ.get((kind, host), 0) != seq:
            return None                   # в это время писали мы сами — результат ненадёжен
        old = _db_get_snapshot(kind, host)
        if old == value:
            return None
        _db_set_snapshot(kind, host, value)
    if old is None:
        return "baseline"
    note = "Изменение обнаружено проверкой; оно произошло не через ProxyTool."
    record_event(kind, host, "system", "ext", protocol, "", old, value,
                 (detail + " " if detail else "") + note)
    name = "прокси" if kind == "proxy" else "hosts"
    log("warn", f"[внешнее изменение] {name}: {'этот ПК' if host == 'local' else host}", kind)
    return "changed"


def _note_change(old, new, proto):
    """Задача запоминает, что реально изменила (для записи в журнал событий)."""
    if old != new:
        if not hasattr(_CTX, "changes"):
            _CTX.changes = []
        _CTX.changes.append((old, new, proto))


def query_events(kind="", status="", q="", before=0, limit=200):
    if _DB is None:
        return []
    sql = "SELECT id,ts,kind,host,actor,status,protocol,detail,diff,seen FROM events WHERE 1=1"
    args = []
    if kind in ("proxy", "hosts"):
        sql += " AND kind=?"
        args.append(kind)
    if status in ("ok", "err", "skip", "ext"):
        sql += " AND status=?"
        args.append(status)
    if q:
        like = f"%{q}%"
        sql += " AND (host LIKE ? OR detail LIKE ? OR diff LIKE ? OR protocol LIKE ? OR actor LIKE ?)"
        args += [like] * 5
    if before:
        sql += " AND id<?"
        args.append(before)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(500, limit)))
    with _DB_LOCK:
        try:
            rows = _DB.execute(sql, args).fetchall()
        except sqlite3.Error:
            return []
    keys = ("id", "ts", "kind", "host", "actor", "status", "protocol", "detail", "diff", "seen")
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        d["detail"], d["diff"] = d["detail"][:240], d["diff"][:300]
        out.append(d)
    return out


def get_event(eid):
    if _DB is None:
        return None
    with _DB_LOCK:
        try:
            r = _DB.execute("SELECT id,ts,kind,host,actor,status,protocol,field,old,new,detail,diff,seen"
                            " FROM events WHERE id=?", (eid,)).fetchone()
        except sqlite3.Error:
            return None
    if not r:
        return None
    return dict(zip(("id", "ts", "kind", "host", "actor", "status", "protocol", "field",
                     "old", "new", "detail", "diff", "seen"), r))


def mark_seen(ids=None):
    if _DB is None:
        return
    with _DB_LOCK:
        try:
            if ids is None:
                _DB.execute("UPDATE events SET seen=1 WHERE seen=0")
            else:
                _DB.executemany("UPDATE events SET seen=1 WHERE id=?", [(int(i),) for i in ids[:500]])
            _DB.commit()
        except (sqlite3.Error, ValueError, TypeError):
            pass


def unseen_ext():
    if _DB is None:
        return 0
    with _DB_LOCK:
        try:
            return _DB.execute("SELECT COUNT(*) FROM events WHERE status='ext' AND seen=0").fetchone()[0]
        except sqlite3.Error:
            return 0


def event_stats(rng="24h"):
    """Итоги за сегодня/вчера/месяц + ряды для графика (сколько ПК исправлено в каждом отрезке)."""
    empty = {"ok": 0, "err": 0, "skip": 0, "ext": 0}
    if _DB is None:
        return {"totals": {"today": dict(empty), "yesterday": dict(empty), "month": dict(empty)},
                "series": {"labels": [], "proxy": [], "hosts": [], "ext": []}, "resets": reset_periods()}
    now = datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    spans = {"today": (today, now + timedelta(days=1)),
             "yesterday": (today - timedelta(days=1), today),
             "month": (today.replace(day=1), now + timedelta(days=1))}
    totals = {}
    with _DB_LOCK:
        for name, (a, b) in spans.items():
            row = dict(empty)
            for st, n in _DB.execute("SELECT status,COUNT(*) FROM events WHERE ts>=? AND ts<?"
                                     " GROUP BY status", (a.timestamp(), b.timestamp())):
                if st in row:
                    row[st] = n
            totals[name] = row
        if rng == "7d":
            starts = [today - timedelta(days=i) for i in range(6, -1, -1)]
            labels = [d.strftime("%d.%m") for d in starts]
        else:
            base = now.replace(minute=0, second=0, microsecond=0)
            starts = [base - timedelta(hours=i) for i in range(23, -1, -1)]
            labels = [d.strftime("%H:00") for d in starts]
        st_ts = [d.timestamp() for d in starts]
        rows = _DB.execute("SELECT ts,kind,host FROM events WHERE status='ok' AND actor IN ('me','auto')"
                           " AND ts>=?", (st_ts[0],)).fetchall()
    ext = [0] * len(starts)
    with _DB_LOCK:
        for (ts,) in _DB.execute("SELECT ts FROM events WHERE status='ext' AND host='local' AND ts>=?",
                                 (st_ts[0],)):
            i = bisect.bisect_right(st_ts, ts) - 1
            if 0 <= i < len(starts):
                ext[i] += 1
    sets = {"proxy": [set() for _ in starts], "hosts": [set() for _ in starts]}
    for ts, kind, host in rows:
        i = bisect.bisect_right(st_ts, ts) - 1
        if 0 <= i < len(starts) and kind in sets:
            sets[kind][i].add(host)
    return {"totals": totals,
            "series": {"labels": labels, "proxy": [len(x) for x in sets["proxy"]],
                       "hosts": [len(x) for x in sets["hosts"]], "ext": ext},
            "resets": reset_periods()}


def reset_periods():
    """Как часто система сама (извне) возвращает прокси и hosts на этом ПК: по реальным замерам."""
    out = {}
    for kind in ("proxy", "hosts"):
        rows = []
        if _DB is not None:
            with _DB_LOCK:
                rows = [r[0] for r in _DB.execute(
                    "SELECT ts FROM events WHERE kind=? AND host='local' AND status='ext'"
                    " ORDER BY ts DESC LIMIT 200", (kind,))][::-1]
        bursts = []
        for ts in rows:                       # серия изменений подряд (до 45 с) — одно событие
            if not bursts or ts - bursts[-1] > 45:
                bursts.append(ts)
        gaps = [(b - a) / 60.0 for a, b in zip(bursts, bursts[1:])]
        recent = gaps[-8:]
        med = statistics.median(recent) if recent else None
        stable = bool(recent) and len(recent) >= 3 and med > 0 and \
            all(abs(g - med) <= 0.2 * med for g in recent[-3:])
        out[kind] = {"changes": len(bursts), "samples": len(gaps),
                     "last_ts": bursts[-1] if bursts else None, "times": bursts[-5:],
                     "median_min": round(med, 1) if med else None,
                     "last_gap_min": round(gaps[-1], 1) if gaps else None,
                     "stable": stable,
                     "next_ts": (bursts[-1] + med * 60) if (bursts and med) else None}
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  ОБЩИЕ ФУНКЦИИ
# ═════════════════════════════════════════════════════════════════════════════
NOCHG = "Без изменений"


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _decode_best(raw):
    if not raw:
        return ""
    if raw.count(b"\x00") > len(raw) // 4:
        for enc in ("utf-16-le", "utf-16"):
            try:
                return raw.decode(enc, errors="replace")
            except Exception:
                pass
    for enc in ("utf-8", "cp866", "cp1251", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


# ── Полная остановка: флаг + убийство запущенных процессов и сокетов ──────────
CANCEL = threading.Event()
# Потоковые флаги: bg=True — фоновый поток (монитор), кнопка «Стоп» его не трогает;
# changes — заметки об изменениях, которые собирает текущая задача для журнала событий.
_CTX = threading.local()
_PROCS = set()
_SOCKS = set()
_KILL_LOCK = threading.Lock()


class JobCancelled(Exception):
    """Операция прервана кнопкой «Стоп»."""


def cancel_job():
    """Немедленно прерывает всё: новые запросы не стартуют, активные reg/sc убиваются."""
    CANCEL.set()
    with _KILL_LOCK:
        procs, socks = list(_PROCS), list(_SOCKS)
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass
    for s in socks:
        try:
            s.close()
        except Exception:
            pass


def _run(args, timeout=8):
    bg = getattr(_CTX, "bg", False)
    if CANCEL.is_set() and not bg:
        raise JobCancelled()
    try:
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
    except Exception:
        return "", -1
    if not bg:
        with _KILL_LOCK:
            _PROCS.add(p)
    try:
        if CANCEL.is_set() and not bg:   # «Стоп» нажат между проверкой и регистрацией
            p.kill()
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            return "", -1
        except Exception:
            return "", -1
    finally:
        if not bg:
            with _KILL_LOCK:
                _PROCS.discard(p)
    if CANCEL.is_set() and not bg:
        raise JobCancelled()
    return _decode_best(out), p.returncode


def _local_ips():
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        host = socket.gethostname()
        ips.add(host.lower())
        for info in socket.getaddrinfo(host, None):
            ips.add(str(info[4][0]).lower())
    except Exception:
        pass
    return ips


_LOCAL = _local_ips()


def is_local(ip):
    return ip.strip().lower() in _LOCAL


def reachable(ip, timeout=2.0):
    """Проверяет, открыты ли порты SMB/RPC, нужные для удалённого реестра."""
    bg = getattr(_CTX, "bg", False)
    for p in (445, 135):
        if CANCEL.is_set() and not bg:
            raise JobCancelled()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if not bg:
                with _KILL_LOCK:
                    _SOCKS.add(s)
            rc = s.connect_ex((ip, p))
            if rc == 0:
                return True
        except Exception:
            pass
        finally:
            if not bg:
                with _KILL_LOCK:
                    _SOCKS.discard(s)
            try:
                s.close()
            except Exception:
                pass
        if CANCEL.is_set() and not bg:
            raise JobCancelled()
    return False


MAX_TARGETS = 65536


def parse_targets(text):
    """Адреса через пробел/запятую/новую строку:
       10.0.0.5 | 10.0.0.1-10.0.0.50 | 10.0.0.1-50 | 10.0.0.0/24 | localhost | имя-хоста"""
    out = []
    for tok in re.split(r"[\s,;]+", text or ""):
        tok = tok.strip()
        if not tok:
            continue
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                out.extend(str(h) for h in net.hosts())
            elif "-" in tok and re.match(r"^\d+\.\d+\.\d+\.\d+-\d+(\.\d+\.\d+\.\d+)?$", tok):
                a, b = tok.split("-")
                if "." not in b:
                    b = ".".join(a.split(".")[:3] + [b])
                x, y = int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))
                if x > y:
                    x, y = y, x
                out.extend(str(ipaddress.IPv4Address(i)) for i in range(x, y + 1))
            else:
                out.append(tok)
        except ValueError:
            raise ValueError(f"Неверный адрес: {tok}")
        if len(out) > MAX_TARGETS:
            raise ValueError(f"Адресов больше {MAX_TARGETS}")
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def expand_targets(targets):
    """Список записей -> список IP без повторов."""
    if isinstance(targets, str):
        targets = [targets]
    ips, seen = [], set()
    for t in targets or []:
        addr = norm_target(t)
        if not addr:
            continue
        for ip in parse_targets(addr):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        if len(ips) > MAX_TARGETS:
            raise ValueError(f"Адресов больше {MAX_TARGETS}")
    return ips


def split_entries(text):
    return [e.strip() for e in re.split(r"[;\n\r]+", text or "") if e.strip()]


# ═════════════════════════════════════════════════════════════════════════════
#  ПРОКСИ — ProxyOverride (исключения)
# ═════════════════════════════════════════════════════════════════════════════
INET_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _broadcast_settings_change():
    try:
        w = ctypes.windll.Wininet
        w.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        w.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        pass


def _local_get_value(name, default=""):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_PATH, 0, winreg.KEY_READ) as k:
            try:
                return winreg.QueryValueEx(k, name)[0]
            except FileNotFoundError:
                return default
    except FileNotFoundError:
        return default
    except OSError:
        return None


def _local_set_value(name, value, kind=winreg.REG_SZ):
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, INET_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, name, 0, kind, value)
        winreg.CloseKey(k)
        _broadcast_settings_change()
        return True
    except OSError:
        return False


def _local_get_override():
    return _local_get_value("ProxyOverride", "")


def _local_set_override(val):
    return _local_set_value("ProxyOverride", val)


def _ensure_remote_registry(ip, timeout=6):
    out, _ = _run(["sc", f"\\\\{ip}", "query", "RemoteRegistry"], timeout)
    if "RUNNING" in out.upper():
        return True
    _run(["sc", f"\\\\{ip}", "config", "RemoteRegistry", "start=", "demand"], timeout)
    _run(["sc", f"\\\\{ip}", "start", "RemoteRegistry"], max(timeout, 6))
    out, _ = _run(["sc", f"\\\\{ip}", "query", "RemoteRegistry"], timeout)
    return "RUNNING" in out.upper()


def _remote_user_sids(ip, timeout=8):
    out, rc = _run(["reg", "query", f"\\\\{ip}\\HKU"], timeout)
    if rc != 0 or not out:
        return None
    sids = []
    for line in out.replace("\x00", "").splitlines():
        line = line.strip()
        if line.endswith("_Classes"):
            continue
        m = re.search(r"(S-1-5-21-[\d-]+)$", line)
        if m:
            sids.append(m.group(1))
    return sids


def _remote_get_override(ip, sid, timeout=8):
    path = f"\\\\{ip}\\HKU\\{sid}\\{INET_PATH}"
    out, rc = _run(["reg", "query", path, "/v", "ProxyOverride"], timeout)
    if rc != 0:
        return ""
    m = re.search(r"ProxyOverride\s+REG_SZ\s+(.*)", out.replace("\x00", ""))
    return m.group(1).strip() if m else ""


def _remote_set_override(ip, sid, val, timeout=10):
    path = f"\\\\{ip}\\HKU\\{sid}\\{INET_PATH}"
    _, rc = _run(["reg", "add", path, "/v", "ProxyOverride", "/t", "REG_SZ",
                  "/d", val, "/f"], timeout)
    return rc == 0


_STATE_KEYS = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")


def _empty_state():
    return {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": "", "AutoConfigURL": ""}


def _fmt_state(st, prefix=""):
    """Состояние прокси -> читаемый текст (его же храним в снимках и событиях)."""
    return "\n".join(f"{prefix}{k}: {st.get(k, '')}" for k in _STATE_KEYS)


def _remote_proxy_state(ip, sid, timeout=8):
    """Все четыре значения прокси пользователя одним вызовом reg query. None — ключ не прочитан."""
    path = f"\\\\{ip}\\HKU\\{sid}\\{INET_PATH}"
    out, rc = _run(["reg", "query", path], timeout)
    if rc != 0:
        return None
    st = _empty_state()
    for line in out.replace("\x00", "").splitlines():
        m = re.match(r"^\s+(\w+)\s+REG_(SZ|DWORD|EXPAND_SZ)\s*(.*?)\s*$", line)
        if not m or m.group(1) not in st:
            continue
        if m.group(2) == "DWORD":
            try:
                st[m.group(1)] = int(m.group(3), 0)
            except ValueError:
                pass
        else:
            st[m.group(1)] = m.group(3)
    st["ProxyEnable"] = 1 if st["ProxyEnable"] == 1 else 0
    return st


def local_state():
    st = _empty_state()
    for k in _STATE_KEYS:
        v = _local_get_value(k, st[k])
        st[k] = v if v is not None else st[k]
    st["ProxyEnable"] = 1 if st["ProxyEnable"] == 1 else 0
    return st


def local_state_text():
    return _fmt_state(local_state())


def remote_proxy_snapshot(ip, timeout=8):
    """-> (текст состояния всех профилей, ошибка)"""
    sids, err = _remote_prepare(ip, timeout)
    if err:
        return None, err
    parts = []
    for sid in sorted(sids):
        st = _remote_proxy_state(ip, sid, timeout) or _empty_state()
        parts.append(_fmt_state(st, f"[{sid[-6:]}] "))
    return "\n".join(parts), None


def _local_enable_proxy():
    """-> on | enabled | fail. Включает прокси независимо от наличия сервера."""
    if _local_get_value("ProxyEnable", 0) == 1:
        return "on"
    return "enabled" if _local_set_value("ProxyEnable", 1, winreg.REG_DWORD) else "fail"


def _enable_prefix(states):
    """Текст-приставка к результату по итогам включения прокси."""
    if "enabled" in states:
        return "Прокси включён; "
    return ""


def _merge(current, new_entries):
    existing = [e.strip() for e in current.split(";") if e.strip()]
    added = []
    for e in new_entries:
        e = e.strip()
        if e and e not in existing:
            existing.append(e)
            added.append(e)
    return ";".join(existing), added


def _unmerge(current, entries):
    drop = {e.strip().lower() for e in entries if e.strip()}
    keep, removed = [], []
    for e in (x.strip() for x in current.split(";") if x.strip()):
        (removed if e.lower() in drop else keep).append(e)
    return ";".join(keep), removed


def _remote_prepare(ip, timeout):
    """-> (sids, текст_ошибки)"""
    if not reachable(ip, min(timeout, 2.0)):
        return None, "Нет связи (выключен или порт закрыт)"
    if not _ensure_remote_registry(ip, timeout):
        return None, "Не удалось запустить Remote Registry (нет прав?)"
    sids = _remote_user_sids(ip, timeout)
    if sids is None:
        return None, "Не удалось прочитать HKU (нет прав)"
    if not sids:
        return None, "Профиль пользователя не найден (никто не вошёл?)"
    return sids, None


def _proxy_add_local(entries, enable):
    st = _local_enable_proxy() if enable else "skip"
    if st == "fail":
        return False, "Не удалось включить прокси — исключения не добавлены"
    pre = _enable_prefix([st])
    cur = _local_get_override()
    if cur is None:
        return False, "Не удалось открыть локальный реестр"
    new_val, added = _merge(cur, entries)
    if not added:
        return True, (f"[локально] {pre}записи уже есть" if st == "enabled"
                      else f"{NOCHG}: {pre}все записи уже есть")
    if _local_set_override(new_val):
        return True, f"[локально] {pre}Добавлено: {', '.join(added)}"
    return False, "Ошибка записи в локальный реестр (нет прав?)"


def _proxy_remove_local(entries):
    cur = _local_get_override()
    if cur is None:
        return False, "Не удалось открыть локальный реестр"
    new_val, removed = _unmerge(cur, entries)
    if not removed:
        return True, f"{NOCHG}: совпадений нет"
    if _local_set_override(new_val):
        return True, f"[локально] Удалено: {', '.join(removed)}"
    return False, "Ошибка записи в локальный реестр (нет прав?)"


def _local_write(fn, *args):
    """Локальная запись прокси с учётом в журнале: снимок «до/после» + защита от ложного «внешнего» события."""
    begin_write("proxy", "local")
    before = local_state_text()
    try:
        res = fn(*args)
    finally:
        after = local_state_text()
        end_write("proxy", "local", after)
    _note_change(before, after, PROTO_LOCAL_REG)
    return res


def proxy_add(ip, entries, timeout=5.0, enable=True):
    """enable=True — сначала включить прокси, потом добавить; False — только добавить исключения."""
    entries = [e.strip() for e in entries if e.strip()]
    if not entries:
        return True, "Нет записей для добавления"
    # Сначала (если нужно) включаем прокси, и только потом добавляем исключения.
    if is_local(ip):
        return _local_write(_proxy_add_local, entries, enable)

    sids, err = _remote_prepare(ip, timeout)
    if err:
        return False, err
    all_added, states, fail = [], [], 0
    before_p, after_p = [], []
    begin_write("proxy", ip)
    try:
        for sid in sorted(sids):
            tag = f"[{sid[-6:]}] "
            cur = _remote_proxy_state(ip, sid, timeout) or _empty_state()
            before_p.append(_fmt_state(cur, tag))
            st = "skip"
            if enable:
                if cur["ProxyEnable"] == 1:
                    st = "on"
                else:
                    path = f"\\\\{ip}\\HKU\\{sid}\\{INET_PATH}"
                    _, rc = _run(["reg", "add", path, "/v", "ProxyEnable", "/t", "REG_DWORD",
                                  "/d", "1", "/f"], timeout)
                    st = "enabled" if rc == 0 else "fail"
                    if st == "enabled":
                        cur["ProxyEnable"] = 1
            states.append(st)
            if st != "fail":                  # прокси не включился — исключения не пишем
                new_val, added = _merge(cur["ProxyOverride"], entries)
                if added:
                    if _remote_set_override(ip, sid, new_val, timeout):
                        all_added.extend(added)
                        cur["ProxyOverride"] = new_val
                    else:
                        fail += 1
            else:
                fail += 1
            after_p.append(_fmt_state(cur, tag))
    finally:
        after = "\n".join(after_p)
        end_write("proxy", ip, after if len(after_p) == len(sids) else None)
        _note_change("\n".join(before_p), after, PROTO_REMOTE_REG)
    pre = _enable_prefix(states)
    if all_added:
        return True, f"{pre}Добавлено: {', '.join(sorted(set(all_added)))}"
    if fail:
        return False, "Ошибка записи в реестр (прокси/исключения)"
    if "enabled" in states:
        return True, f"{pre}записи уже есть"
    return True, f"{NOCHG}: {pre}все записи уже есть"


def proxy_remove(ip, entries, timeout=5.0):
    entries = [e.strip() for e in entries if e.strip()]
    if not entries:
        return True, "Нет записей для удаления"
    if is_local(ip):
        return _local_write(_proxy_remove_local, entries)

    sids, err = _remote_prepare(ip, timeout)
    if err:
        return False, err
    all_rm, fail = [], 0
    before_p, after_p = [], []
    begin_write("proxy", ip)
    try:
        for sid in sorted(sids):
            tag = f"[{sid[-6:]}] "
            cur = _remote_proxy_state(ip, sid, timeout) or _empty_state()
            before_p.append(_fmt_state(cur, tag))
            new_val, removed = _unmerge(cur["ProxyOverride"], entries)
            if removed:
                if _remote_set_override(ip, sid, new_val, timeout):
                    all_rm.extend(removed)
                    cur["ProxyOverride"] = new_val
                else:
                    fail += 1
            after_p.append(_fmt_state(cur, tag))
    finally:
        after = "\n".join(after_p)
        end_write("proxy", ip, after if len(after_p) == len(sids) else None)
        _note_change("\n".join(before_p), after, PROTO_REMOTE_REG)
    if all_rm:
        return True, f"Удалено: {', '.join(sorted(set(all_rm)))}"
    if fail:
        return False, "Ошибка записи в реестр"
    return True, f"{NOCHG}: совпадений нет"


def proxy_read(ip, timeout=5.0):
    if is_local(ip):
        cur = _local_get_override()
        if cur is None:
            return False, "Не удалось открыть локальный реестр"
        return True, f"[локально] {cur or '(пусто)'}"
    sids, err = _remote_prepare(ip, timeout)
    if err:
        return False, err
    return True, " | ".join(
        f"{sid[-6:]}: {_remote_get_override(ip, sid, timeout) or '(пусто)'}" for sid in sids)


# ── Локальный прокси (включить/выключить, сервер) ───────────────────────────
def local_proxy_info():
    enable = _local_get_value("ProxyEnable", 0)
    return {
        "enable": 1 if enable == 1 else 0,
        "server": _local_get_value("ProxyServer", "") or "",
        "override": _local_get_value("ProxyOverride", "") or "",
        "pac": _local_get_value("AutoConfigURL", "") or "",
    }


def local_proxy_set(enable=None, server=None, override=None):
    begin_write("proxy", "local")
    before = local_state_text()
    ok = True
    try:
        if server is not None:
            ok &= _local_set_value("ProxyServer", server)
        if override is not None:
            ok &= _local_set_value("ProxyOverride", override)
        if enable is not None:
            ok &= _local_set_value("ProxyEnable", 1 if enable else 0, winreg.REG_DWORD)
        _broadcast_settings_change()
    finally:
        after = local_state_text()
        end_write("proxy", "local", after)
    if not ok:
        record_event("proxy", "local", "me", "err", PROTO_LOCAL_REG, "", before, after,
                     "Ошибка записи в реестр (кнопка питания / параметры)")
    elif before == after:
        record_event("proxy", "local", "me", "skip", PROTO_LOCAL_REG, "", before, after,
                     f"{NOCHG}: значения уже такие (кнопка питания / параметры)")
    else:
        record_event("proxy", "local", "me", "ok", PROTO_LOCAL_REG, "", before, after,
                     "Изменено вручную: кнопка питания / параметры локального прокси")
    return bool(ok)


# ═════════════════════════════════════════════════════════════════════════════
#  ФАЙЛ HOSTS
# ═════════════════════════════════════════════════════════════════════════════
def _hosts_norm(text):
    """Единый вид для сравнения: переводы строк \n, без хвостовых пробелов и пустых строк по краям."""
    lines = (text or "").replace("\ufeff", "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(l.rstrip() for l in lines).strip("\n")


def hosts_info():
    """Состояние файла hosts на этом ПК для интерфейса."""
    try:
        with open(HOSTS_PATH, "rb") as f:
            raw = f.read()
        st = os.stat(HOSTS_PATH)
    except OSError as e:
        return {"path": HOSTS_PATH, "exists": False, "text": "", "size": 0, "mtime": 0,
                "error": e.strerror or str(e)}
    text = _decode_best(raw).lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    return {"path": HOSTS_PATH, "exists": True, "text": text, "size": len(raw), "mtime": st.st_mtime}


def hosts_mtime():
    try:
        return os.stat(HOSTS_PATH).st_mtime
    except OSError:
        return 0


def _hosts_read_local():
    """-> (нормализованный текст | None, ошибка)"""
    try:
        with open(HOSTS_PATH, "rb") as f:
            return _hosts_norm(_decode_best(f.read())), None
    except FileNotFoundError:
        return "", None
    except OSError as e:
        return None, f"Не удалось прочитать hosts: {e.strerror or e}"


def _hosts_write_local(norm):
    data = (norm.replace("\n", "\r\n") + "\r\n").encode("utf-8")
    with open(HOSTS_PATH, "wb") as f:
        f.write(data)


def _hosts_write_elevated(norm):
    """Нет прав на запись: копируем через повышенный процесс (появится запрос UAC — его нужно подтвердить)."""
    tmp = _hosts_tmp()
    try:
        with open(tmp, "wb") as f:
            f.write((norm.replace("\n", "\r\n") + "\r\n").encode("utf-8"))
        args = f'/c copy /y "{tmp}" "{HOSTS_PATH}"'
        ps = f"Start-Process -FilePath cmd.exe -ArgumentList '{args}' -Verb RunAs -Wait -WindowStyle Hidden"
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=120,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    cur, _ = _hosts_read_local()
    return cur == norm


def _hosts_unc(ip):
    return f"\\{ip}\ADMIN$\System32\drivers\etc\hosts"


def _hosts_tmp():
    _ensure_dir()
    return os.path.join(DATA_DIR, f"hosts_{os.getpid()}_{threading.get_ident()}.tmp")


def hosts_remote_read(ip, timeout=8):
    """-> (нормализованный текст | None, ошибка)"""
    if not reachable(ip, min(timeout, 2.0)):
        return None, "Нет связи (выключен или порт закрыт)"
    tmp = _hosts_tmp()
    try:
        _, rc = _run(["cmd", "/c", "copy", "/y", _hosts_unc(ip), tmp], timeout)
        if rc != 0:
            return None, "Не удалось прочитать hosts (нет доступа к ADMIN$?)"
        with open(tmp, "rb") as f:
            return _hosts_norm(_decode_best(f.read())), None
    except OSError as e:
        return None, f"Ошибка чтения копии hosts: {e.strerror or e}"
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _hosts_remote_write(ip, norm, timeout):
    tmp = _hosts_tmp()
    try:
        with open(tmp, "wb") as f:
            f.write((norm.replace("\n", "\r\n") + "\r\n").encode("utf-8"))
        _, rc = _run(["cmd", "/c", "copy", "/y", tmp, _hosts_unc(ip)], timeout)
        return rc == 0
    except OSError:
        return False
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def hosts_apply(ip, content, timeout=5.0):
    """Записывает содержимое hosts на компьютер. Уже применено или ошибка — просто пропуск для этого адреса."""
    new = _hosts_norm(content)
    if not new.strip():
        return False, "Пустое содержимое hosts — не применяется"
    if is_local(ip):
        cur, err = _hosts_read_local()
        if err:
            return False, err
        if cur == new:
            return True, f"{NOCHG}: [локально] hosts уже применён"
        begin_write("hosts", "local")
        via = ""
        try:
            _hosts_write_local(new)
        except PermissionError:
            if _hosts_write_elevated(new):
                via = " (через запрос UAC)"
            else:
                end_write("hosts", "local", None)
                return False, "Отказано в доступе: подтвердите запрос UAC или запустите ProxyTool от администратора"
        except OSError as e:
            end_write("hosts", "local", None)
            return False, f"Ошибка записи hosts: {e.strerror or e}"
        end_write("hosts", "local", new)
        _note_change(cur, new, PROTO_LOCAL_HOSTS + via)
        return True, "[локально] hosts обновлён" + via

    cur, err = hosts_remote_read(ip, timeout)
    if err:
        return False, err
    if cur == new:
        return True, f"{NOCHG}: hosts уже применён"
    begin_write("hosts", ip)
    ok = _hosts_remote_write(ip, new, timeout)
    end_write("hosts", ip, new if ok else None)
    if not ok:
        return False, "Ошибка записи hosts (нет доступа к ADMIN$ / файл занят)"
    _note_change(cur, new, PROTO_REMOTE_HOSTS)
    return True, "hosts обновлён"


# ═════════════════════════════════════════════════════════════════════════════
#  ЗАДАЧИ и АВТО-ТАЙМЛАЙН
# ═════════════════════════════════════════════════════════════════════════════
TOOLS = {
    "proxy_add":    ("Прокси: добавить",  lambda ip, p, t: proxy_add(ip, p["entries"], t, p.get("enable", True))),
    "proxy_remove": ("Прокси: удалить",   lambda ip, p, t: proxy_remove(ip, p["entries"], t)),
    "proxy_read":   ("Прокси: прочитать", lambda ip, p, t: proxy_read(ip, t)),
    "hosts_apply":  ("Hosts: применить",  lambda ip, p, t: hosts_apply(ip, p["content"], t)),
}
EVENT_TOOLS = {"proxy_add": "proxy", "proxy_remove": "proxy", "hosts_apply": "hosts"}


def _task_status(ok, msg):
    return "err" if not ok else ("skip" if NOCHG in msg else "ok")


def _record_task_event(tool, ip, ok, msg, actor):
    """Результат по одному адресу -> журнал событий (SQLite)."""
    kind = EVENT_TOOLS[tool]
    local = is_local(ip)
    ch = getattr(_CTX, "changes", None) or []
    if ch:
        old = "\n".join(c[0] for c in ch)
        new = "\n".join(c[1] for c in ch)
        proto = ch[0][2]
    else:
        old = new = ""
        if local:
            proto = PROTO_LOCAL_REG if kind == "proxy" else PROTO_LOCAL_HOSTS
        else:
            proto = PROTO_REMOTE_REG if kind == "proxy" else PROTO_REMOTE_HOSTS
    record_event(kind, "local" if local else ip, actor, _task_status(ok, msg), proto, "", old, new, msg)


JOB ={"running": False, "name": "", "done": 0, "total": 0, "ok": 0, "skip": 0, "err": 0}
_JOB_LOCK = threading.Lock()


def run_over_targets(tool, items, params, workers, timeout, prefix=""):
    """items — список IP; params["enable"] — включать ли прокси перед добавлением исключений."""
    title, fn = TOOLS[tool]
    tag = EVENT_TOOLS.get(tool, "")
    log("head", f"== {prefix}{title} | адресов: {len(items)} | потоков: {workers} ==", tag)
    ok_n = skip_n = err_n = 0
    actor = "auto" if prefix else "me"

    def task(ip):
        if CANCEL.is_set():
            return ip, None, ""
        _CTX.changes = []
        try:
            ok, msg = fn(ip, params, timeout)
        except JobCancelled:
            return ip, None, ""
        except Exception as e:  # один адрес не должен ронять весь цикл
            ok, msg = False, f"Исключение: {e}"
        if tool in EVENT_TOOLS:
            try:
                _record_task_event(tool, ip, ok, msg, actor)
            except Exception:
                pass
        return ip, ok, msg

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        futs = [ex.submit(task, ip) for ip in items]
        for f in as_completed(futs):
            if f.cancelled():
                continue
            ip, ok, msg = f.result()
            if ok is None:                 # прервано — в журнал и счётчики не пишем
                continue
            st = _task_status(ok, msg)
            if st == "err":
                lv = "err"; err_n += 1
            elif st == "skip":
                lv = "skip"; skip_n += 1
            else:
                lv = "ok"; ok_n += 1
            log(lv, f"{ip:16s} {msg}", tag)
            with _JOB_LOCK:
                JOB["done"] += 1
                JOB["ok"], JOB["skip"], JOB["err"] = ok_n, skip_n, err_n
    finally:
        ex.shutdown(wait=True, cancel_futures=True)
    if CANCEL.is_set():
        log("warn", f"-> ОСТАНОВЛЕНО | успешно: {ok_n} | без изменений: {skip_n} | ошибок: {err_n}", tag)
    else:
        log("head", f"-> успешно: {ok_n} | без изменений: {skip_n} | ошибок: {err_n}", tag)
    return ok_n, skip_n, err_n


def _wait_job_idle(seconds=5.0):
    """После «Стоп» активные процессы убиваются за доли секунды — ждём, пока задача освободит слот."""
    end = datetime.now() + timedelta(seconds=seconds)
    while datetime.now() < end:
        with _JOB_LOCK:
            if not JOB["running"]:
                return True
        threading.Event().wait(0.05)
    return False


def apply_skips(items):
    """Убирает адреса из списка «пропускать» (читается при каждом запуске, поэтому действует и в автообновлении).
    -> (оставшиеся, сколько убрано)"""
    skips = set(load_settings().get("skips") or [])
    if not skips:
        return items, 0
    kept = [ip for ip in items if ip not in skips]
    return kept, len(items) - len(kept)


def start_job(tool, items, params, workers, timeout):
    items, n_skip = apply_skips(items)
    if not items:
        return False, "Все адреса отмечены как пропускаемые — делать нечего"
    with _JOB_LOCK:
        if JOB["running"]:
            return False, "Уже выполняется другая задача"
        CANCEL.clear()
        JOB.update(running=True, name=TOOLS[tool][0], done=0, total=len(items), ok=0, skip=0, err=0)

    def runner():
        try:
            if n_skip:
                log("info", f"Пропущено адресов из списка исключённых: {n_skip}", EVENT_TOOLS.get(tool, ""))
            run_over_targets(tool, items, params, workers, timeout)
        finally:
            with _JOB_LOCK:
                JOB["running"] = False

    threading.Thread(target=runner, daemon=True).start()
    return True, "Запущено"


class AutoTimeline:
    """Периодически повторяет добавление исключений: каждые N часов/минут."""

    def __init__(self):
        self.running = False
        self.cycle = 0
        self.next_ts = None
        self.cfg = None
        self.last = ""
        self.initial_delay = 0
        self._stop = threading.Event()      # у каждого запуска свой — старый цикл не оживает
        self._lock = threading.Lock()

    def start(self, cfg, raw=None, restored=False):
        """raw — исходные параметры запроса: их сохраняем в AppData, чтобы после
        перезапуска/перезагрузки автообновление продолжилось само."""
        with self._lock:
            if self.running:
                return False, "Автообновление уже запущено"
        if CANCEL.is_set() and not _wait_job_idle():
            return False, "Предыдущая задача ещё останавливается, повторите"
        with self._lock:
            if self.running:
                return False, "Автообновление уже запущено"
            self.running, self.cycle, self.cfg, self.last = True, 0, cfg, ""
            self.initial_delay = 15 if restored else 0   # дать сети подняться после загрузки
            self._stop = stop = threading.Event()
        if not restored:
            save_auto_state(True, raw)
        threading.Thread(target=self._loop, args=(stop,), daemon=True).start()
        unit = "ч" if cfg["unit"] == "soat" else "мин"
        src = "ВОССТАНОВЛЕНО после перезапуска" if restored else "ЗАПУЩЕНО"
        log("info", f"Автообновление {src}: каждые {cfg['every']} {unit} ({TOOLS[cfg['tool']][0]})")
        return True, "Запущено"

    def stop(self, persist=True):
        """Полная остановка: цикл завершается, текущая задача прерывается, reg/sc убиваются.
        persist=False — это выход программы, а не команда пользователя:
        флаг «работало» остаётся в файле, и при следующем старте цикл возобновится."""
        with self._lock:
            was = self.running
            self.running = False
            self.next_ts = None
            stop = self._stop
        with _JOB_LOCK:
            stop.set()
        cancel_job()
        if persist:
            save_auto_state(False, None)
            if was:
                log("info", "Автообновление ОСТАНОВЛЕНО")

    def _loop(self, stop):
        c = self.cfg
        secs = max(1, int(c["every"])) * (3600 if c["unit"] == "soat" else 60)
        if self.initial_delay and stop.wait(self.initial_delay):
            return
        while not stop.is_set():
            self.cycle += 1
            items, n_skip = apply_skips(c["items"])
            with _JOB_LOCK:
                busy = JOB["running"]
                started = not busy and not stop.is_set() and bool(items)
                if started:
                    CANCEL.clear()
                    JOB.update(running=True, name=f"АВТО №{self.cycle}: {TOOLS[c['tool']][0]}",
                               done=0, total=len(items), ok=0, skip=0, err=0)
            if busy:
                log("warn", f"Цикл №{self.cycle}: выполняется другая задача — пропущен")
            elif not items:
                log("warn", f"Цикл №{self.cycle}: все адреса отмечены как пропускаемые — пропущен")
            elif started:
                try:
                    if n_skip:
                        log("info", f"Цикл №{self.cycle}: пропущено адресов из списка исключённых: {n_skip}")
                    o, s, e = run_over_targets(c["tool"], items, c["params"], c["workers"],
                                               c["timeout"], prefix=f"Цикл №{self.cycle} | ")
                    if not stop.is_set():
                        self.last = f"№{self.cycle}: обновлено {o}, без изменений {s}, ошибок {e}"
                finally:
                    with _JOB_LOCK:
                        JOB["running"] = False
            if stop.is_set():
                break
            self.next_ts = (datetime.now() + timedelta(seconds=secs)).timestamp()
            if stop.wait(secs):
                break
        if self._stop is stop:
            self.running = False
            self.next_ts = None

    def state(self):
        return {"running": self.running, "cycle": self.cycle, "next_ts": self.next_ts,
                "last": self.last,
                "cfg": None if not self.cfg else {
                    "tool": self.cfg["tool"], "every": self.cfg["every"], "unit": self.cfg["unit"],
                    "targets": len(self.cfg["items"])}}


AUTO = AutoTimeline()


def build_request(body):
    tool = body.get("tool", "")
    if tool not in TOOLS:
        raise ValueError("Неизвестная операция")
    items = expand_targets(body.get("targets", []))
    if not items:
        raise ValueError("Добавьте хотя бы один адрес")
    entries = split_entries(body.get("entries", ""))
    if tool in ("proxy_add", "proxy_remove") and not entries:
        raise ValueError("Список исключений пуст")
    content = str(body.get("content", ""))[:500000]
    if tool == "hosts_apply" and not content.strip():
        raise ValueError("Содержимое hosts пусто")
    try:
        workers = min(200, max(1, int(body.get("workers", 50))))
    except (TypeError, ValueError):
        workers = 50
    try:
        timeout = max(1.0, float(body.get("timeout", 5)))
    except (TypeError, ValueError):
        timeout = 5.0
    return tool, items, {"entries": entries, "enable": body.get("proxy_on") is not False,
                         "content": content}, workers, timeout


def auto_cfg_from_body(body):
    """-> (cfg для AutoTimeline, raw для сохранения в AppData)"""
    tool, items, params, workers, timeout = build_request(body)
    if tool != "proxy_add":
        raise ValueError("Эта операция не подходит для автообновления")
    unit = body.get("unit") if body.get("unit") in ("soat", "daqiqa") else "soat"
    try:
        every = max(1, int(body.get("every", 1)))
    except (TypeError, ValueError):
        every = 1
    cfg = {"tool": tool, "items": items, "params": params, "workers": workers,
           "timeout": timeout, "every": every, "unit": unit}
    targets = body.get("targets", "")
    if isinstance(targets, list):
        targets = [norm_target(t) for t in targets[:2000]]
    raw = {"tool": tool, "targets": targets, "entries": str(body.get("entries", ""))[:20000],
           "workers": workers, "timeout": timeout, "every": every, "unit": unit,
           "proxy_on": params["enable"]}
    return cfg, raw


def save_auto_state(running, raw):
    """Атомарно пишет состояние автообновления (running + параметры) в AppData."""
    data = {"running": bool(running)}
    if raw:
        data["raw"] = raw
    else:
        try:  # при остановке сохраняем прежние параметры, меняем только флаг
            with open(AUTO_FILE, "r", encoding="utf-8") as f:
                old = json.load(f)
            if isinstance(old, dict) and old.get("raw"):
                data["raw"] = old["raw"]
        except (OSError, ValueError):
            pass
    _ensure_dir()
    try:
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, AUTO_FILE)
    except OSError:
        pass


def restore_auto():
    """При старте: если автообновление работало до выключения — запускаем снова."""
    try:
        with open(AUTO_FILE, "r", encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        return
    if not (isinstance(st, dict) and st.get("running") and isinstance(st.get("raw"), dict)):
        return
    try:
        cfg, raw = auto_cfg_from_body(st["raw"])
    except ValueError as e:
        log("warn", f"Не удалось восстановить автообновление: {e}")
        return
    AUTO.start(cfg, raw, restored=True)


# ═════════════════════════════════════════════════════════════════════════════
#  МОНИТОРИНГ: этот ПК (всегда) и выбранные удалённые ПК + быстрый ping-скан
# ═════════════════════════════════════════════════════════════════════════════
def _int_setting(cfg, key, default, lo, hi):
    try:
        return max(lo, min(hi, int(float(cfg.get(key) or default))))
    except (TypeError, ValueError):
        return default


def _policy_hint():
    """Есть ли политика прокси от домена (GPO) — для подсказки об источнике внешнего изменения."""
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(root, r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"):
                return "Групповая политика (GPO): в реестре есть ключ Policies\\…\\Internet Settings"
        except OSError:
            pass
    return "Внешняя запись в реестр (скрипт, логон-скрипт, агент или другая программа)"


def ping_ip(ip, timeout=0.6):
    """Быстрая проверка живости: время отклика TCP 445/135 в мс. 'Отказ в соединении' тоже значит «жив»."""
    for port in (445, 135):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            rc = s.connect_ex((ip, port))
        except Exception:
            rc = -1
        finally:
            try:
                s.close()
            except Exception:
                pass
        if rc in (0, 10061):
            return max(1, int((time.perf_counter() - t0) * 1000))
    return None


class Monitor:
    def __init__(self):
        self.stop = threading.Event()
        self.kick = threading.Event()    # «список наблюдаемых ПК изменился — проверить сразу»
        self.rstate = {}                 # (kind, ip) -> {online, ms, checked, err, changed}
        self._lk = threading.Lock()

    def start(self):
        threading.Thread(target=self._local_loop, daemon=True).start()
        threading.Thread(target=self._remote_loop, daemon=True).start()

    # ── этот компьютер ──
    def _local_loop(self):
        _CTX.bg = True
        while True:
            self._check_local()
            every = _int_setting(load_settings(), "mon_every", 10, 2, 3600)
            if self.stop.wait(every):
                return

    def _check_local(self):
        try:
            seq = _wseq("proxy", "local")
            txt = local_state_text()
            observe("proxy", "local", txt, seq, _policy_hint())
            seq = _wseq("hosts", "local")
            norm, err = _hosts_read_local()
            if norm is not None:
                observe("hosts", "local", norm, seq,
                        "Внешняя запись в файл hosts (скрипт, агент, антивирус или другая программа)")
        except Exception as e:
            log("err", f"Монитор (этот ПК): {e}")

    # ── удалённые ПК ──
    def _remote_loop(self):
        _CTX.bg = True
        if self.stop.wait(5):
            return
        while not self.stop.is_set():
            self.kick.clear()
            cfg = load_settings()
            jobs = [(k, ip) for k, key in (("proxy", "watch_proxy"), ("hosts", "watch_hosts"))
                    for ip in cfg.get(key) or [] if not is_local(ip)]
            wanted = set(jobs)
            with self._lk:
                for key in [k for k in self.rstate if k not in wanted]:
                    del self.rstate[key]
            if jobs:
                workers = min(50, _int_setting(cfg, "workers", 50, 1, 200), len(jobs))
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    list(ex.map(self._check_remote, jobs))
            if self.kick.wait(_int_setting(cfg, "watch_every", 60, 10, 86400)):
                if self.stop.wait(1.5):       # несколько кликов подряд — одна проверка
                    return
            if self.stop.is_set():
                return

    def _check_remote(self, job):
        _CTX.bg = True
        kind, ip = job
        ms = ping_ip(ip, 1.0)
        st = {"online": ms is not None, "ms": ms, "checked": time.time(), "err": ""}
        if ms is not None:
            try:
                seq = _wseq(kind, ip)
                if kind == "proxy":
                    txt, err = remote_proxy_snapshot(ip, 8)
                    proto = PROTO_REMOTE_REG + " — удалённое наблюдение"
                else:
                    txt, err = hosts_remote_read(ip, 8)
                    proto = PROTO_REMOTE_HOSTS + " — удалённое наблюдение"
                if err:
                    st["err"] = err
                elif observe(kind, ip, txt, seq, proto) == "changed":
                    st["changed"] = time.time()
            except Exception as e:
                st["err"] = str(e)
        with self._lk:
            st.setdefault("changed", self.rstate.get(job, {}).get("changed"))
            self.rstate[job] = st

    def states(self):
        with self._lk:
            return [dict(v, kind=k[0], ip=k[1]) for k, v in self.rstate.items()]


MON = Monitor()

SCAN = {"running": False, "done": 0, "total": 0, "items": [], "id": 0}
_SCAN_LOCK = threading.Lock()


def scan_start(kind="proxy"):
    """Пингует все адреса из интервалов (прокси или hosts) одновременно. Результаты копятся в SCAN['items']."""
    items = expand_targets(load_settings().get("hosts_targets" if kind == "hosts" else "targets"))
    items, _ = apply_skips(items)
    items = [ip for ip in items if not is_local(ip)]
    if not items:
        return False, "Нет адресов для проверки: добавьте интервалы на этой вкладке"
    with _SCAN_LOCK:
        if SCAN["running"]:
            return False, "Сканирование уже идёт"
        SCAN["id"] += 1
        sid = SCAN["id"]
        SCAN.update(running=True, done=0, total=len(items), items=[])

    def one(ip):
        ms = ping_ip(ip, 0.6)
        with _SCAN_LOCK:
            if SCAN["id"] == sid:
                SCAN["items"].append([ip, ms])
                SCAN["done"] += 1

    def runner():
        try:
            with ThreadPoolExecutor(max_workers=min(300, len(items))) as ex:
                list(ex.map(one, items))
        finally:
            with _SCAN_LOCK:
                SCAN["running"] = False

    threading.Thread(target=runner, daemon=True).start()
    return True, "Запущено"


# ═════════════════════════════════════════════════════════════════════════════
#  ВЕБ-ИНТЕРФЕЙС (неоморфизм)
# ═════════════════════════════════════════════════════════════════════════════
INDEX_HTML = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProxyTool</title>
<style>
:root{
  color-scheme:light;
  --bg:#e4e9f0; --hi:#ffffff; --lo:#b9c1cf;
  --text:#2b3446; --sub:#566175; --acc:#3d6df5;
  --ok:#17825a; --err:#c0303f; --warn:#9a6a00; --skip:#6a7487; --head:#3d6df5; --c1:#3d6df5; --c2:#d9731a;
  --r:18px; --r-s:12px;
  --raise:7px 7px 15px var(--lo), -7px -7px 15px var(--hi);
  --raise-s:4px 4px 9px var(--lo), -4px -4px 9px var(--hi);
  --sink:inset 5px 5px 10px var(--lo), inset -5px -5px 10px var(--hi);
  --sink-s:inset 3px 3px 6px var(--lo), inset -3px -3px 6px var(--hi);
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  color-scheme:dark;
  --bg:#262b35; --hi:#323946; --lo:#1a1e26;
  --text:#e3e8f2; --sub:#9aa5ba; --acc:#6f95ff;
  --ok:#4fd39a; --err:#ff7b88; --warn:#f0c15a; --skip:#8d97ab; --head:#8aa8ff; --c1:#7fa2ff; --c2:#f2a45a;}}
:root[data-theme=dark]{
  color-scheme:dark;
  --bg:#262b35; --hi:#323946; --lo:#1a1e26;
  --text:#e3e8f2; --sub:#9aa5ba; --acc:#6f95ff;
  --ok:#4fd39a; --err:#ff7b88; --warn:#f0c15a; --skip:#8d97ab; --head:#8aa8ff; --c1:#7fa2ff; --c2:#f2a45a;}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{height:100%;margin:0;overflow:hidden}
body{background:var(--bg);color:var(--text);
  font:14px/1.45 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
:focus-visible{outline:2px solid var(--acc);outline-offset:3px}
*{scrollbar-width:thin;scrollbar-color:var(--lo) transparent}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:var(--lo);border-radius:99px;border:2px solid var(--bg)}
::-webkit-scrollbar-track{background:transparent}

/* ── одна страница: шапка + сетка на всю высоту ── */
.app{height:100vh;display:flex;flex-direction:column;padding:14px 18px 8px;gap:6px}
header{display:flex;align-items:center;gap:14px;flex:0 0 auto;padding:0 12px}
h1{margin:0;font-size:20px;font-weight:650;letter-spacing:.01em}
.sp{flex:1}
.pill{padding:5px 13px;border-radius:99px;box-shadow:var(--sink-s);color:var(--sub);font-size:12.5px;white-space:nowrap;transition:color .3s}
.pill.good{color:var(--ok)}.pill.bad{color:var(--err)}
.iconbtn{width:38px;height:38px;border:0;border-radius:50%;background:var(--bg);color:var(--text);
  box-shadow:var(--raise-s);cursor:pointer;font-size:16px;position:relative;overflow:hidden;
  transition:box-shadow .15s,transform .15s}
.iconbtn:active{box-shadow:var(--sink-s);transform:scale(.92)}
.iconbtn.spin{animation:spin .55s cubic-bezier(.3,1.2,.5,1)}
.iconbtn{display:grid;place-items:center}
#snd .x{display:none}#snd.muted .x{display:inline}#snd.muted .w{display:none}#snd.muted{color:var(--sub)}
.seg{position:relative;display:flex;padding:5px;border-radius:var(--r);box-shadow:var(--sink)}
.seg-thumb{position:absolute;top:5px;bottom:5px;left:0;width:0;border-radius:var(--r-s);background:var(--bg);pointer-events:none;
  box-shadow:var(--raise-s);transition:transform .4s cubic-bezier(.3,1.25,.5,1),width .4s cubic-bezier(.3,1.25,.5,1)}
.seg button{position:relative;z-index:1;overflow:hidden;border:0;background:none;color:var(--sub);padding:8px 20px;border-radius:var(--r-s);
  cursor:pointer;font:600 13.5px inherit;transition:color .25s;white-space:nowrap}
.seg button[aria-selected=true]{color:var(--acc)}

main{flex:1;min-height:0;display:grid;gap:0;
  grid-template-columns:minmax(290px,1fr) minmax(290px,1fr) minmax(340px,1.35fr)}
.tab{display:contents}
.col{display:flex;flex-direction:column;gap:18px;min-height:0;min-width:0;padding:12px;overflow:auto}

.card{background:var(--bg);border-radius:var(--r);box-shadow:var(--raise);padding:16px 18px;flex:0 0 auto}
.card.grow{flex:1 1 0;min-height:0;display:flex;flex-direction:column}
.card h2{margin:0 0 10px;font-size:14.5px;font-weight:650}
.hint{color:var(--sub);font-size:12.5px;margin:0 0 8px}
label,.lbl{display:block;color:var(--sub);font-size:12.5px;margin:10px 0 5px}
input[type=text],textarea{
  width:100%;border:0;background:var(--bg);color:var(--text);border-radius:var(--r-s);
  padding:9px 13px;font:13.5px Consolas,"Cascadia Mono",monospace;box-shadow:var(--sink-s)}
input::placeholder,textarea::placeholder{color:var(--sub);opacity:.7}
textarea{resize:none;min-height:80px}
.card.grow textarea{flex:1;min-height:70px}
.row{display:flex;gap:12px;align-items:flex-end}.row>*{flex:1;min-width:0}
.btns{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}

.btn{border:0;border-radius:var(--r-s);background:var(--bg);color:var(--text);cursor:pointer;
  padding:9px 16px;font:600 13.5px inherit;box-shadow:var(--raise-s);white-space:nowrap;position:relative;overflow:hidden;
  transition:box-shadow .15s,color .15s,transform .15s}
.btn:hover{color:var(--acc)}
.btn:active{box-shadow:var(--sink-s);transform:translateY(1px) scale(.975)}
.btn.main{color:var(--acc)}
.btn.danger{color:var(--err)}
.btn:disabled{opacity:.45;cursor:not-allowed;box-shadow:var(--sink-s);color:var(--sub)}
.btn.sm{padding:7px 13px}

/* ── свои числовые поля (вместо нативных стрелок) ── */
.num{display:flex;align-items:center;gap:8px}
.num input{flex:1;min-width:0;text-align:center;width:100%;border:0;background:var(--bg);color:var(--text);
  border-radius:var(--r-s);padding:9px 4px;font:13.5px Consolas,"Cascadia Mono",monospace;box-shadow:var(--sink-s)}
.step{flex:0 0 32px;height:32px;border:0;border-radius:50%;background:var(--bg);color:var(--acc);cursor:pointer;
  box-shadow:var(--raise-s);font:600 17px/1 inherit;display:grid;place-items:center;padding:0;position:relative;overflow:hidden;transition:box-shadow .12s,transform .12s}
.step:active{box-shadow:var(--sink-s);transform:scale(.9)}

/* ── свой выпадающий список (вместо нативного) ── */
.dd{position:relative}
.dd-btn{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;border:0;
  background:var(--bg);color:var(--text);border-radius:var(--r-s);padding:9px 13px;cursor:pointer;
  font:600 13.5px inherit;box-shadow:var(--raise-s);position:relative;overflow:hidden;transition:box-shadow .12s,transform .12s}
.dd-btn:active,.dd-btn[aria-expanded=true]{box-shadow:var(--sink-s)}
.dd-btn:active{transform:scale(.985)}
.dd-btn svg{width:14px;height:14px;color:var(--acc);transition:transform .3s cubic-bezier(.3,1.3,.5,1);flex:0 0 auto}
.dd-btn[aria-expanded=true] svg{transform:rotate(180deg)}
.dd-list{position:fixed;z-index:50;margin:0;padding:8px;list-style:none;background:var(--bg);
  border-radius:var(--r-s);box-shadow:var(--raise);max-height:260px;overflow:auto;
  transform-origin:top center;animation:ddIn .22s cubic-bezier(.2,.8,.2,1)}
.dd-list.out{animation:ddOut .13s ease-in forwards}
.dd-list li{position:relative;overflow:hidden;padding:8px 14px;border-radius:10px;cursor:pointer;font-size:13.5px;white-space:nowrap;
  transition:color .15s;animation:liIn .26s cubic-bezier(.2,.8,.2,1) both;animation-delay:calc(var(--i,0)*24ms + 40ms)}
.dd-list.out li{animation:none}
.dd-list li.act{color:var(--acc)}
.dd-list li[aria-selected=true]{color:var(--acc);font-weight:650;box-shadow:var(--sink-s)}

/* ── свой переключатель ── */
.sw{display:flex;align-items:center;gap:9px;margin:0;color:var(--sub);cursor:pointer;position:relative;white-space:nowrap;font-size:13px}
.sw input{position:absolute;opacity:0;width:100%;height:100%;margin:0;cursor:pointer}
.sw .trk{width:42px;height:24px;border-radius:99px;box-shadow:var(--sink-s);position:relative;flex:0 0 auto}
.sw .trk::after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;
  background:var(--bg);box-shadow:2px 2px 4px var(--lo),-2px -2px 4px var(--hi);transition:transform .2s,background .2s}
.sw input:checked+.trk::after{transform:translateX(18px);background:var(--acc)}
.sw input:focus-visible+.trk{outline:2px solid var(--acc);outline-offset:3px}

/* ── список адресов (прокручивается внутри) ── */
.list{flex:1;min-height:90px;overflow:auto;border-radius:var(--r-s);box-shadow:var(--sink);padding:8px;margin-top:12px;
  display:flex;flex-direction:column;gap:8px}
.li{display:flex;align-items:center;gap:10px;padding:7px 8px 7px 13px;border-radius:var(--r-s);background:var(--bg);
  box-shadow:var(--raise-s);flex:0 0 auto}
.li .addr{flex:1;min-width:0;font:13px Consolas,"Cascadia Mono",monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.li{cursor:pointer;user-select:none;transition:box-shadow .15s,color .15s}
.li .cnt{color:var(--sub);font-size:12px;white-space:nowrap}
.li .cnt b{color:var(--err);font-weight:600}

.bw{display:inline-flex;align-items:center;gap:8px}
.pxi{border:0;border-radius:99px;background:var(--bg);box-shadow:var(--sink-s);color:var(--sub);cursor:pointer;
  padding:5px 11px 5px 24px;font:600 12px inherit;white-space:nowrap;position:relative;overflow:hidden;transition:color .2s}
.pxi::before{content:"";position:absolute;left:10px;top:50%;width:8px;height:8px;margin-top:-4px;border-radius:50%;
  background:var(--skip);transition:background .2s,box-shadow .2s}
.pxi.on{color:var(--ok)}
.pxi.on::before{background:var(--ok);box-shadow:0 0 7px var(--ok)}

/* ── контекстное меню (ПКМ по интервалу) ── */
.ctx{position:fixed;z-index:80;min-width:260px;padding:8px;margin:0;list-style:none;background:var(--bg);
  border-radius:var(--r-s);box-shadow:var(--raise);animation:ddIn .16s cubic-bezier(.2,.8,.2,1)}
.ctx .it{position:relative;overflow:hidden;display:flex;align-items:center;gap:10px;padding:8px 14px;border-radius:10px;
  cursor:pointer;font-size:13.5px;white-space:nowrap;transition:color .15s}
.ctx .it:hover,.ctx .it:focus-visible{color:var(--acc);box-shadow:var(--sink-s);outline:0}
.ctx .it.danger{color:var(--err)}
.ctx .it .ck{width:16px;text-align:center;color:var(--acc);flex:0 0 auto}
.ctx .sep{height:1px;margin:6px 8px;background:var(--lo);opacity:.6}

/* ── окно редактирования интервала ── */
#modal,#skipModal{position:fixed;inset:0;z-index:90;display:grid;place-items:center;background:rgba(0,0,0,.28)}
#modal .card,#skipModal .card{width:min(440px,92vw);animation:pop .3s cubic-bezier(.3,1.4,.5,1)}
#skipModal .card{width:min(820px,94vw);max-height:86vh;display:flex;flex-direction:column;padding:0}
.skhead{flex:0 0 auto;padding:16px 18px 12px;border-bottom:1px solid color-mix(in srgb,var(--lo) 55%,transparent)}
.skhead h2{margin:0 0 4px}
.skhead .hint{margin:0 0 10px}
.skhead .btns{margin-top:10px}
.sklist{flex:1 1 auto;min-height:120px;overflow:auto;padding:12px 18px;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;align-content:start}
.sklist>.btn,.sklist>.empty{grid-column:1/-1;justify-self:center}
@media (max-width:640px){.sklist{grid-template-columns:repeat(2,minmax(0,1fr))}}
.skrow{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:6px 10px 6px 14px;border-radius:var(--r-s);
  box-shadow:var(--raise-s);min-width:0;cursor:pointer}
.skrow .ip{font:13px Consolas,"Cascadia Mono",monospace}
.skrow.on{box-shadow:var(--sink-s)}
.skrow.on .ip{color:var(--err);text-decoration:line-through}
.skrow .sw{flex:0 0 auto}
.skfoot{flex:0 0 auto;display:flex;align-items:center;gap:12px;padding:12px 18px 16px;border-top:1px solid color-mix(in srgb,var(--lo) 55%,transparent)}
.skfoot .hint{flex:1;margin:0}
#modal .err{min-height:18px;margin:8px 0 0;font-size:12.5px}
.li button{width:26px;height:26px;border:0;border-radius:50%;background:var(--bg);color:var(--err);
  box-shadow:var(--sink-s);cursor:pointer;line-height:1;font-size:12px;flex:0 0 auto;position:relative;overflow:hidden;transition:transform .12s}
.li button:active{transform:scale(.86)}
.empty{color:var(--sub);font-size:13px;margin:auto;text-align:center;padding:10px}

/* ── главный выключатель ── */
.power{width:min(170px,34vh);height:min(170px,34vh);border-radius:50%;border:0;background:var(--bg);cursor:pointer;
  box-shadow:var(--raise);display:grid;place-items:center;color:var(--sub);position:relative;
  transition:box-shadow .25s,color .25s,transform .15s}
.power:active{transform:scale(.97)}
.power::after{content:"";position:absolute;inset:-2px;border-radius:50%;border:2px solid var(--acc);opacity:0;pointer-events:none}
.power.ping::after{animation:ring .8s ease-out}
.power svg{width:42%;height:42%;transition:filter .3s,transform .35s cubic-bezier(.3,1.4,.5,1)}
.power:active,.power[aria-pressed=true]{box-shadow:var(--sink)}
.power[aria-pressed=true]{color:var(--acc)}
.power[aria-pressed=true] svg{filter:drop-shadow(0 0 8px var(--acc));transform:scale(1.07)}
.power-info b.swap{animation:swapIn .35s cubic-bezier(.2,.8,.2,1)}
.power-info b{display:block;font-size:20px;font-weight:650}
.power-info span{color:var(--sub);font-size:13px;word-break:break-all}

.track{height:11px;border-radius:99px;box-shadow:var(--sink-s);overflow:hidden;margin-top:9px}
.track i{display:block;height:100%;width:0;border-radius:99px;background:var(--acc);transition:width .3s}
.kv{font:12.5px Consolas,"Cascadia Mono",monospace;color:var(--sub);white-space:pre-line}

/* ── журнал: «утопленный экран», прокручивается внутри ── */
.logcard{flex:1 1 0;min-height:0;display:flex;flex-direction:column}
.logbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.logbar h2{margin:0}
.logbar input[type=text]{flex:1 1 90px;min-width:90px;max-width:170px;padding:7px 12px}
.logbar .dd{flex:0 0 138px}
.logbar .dd-btn{padding:7px 12px}
#log{flex:1;min-height:0;overflow:auto;border-radius:var(--r);box-shadow:var(--sink);padding:14px;
  font:12.5px/1.55 Consolas,"Cascadia Mono",monospace;white-space:pre-wrap;word-break:break-all}
#log div{padding:1px 0}
.ok{color:var(--ok)}.err{color:var(--err)}.warn,.info{color:var(--warn)}.skip{color:var(--skip)}
.head{color:var(--head);font-weight:600;margin-top:7px}
.t{color:var(--sub);margin-right:10px;opacity:.8}
.hide{display:none!important}

#toast{position:fixed;left:50%;bottom:26px;transform:translate(-50%,24px);opacity:0;pointer-events:none;
  background:var(--bg);color:var(--err);padding:12px 22px;border-radius:var(--r-s);box-shadow:var(--raise);
  transition:opacity .25s,transform .25s;z-index:99;max-width:90vw}
#toast.show{opacity:1;transform:translate(-50%,0)}

/* ── анимации ── */
.tab:not(.hide) .col{animation:tabIn .5s cubic-bezier(.2,.8,.2,1) backwards}
.tab:not(.hide) .col:nth-child(2){animation-delay:.08s}
.li.pop{animation:pop .4s cubic-bezier(.3,1.4,.5,1)}
.li.out{animation:liOut .2s ease-in forwards}
.card.flash{animation:flash .9s ease-out}
.rip{position:absolute;border-radius:50%;pointer-events:none;transform:scale(0);opacity:.7;
  background:radial-gradient(circle,color-mix(in srgb,var(--acc) 40%,transparent) 0,color-mix(in srgb,var(--acc) 14%,transparent) 55%,transparent 70%);
  animation:rip .6s cubic-bezier(.2,.7,.3,1) forwards}
@keyframes rip{to{transform:scale(1);opacity:0}}
@keyframes tabIn{from{opacity:0;transform:translateY(16px) scale(.985)}to{opacity:1;transform:none}}
@keyframes ddIn{from{opacity:0;transform:translateY(-6px) scale(.95)}to{opacity:1;transform:none}}
@keyframes ddOut{to{opacity:0;transform:translateY(-4px) scale(.96)}}
@keyframes liIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
@keyframes swapIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes pop{0%{opacity:0;transform:scale(.88) translateY(8px)}60%{opacity:1;transform:scale(1.025)}100%{transform:none}}
@keyframes liOut{to{opacity:0;transform:translateX(18px) scale(.94)}}
@keyframes ring{from{opacity:.6;transform:scale(1)}to{opacity:0;transform:scale(1.5)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes flash{0%{box-shadow:var(--raise),0 0 0 0 color-mix(in srgb,var(--acc) 45%,transparent)}
  45%{box-shadow:var(--raise),0 0 0 7px color-mix(in srgb,var(--acc) 28%,transparent)}
  100%{box-shadow:var(--raise),0 0 0 14px transparent}}

/* узкие/низкие окна: разрешаем обычную прокрутку страницы, чтобы ничего не обрезалось */
/* ══ панель «Локальный прокси»: питание + параметры + итоги, график, журнал ══ */
.col.wide{grid-column:1/-1}
.dash{gap:14px;overflow:hidden}
.toprow{display:grid;grid-template-columns:minmax(210px,250px) minmax(260px,1fr) minmax(330px,1.3fr);gap:18px;align-items:stretch;flex:0 0 auto}
.powerbox{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;text-align:center;padding:6px 4px}
.params h2,.totals h2{margin-bottom:6px}
.params textarea{min-height:58px;height:58px}
.params .btns{margin-top:10px}
.tot{width:100%;border-collapse:collapse}
.tot th{color:var(--sub);font-weight:600;font-size:12px;text-align:right;padding:2px 6px}
.tot td{text-align:right;padding:3px 6px;font:600 13.5px Consolas,"Cascadia Mono",monospace}
.tot td:first-child,.tot th:first-child{text-align:left;font:600 12.5px "Segoe UI",system-ui,sans-serif}
.resets{margin-top:8px;font-size:12.5px;color:var(--sub);line-height:1.5}
.resets div{display:flex;gap:8px;align-items:baseline}
.resets i{flex:0 0 9px;height:9px;border-radius:50%;transform:translateY(0)}
.chartcard{flex:1 1 0;min-height:150px;display:flex;flex-direction:column}
.charthead{display:flex;align-items:center;gap:16px;margin-bottom:6px;flex-wrap:wrap}
.charthead h2{margin:0}
.charthead .dd{flex:0 0 130px}
.charthead .dd-btn{padding:6px 12px}
.legend{display:flex;gap:16px;font-size:12.5px;color:var(--sub)}
.legend i{display:inline-block;width:18px;height:3px;border-radius:2px;vertical-align:middle;margin-right:6px}
#chart{position:relative;flex:1;min-height:0}
#chart svg{width:100%;height:100%;display:block}
.ctip{position:absolute;pointer-events:none;background:var(--bg);box-shadow:var(--raise-s);border-radius:var(--r-s);
  padding:6px 11px;font-size:12.5px;white-space:nowrap;z-index:3;transform:translate(-50%,-125%);line-height:1.45}
.ctip b{font-weight:650}
svg .gl{stroke:var(--lo);stroke-width:1;opacity:.6}
svg .tx{fill:var(--sub);font:11px "Segoe UI",system-ui,sans-serif}
svg .ln{fill:none;stroke-width:2.4;stroke-linejoin:round;stroke-linecap:round}
svg .l1{stroke:var(--c1)}svg .l2{stroke:var(--c2)}svg .l3{stroke:var(--err)}svg .ln.l3{stroke-dasharray:5 4}
svg .dot{stroke:var(--bg);stroke-width:1.5}
svg .dot.l1{fill:var(--c1)}svg .dot.l2{fill:var(--c2)}svg .dot.l3{fill:var(--err)}
.ck1{background:var(--c1)}.ck2{background:var(--c2)}.ck3{background:var(--err)}
#pcModal .card{width:min(860px,94vw);max-height:86vh;display:flex;flex-direction:column;padding:0;animation:pop .3s cubic-bezier(.3,1.4,.5,1)}
#pcModal .hstruct{margin:12px 18px;min-height:140px}
#pcModal .skhead input{width:100%}
.pcrow.off{opacity:.45;cursor:not-allowed}
.pcrow .nm{display:flex;align-items:center;gap:9px;min-width:0}
.resets .sub{display:block;font-size:11.5px;opacity:.85}

/* ── список событий (общий для панели и окон истории) ── */
.evcard{flex:1 1 0;display:flex;flex-direction:column;min-height:0}
.evcard .logbar input[type=text]{max-width:320px;flex:1 1 160px}
.evcard .logbar .dd{flex:0 0 168px}
.evl{flex:1;min-height:0;overflow:auto;border-radius:var(--r);box-shadow:var(--sink);padding:10px;display:flex;flex-direction:column;gap:7px}
.ev{display:grid;grid-template-columns:112px 58px minmax(90px,150px) 112px 128px minmax(0,1fr);gap:10px;align-items:center;
  padding:7px 12px;border-radius:var(--r-s);background:var(--bg);box-shadow:var(--raise-s);cursor:pointer;font-size:12.5px;flex:0 0 auto;
  transition:box-shadow .15s}
.ev:hover,.ev:focus-visible{box-shadow:var(--sink-s)}
.ev .et{font:12px Consolas,"Cascadia Mono",monospace;color:var(--sub)}
.ev .host{font:12.5px Consolas,"Cascadia Mono",monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .sum{font:12px Consolas,"Cascadia Mono",monospace;color:var(--sub);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip{display:inline-block;padding:2px 9px;border-radius:99px;box-shadow:var(--sink-s);font-size:11.5px;font-weight:600;
  text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;justify-self:start}
.chip.st-ok{color:var(--ok)}.chip.st-err{color:var(--err)}.chip.st-skip{color:var(--skip)}.chip.st-ext{color:var(--warn)}
.chip.k-proxy{color:var(--c1)}.chip.k-hosts{color:var(--c2)}
.chip.who-system{color:var(--warn)}
.ev.blink{animation:blink 1.2s ease-in-out infinite}
@keyframes blink{0%,100%{box-shadow:var(--raise-s),0 0 0 0 transparent}
  50%{box-shadow:var(--raise-s),0 0 0 3px color-mix(in srgb,var(--warn) 60%,transparent);background:color-mix(in srgb,var(--warn) 10%,var(--bg))}}
.evl .more{align-self:center;flex:0 0 auto}

/* ── окно «подробно о событии» и окно истории ── */
#evModal,#histModal,#watchModal,#pcModal{position:fixed;inset:0;z-index:90;display:grid;place-items:center;background:rgba(0,0,0,.28)}
#evModal{z-index:95}
#evModal .card{width:min(780px,94vw);max-height:88vh;overflow:auto;animation:pop .3s cubic-bezier(.3,1.4,.5,1)}
.kvgrid{display:grid;grid-template-columns:150px minmax(0,1fr);gap:7px 14px;font-size:13px;margin:8px 0 0}
.kvgrid dt{color:var(--sub)}
.kvgrid dd{margin:0;word-break:break-word}
.dff{margin-top:6px;border-radius:var(--r-s);box-shadow:var(--sink-s);padding:8px 12px;max-height:200px;overflow:auto}
.dff div{font:12px/1.55 Consolas,"Cascadia Mono",monospace;white-space:pre-wrap;word-break:break-all}
.dff .add{color:var(--ok)}.dff .del{color:var(--err)}
.cmp{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
.cmp h3{margin:0 0 6px;font-size:12.5px;color:var(--sub);font-weight:600}
.cmp pre{margin:0;max-height:240px;overflow:auto;white-space:pre-wrap;word-break:break-all;font:12px/1.5 Consolas,"Cascadia Mono",monospace;
  padding:10px 12px;border-radius:var(--r-s);box-shadow:var(--sink-s)}
#histModal .card{width:min(1180px,96vw);height:min(84vh,780px);display:flex;flex-direction:column;padding:0;animation:pop .3s cubic-bezier(.3,1.4,.5,1)}
.histbody{flex:1;min-height:0;padding:14px 18px 6px;display:flex;flex-direction:column}
.histbody>div{flex:1;min-height:0;display:flex;flex-direction:column}
#watchModal .card{width:min(860px,94vw);max-height:88vh;display:flex;flex-direction:column;padding:0;animation:pop .3s cubic-bezier(.3,1.4,.5,1)}
#watchModal .skhead .row{margin-bottom:8px}
#watchModal .skhead .dd{flex:0 0 170px}
#watchModal .skhead input[type=text]{flex:1}
.wrow .nm{display:flex;align-items:center;gap:9px;min-width:0}
.wrow .ip{font:13px Consolas,"Cascadia Mono",monospace}
.wrow .ms{color:var(--sub);font-size:11.5px;white-space:nowrap}
.wdot{flex:0 0 9px;height:9px;border-radius:50%;background:var(--skip)}
.wdot.on{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.wdot.bad{background:var(--err)}
.wrow.w-on{box-shadow:var(--sink-s)}
.bdg2{display:inline-block;min-width:20px;margin-left:8px;padding:0 7px;border-radius:99px;background:var(--ok);color:var(--bg);font-size:11.5px;font-weight:700;line-height:19px;text-align:center}
.bdg{display:inline-block;min-width:18px;margin-left:8px;padding:0 6px;border-radius:99px;background:var(--err);color:#fff;
  font-size:11px;line-height:18px;text-align:center;animation:blink2 1.2s ease-in-out infinite}
@keyframes blink2{50%{opacity:.45}}

/* ── вкладка hosts ── */
.tab-hosts-edit{flex:1;min-height:120px;margin-top:8px;white-space:pre;overflow:auto;tab-size:4;line-height:1.55;font-size:13px}
.pillrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 8px}
.pillrow .pill{font-size:12px;padding:3px 11px}
.pill.warn{color:var(--warn)}
.hstruct{flex:1;min-height:120px;overflow:auto;border-radius:var(--r-s);box-shadow:var(--sink);padding:8px;display:flex;flex-direction:column;gap:3px;margin-top:8px}
.hr{display:grid;grid-template-columns:38px 132px minmax(0,1fr);gap:8px;padding:4px 10px;border-radius:10px;font:12.5px Consolas,"Cascadia Mono",monospace;
  cursor:pointer;align-items:baseline;flex:0 0 auto}
.hr:hover{box-shadow:var(--sink-s)}
.hr .n{color:var(--sub);opacity:.7}
.hr .ip{color:var(--acc)}
.hr .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hr .cm{color:var(--sub)}
.hr.c .cm{grid-column:2/-1}
.hr.bad .ip{color:var(--err)}
.hint.bad{color:var(--err)}
.tgl{display:flex;flex-direction:column;gap:6px;max-height:150px;overflow:auto;margin-top:6px}
.tgl div{display:flex;justify-content:space-between;gap:10px;font:12.5px Consolas,"Cascadia Mono",monospace}
.tgl span:last-child{color:var(--sub)}

@media (max-width:1100px){
  .ev{grid-template-columns:100px 54px minmax(0,1fr) 100px}
  .ev .who,.ev .sum{display:none}
  .cmp{grid-template-columns:1fr}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
</style></head><body>
<div class="app">
<header>
  <h1>ProxyTool</h1>
  <span class="pill" id="admin">…</span>
  <span class="pill" id="jobb">Свободен</span>
  <span class="sp"></span>
  <div class="seg" id="seg" role="tablist"><span class="seg-thumb" id="segThumb"></span>
    <button role="tab" data-t="proxy" aria-selected="true">Исключения прокси</button>
    <button role="tab" data-t="hosts" aria-selected="false">Файл hosts</button>
    <button role="tab" data-t="local" aria-selected="false">Дашборд<span class="bdg" id="bdg" hidden>0</span></button>
  </div>
  <span class="sp"></span>
  <span class="pill">порт 1805</span>
  <button class="iconbtn" id="snd" title="Звуки" aria-label="Звуки включены" aria-pressed="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5 6 9H3v6h3l5 4z"/><path class="w" d="M15.5 9a4 4 0 0 1 0 6M18.5 6.5a8 8 0 0 1 0 11"/><path class="x" d="M16 9l5 6M21 9l-5 6"/></svg></button>
  <button class="iconbtn" id="theme" title="Сменить тему" aria-label="Сменить тему">◐</button>
</header>

<main>
  <!-- ─────────── вкладка: исключения прокси ─────────── -->
  <section id="tab-proxy" class="tab">
    <div class="col">
      <div class="card grow">
        <h2>Адреса</h2>
        <div class="row">
          <div><label for="ip_from" style="margin-top:0">Начальный IP</label><input type="text" id="ip_from" placeholder="10.145.37.1" autocomplete="off"></div>
          <div><label for="ip_to" style="margin-top:0">Конечный IP</label><input type="text" id="ip_to" placeholder="10.145.37.254" autocomplete="off"></div>
        </div>
        <div class="btns">
          <button class="btn main" id="addRange">Добавить диапазон</button>
          <button class="btn" id="addLocal">Этот компьютер</button>
        </div>
        <div class="list" id="chips" aria-live="polite"></div>
        <div class="row" style="margin-top:12px">
          <div><span class="lbl" style="margin-top:0">Потоков</span>
            <div class="num" data-min="1" data-max="200"><button class="step" data-d="-1" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="workers" aria-label="Потоков"><button class="step" data-d="1" aria-label="Больше">+</button></div></div>
          <div><span class="lbl" style="margin-top:0">Таймаут, с</span>
            <div class="num" data-min="1" data-max="120"><button class="step" data-d="-1" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="timeout" aria-label="Таймаут"><button class="step" data-d="1" aria-label="Больше">+</button></div></div>
        </div>
        <p class="hint" id="tcount" style="margin:10px 0 0"></p>
      </div>
    </div>

    <div class="col">
      <div class="card grow">
        <h2>Исключения (ProxyOverride)</h2>
        <label for="entries" style="margin-top:0">Записи через «;» или с новой строки</label>
        <textarea id="entries" placeholder="*.local; 10.145.*; &lt;local&gt;"></textarea>
        <div class="btns">
          <span class="bw"><button class="btn main" id="b_add" title="Правая кнопка — включать ли прокси">Добавить</button><button type="button" class="pxi" id="i_add" title="Нажмите, чтобы переключить"></button></span>
          <button class="btn danger" id="b_rm">Удалить</button>
          <button class="btn" id="b_rd">Прочитать текущие</button>
        </div>
        <div class="btns" style="margin-top:8px">
          <button class="btn sm" id="p_hist">История изменений</button>
          <button class="btn sm" id="p_watch">Наблюдение за ПК<span class="bdg2" id="wcnt" hidden>0</span></button>
        </div>
      </div>
      <div class="card">
        <h2>Автообновление</h2>
        <p class="hint">Записи добавляются заново через заданный интервал.</p>
        <div class="row">
          <div><span class="lbl" style="margin-top:0">Каждые</span>
            <div class="num" data-min="1" data-max="999"><button class="step" data-d="-1" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="a_every" aria-label="Интервал"><button class="step" data-d="1" aria-label="Больше">+</button></div></div>
          <div><span class="lbl" style="margin-top:0">Единица</span>
            <div class="dd" id="a_unit">
              <button class="dd-btn" type="button" aria-haspopup="listbox" aria-expanded="false"><span class="dd-label">часов</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></button>
              <ul class="dd-list" role="listbox" hidden><li role="option" data-v="soat">часов</li><li role="option" data-v="daqiqa">минут</li></ul>
            </div></div>
        </div>
        <div class="btns">
          <span class="bw"><button class="btn main" id="a_start" title="Правая кнопка — включать ли прокси">Запустить</button><button type="button" class="pxi" id="i_auto" title="Нажмите, чтобы переключить"></button></span>
          <button class="btn danger" id="a_stop" disabled>Остановить</button>
        </div>
        <div class="kv" id="a_state" style="margin-top:10px">Остановлено</div>
      </div>
    </div>
  </section>

  <!-- ─────────── вкладка: локальный прокси ─────────── -->
  <section id="tab-local" class="tab hide">
    <div class="col wide dash">
      <div class="toprow">
        <div class="powerbox">
          <button class="power" id="power" aria-pressed="false" aria-label="Включить или выключить прокси">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/></svg>
          </button>
          <div class="power-info"><b id="lp_state">…</b><span id="lp_view"></span></div>
        </div>
        <div class="card params">
          <h2>Параметры</h2>
          <label for="lp_server" style="margin-top:0">Сервер прокси (хост:порт)</label>
          <input type="text" id="lp_server" placeholder="proxy.example.local:8080" autocomplete="off">
          <label for="lp_override">Исключения</label>
          <textarea id="lp_override"></textarea>
          <div class="btns">
            <button class="btn main sm" id="lp_save">Сохранить</button>
            <button class="btn sm" id="lp_reload">Обновить</button>
          </div>
        </div>
        <div class="card totals">
          <h2>Итоги и анализатор этого ПК</h2>
          <table class="tot" aria-label="Итоги по дням">
            <thead><tr><th></th><th>Сегодня</th><th>Вчера</th><th>Месяц</th></tr></thead>
            <tbody id="tot_b"></tbody>
          </table>
          <div class="resets" id="resets"></div>
        </div>
      </div>
      <div class="card evcard" id="dash_log"></div>
    </div>
  </section>

  <!-- ─────────── вкладка: файл hosts ─────────── -->
  <section id="tab-hosts" class="tab hide">
    <div class="col">
      <div class="card grow">
        <h2>Структура файла hosts</h2>
        <p class="hint" id="h_meta" style="margin-bottom:4px">…</p>
        <div class="pillrow"><span class="pill warn" id="h_dirty" hidden>Есть несохранённые правки</span><span class="pill warn" id="h_ext" hidden>Файл изменён снаружи — нажмите «Загрузить с ПК»</span></div>
        <p class="hint" id="h_sum" style="margin:0"></p>
        <div class="row" style="align-items:center;margin-top:8px;flex:0 0 auto">
          <label class="sw" style="margin:0"><input type="checkbox" id="h_com"><span class="trk"></span>Комментарии</label>
          <label class="sw" style="margin:0"><input type="checkbox" id="h_editsw"><span class="trk"></span>Редактировать</label>
        </div>
        <div class="hstruct" id="h_struct"></div>
        <textarea id="h_edit" class="tab-hosts-edit" wrap="off" spellcheck="false" aria-label="Содержимое файла hosts" hidden></textarea>
      </div>
    </div>
    <div class="col">
      <div class="card grow">
        <h2>Адреса для hosts</h2>
        <div class="row">
          <div><label for="hip_from" style="margin-top:0">Начальный IP</label><input type="text" id="hip_from" placeholder="10.145.37.1" autocomplete="off"></div>
          <div><label for="hip_to" style="margin-top:0">Конечный IP</label><input type="text" id="hip_to" placeholder="10.145.37.254" autocomplete="off"></div>
        </div>
        <div class="btns">
          <button class="btn main" id="h_addRange">Добавить диапазон</button>
          <button class="btn" id="h_addLocal">Этот компьютер</button>
        </div>
        <div class="list" id="h_chips" aria-live="polite"></div>
        <div class="row" style="margin-top:12px">
          <div><span class="lbl" style="margin-top:0">Потоков</span>
            <div class="num" data-min="1" data-max="200"><button class="step" data-d="-1" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="h_workers" aria-label="Потоков"><button class="step" data-d="1" aria-label="Больше">+</button></div></div>
          <div><span class="lbl" style="margin-top:0">Таймаут, с</span>
            <div class="num" data-min="1" data-max="120"><button class="step" data-d="-1" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="h_timeout" aria-label="Таймаут"><button class="step" data-d="1" aria-label="Больше">+</button></div></div>
        </div>
        <p class="hint" id="h_tcount" style="margin:10px 0 0"></p>
        <div class="btns">
          <button class="btn main" id="h_apply" title="Записать этот текст в hosts на всех IP из списка (у кого уже так же или кто не ответил — пропускается)">Применить ко всем IP</button>
          <button class="btn" id="h_local" title="Записать только в hosts этого компьютера">Только этот ПК</button>
          <button class="btn" id="h_reload">Загрузить с ПК</button>
        </div>
      </div>
    </div>
  </section>

  <!-- ─────────── общая колонка: задача + журнал ─────────── -->
  <div class="col" id="common">
    <div class="card">
      <h2 style="margin-bottom:6px">Текущая задача</h2>
      <div class="kv" id="jobtxt">Нет активных задач</div>
      <div class="track"><i id="jobbar"></i></div>
      <div class="btns"><button class="btn danger" id="j_stop" disabled>Стоп (прервать всё)</button></div>
    </div>
    <div class="card logcard">
      <div class="logbar">
        <h2>Журнал</h2>
        <input type="text" id="filter" placeholder="Поиск" aria-label="Поиск по журналу">
        <div class="dd" id="lvl">
          <button class="dd-btn" type="button" aria-haspopup="listbox" aria-expanded="false"><span class="dd-label">Все</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></button>
          <ul class="dd-list" role="listbox" hidden>
            <li role="option" data-v="">Все</li><li role="option" data-v="ok">Успешно</li><li role="option" data-v="err">Ошибки</li>
            <li role="option" data-v="skip">Без изменений</li><li role="option" data-v="head">Заголовки</li>
          </ul>
        </div>
        <label class="sw"><input type="checkbox" id="follow" checked><span class="trk"></span>Следить</label>
        <span class="sp"></span>
        <button class="btn sm" id="dl">Сохранить</button>
        <button class="btn sm danger" id="clr">Очистить</button>
      </div>
      <div id="log" role="log" aria-live="off"></div>
    </div>
  </div>
</main>
</div>
<div id="modal" hidden>
  <div class="card" role="dialog" aria-modal="true" aria-labelledby="m_title">
    <h2 id="m_title">Изменить интервал</h2>
    <div class="row">
      <div><label for="m_from" style="margin-top:0">Начальный IP / адрес</label><input type="text" id="m_from" autocomplete="off"></div>
      <div><label for="m_to" style="margin-top:0">Конечный IP</label><input type="text" id="m_to" autocomplete="off"></div>
    </div>
    <p class="err" id="m_err"></p>
    <div class="btns"><button class="btn main" id="m_ok">Сохранить</button><button class="btn" id="m_cancel">Отмена</button></div>
  </div>
</div>
<div id="skipModal" hidden>
  <div class="card" role="dialog" aria-modal="true" aria-labelledby="k_title">
    <div class="skhead">
      <h2 id="k_title">IP интервала</h2>
      <p class="hint">Отмеченные адреса будут пропущены: ни добавление, ни автообновление к ним не обращается.</p>
      <input type="text" id="k_q" placeholder="Поиск по IP" aria-label="Поиск по IP" autocomplete="off">
      <div class="btns">
        <button class="btn sm danger" id="k_skip">Пропускать найденные</button>
        <button class="btn sm" id="k_unskip">Не пропускать найденные</button>
      </div>
    </div>
    <div class="sklist" id="k_list"></div>
    <div class="skfoot"><p class="hint" id="k_info"></p><button class="btn main" id="k_done">Готово</button></div>
  </div>
</div>
<div id="evModal" hidden>
  <div class="card" role="dialog" aria-modal="true" aria-labelledby="e_title">
    <h2 id="e_title">Событие</h2>
    <dl class="kvgrid" id="e_kv"></dl>
    <div id="e_diffw" hidden><span class="lbl">Что изменилось</span><div class="dff" id="e_diff"></div></div>
    <div class="cmp" id="e_cmp"><div><h3>Было</h3><pre id="e_old"></pre></div><div><h3>Стало</h3><pre id="e_new"></pre></div></div>
    <div class="btns"><button class="btn main" id="e_close">Закрыть</button></div>
  </div>
</div>
<div id="histModal" hidden>
  <div class="card" role="dialog" aria-modal="true" aria-labelledby="hs_title">
    <div class="skhead"><h2 id="hs_title">История</h2>
      <p class="hint" style="margin:0">Кто, когда и из какого состояния в какое изменил. Нажмите на запись, чтобы увидеть подробности.</p></div>
    <div class="histbody"><div id="hist_proxy"></div><div id="hist_hosts" hidden></div></div>
    <div class="skfoot"><span class="hint"></span><button class="btn main" id="hs_close">Закрыть</button></div>
  </div>
</div>
<div id="watchModal" hidden>
  <div class="card" role="dialog" aria-modal="true" aria-labelledby="w_title">
    <div class="skhead">
      <h2 id="w_title">Наблюдение за компьютерами</h2>
      <p class="hint">Все IP из интервалов проверяются ping-ом сразу. Включённые ПК проверяются по расписанию, любое изменение попадает в историю.</p>
      <div class="row">
        <div><span class="lbl" style="margin-top:0">Удалённые ПК, раз в (сек)</span>
          <div class="num" data-min="10" data-max="86400"><button class="step" data-d="-10" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="w_every" aria-label="Период проверки удалённых"><button class="step" data-d="10" aria-label="Больше">+</button></div></div>
        <div><span class="lbl" style="margin-top:0">Этот ПК, раз в (сек)</span>
          <div class="num" data-min="2" data-max="3600"><button class="step" data-d="-1" aria-label="Меньше">−</button><input type="text" inputmode="numeric" id="w_local" aria-label="Период проверки этого ПК"><button class="step" data-d="1" aria-label="Больше">+</button></div></div>
      </div>
      <div class="row" style="align-items:center">
        <input type="text" id="w_q" placeholder="Поиск по IP" aria-label="Поиск по IP" autocomplete="off">
        <div class="dd" id="w_flt">
          <button class="dd-btn" type="button" aria-haspopup="listbox" aria-expanded="false"><span class="dd-label">Все</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></button>
          <ul class="dd-list" role="listbox" hidden><li role="option" data-v="">Все</li><li role="option" data-v="on">Онлайн</li><li role="option" data-v="off">Не отвечают</li><li role="option" data-v="watch">Под наблюдением</li></ul>
        </div>
      </div>
      <div class="btns">
        <button class="btn sm main" id="w_scan">Проверить ping заново</button>
        <button class="btn sm" id="w_on">Включить найденных онлайн</button>
        <button class="btn sm danger" id="w_off">Выключить найденных</button>
      </div>
    </div>
    <div class="sklist" id="w_list"></div>
    <div class="skfoot"><p class="hint" id="w_info"></p><button class="btn main" id="w_done">Готово</button></div>
  </div>
</div>
<div id="pcModal" hidden>
  <div class="card" role="dialog" aria-modal="true" aria-labelledby="pc_title">
    <div class="skhead"><h2 id="pc_title">Откуда загрузить hosts</h2><p class="hint" id="pc_info"></p>
      <input type="text" id="pc_q" placeholder="Поиск по IP" aria-label="Поиск по IP" autocomplete="off"></div>
    <div class="sklist" id="pc_pick"></div>
    <div class="hstruct" id="pc_list" hidden></div>
    <div class="skfoot"><p class="hint" id="pc_foot"></p>
      <button class="btn" id="pc_rescan">Проверить ping заново</button>
      <button class="btn" id="pc_back" hidden>Назад</button>
      <button class="btn main" id="pc_replace" hidden title="Весь текст в окне заменится этим файлом">Заменить</button>
      <button class="btn" id="pc_add" hidden title="Недостающие записи допишутся в конец">Добавить</button>
      <button class="btn" id="pc_cancel">Отмена</button></div>
  </div>
</div>
<div id="toast" role="alert"></div>

<script>
const $=id=>document.getElementById(id);
const H={'X-Requested-With':'ProxyTool','Content-Type':'application/json'};
const api=(u,b)=>fetch(u,b===undefined?{headers:H}:{method:'POST',headers:H,body:JSON.stringify(b)}).then(r=>r.json());
let S={targets:[],skips:[],add_proxy:'1',auto_proxy:'1',entries:'',workers:'50',timeout:'5',auto_every:'1',auto_unit:'soat',lp_server:'',lp_override:'',theme:'',sound:'1',watch_proxy:[],watch_hosts:[],watch_every:'60',mon_every:'2',hosts_targets:[],h_workers:'50',h_timeout:'5'};
let lastId=0, all=[], lpOn=0, toastT, curTab='proxy';

function toast(m){snd('err');const t=$('toast');t.textContent=m;t.classList.add('show');clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove('show'),4500)}

/* ── тема ── */
function applyTheme(v){if(v==='light'||v==='dark')document.documentElement.dataset.theme=v;else delete document.documentElement.dataset.theme}
$('theme').onclick=()=>{const tb=$('theme');tb.classList.remove('spin');void tb.offsetWidth;tb.classList.add('spin');const dark=(document.documentElement.dataset.theme||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'))==='dark';
  S.theme=dark?'light':'dark';applyTheme(S.theme);save()};

/* ── звуки (Web Audio: синтезируются в браузере, файлов нет) ── */
let AC=null;
function ac(){if(S.sound==='0')return null;
  try{AC=AC||new (window.AudioContext||window.webkitAudioContext)();if(AC.state==='suspended')AC.resume()}catch(e){return null}return AC}
function tone(f,t0,d,o={}){const c=ac();if(!c)return;
  const osc=c.createOscillator(),g=c.createGain(),n=c.currentTime+t0,v=o.v||.05;
  osc.type=o.type||'sine';osc.frequency.setValueAtTime(f,n);if(o.to)osc.frequency.exponentialRampToValueAtTime(o.to,n+d);
  g.gain.setValueAtTime(.0001,n);g.gain.exponentialRampToValueAtTime(v,n+.008);g.gain.exponentialRampToValueAtTime(.0001,n+d);
  osc.connect(g);g.connect(c.destination);osc.start(n);osc.stop(n+d+.03)}
const SND={
  click:()=>tone(900,0,.05,{v:.03,to:620}),
  tab:()=>{tone(520,0,.07,{v:.04});tone(780,.05,.1,{v:.035})},
  pick:()=>tone(880,0,.07,{v:.035}),
  add:()=>{tone(660,0,.07,{v:.04});tone(990,.06,.1,{v:.035})},
  del:()=>tone(520,0,.11,{v:.04,to:300}),
  ok:()=>{tone(659,0,.12,{v:.05});tone(988,.1,.22,{v:.045})},
  err:()=>{tone(260,0,.14,{type:'triangle',v:.06});tone(190,.12,.24,{type:'triangle',v:.06})},
  on:()=>{tone(440,0,.12,{v:.06});tone(660,.09,.12,{v:.055});tone(880,.18,.28,{v:.05})},
  off:()=>{tone(880,0,.1,{v:.055});tone(660,.08,.1,{v:.05});tone(440,.16,.28,{v:.05})}};
const snd=n=>{try{SND[n]()}catch(e){}};
function paintSound(){const on=S.sound!=='0',b=$('snd');b.classList.toggle('muted',!on);
  b.setAttribute('aria-pressed',on);b.setAttribute('aria-label',on?'Звуки включены':'Звуки выключены');b.title=on?'Звуки включены':'Звуки выключены'}
$('snd').onclick=()=>{S.sound=S.sound==='0'?'1':'0';paintSound();save();if(S.sound!=='0')snd('ok')};

/* ── сохранение в AppData ── */
let saveT;
function save(){clearTimeout(saveT);saveT=setTimeout(()=>api('/api/settings',S).then(r=>{if(!r.ok)toast('Не удалось сохранить настройки в AppData')}),400)}
const bind=(id,key)=>$(id).addEventListener('input',()=>{S[key]=$(id).value;save()});
bind('entries','entries');bind('workers','workers');bind('timeout','timeout');bind('a_every','auto_every');
bind('lp_server','lp_server');bind('lp_override','lp_override');

/* ── числовые поля со своими кнопками ── */
document.querySelectorAll('.num').forEach(n=>{
  const inp=n.querySelector('input'),min=+n.dataset.min,max=+n.dataset.max;
  const clamp=()=>{let v=parseInt(inp.value,10);if(isNaN(v))v=min;return Math.min(max,Math.max(min,v))};
  const fire=()=>inp.dispatchEvent(new Event('input',{bubbles:true}));
  n.querySelectorAll('.step').forEach(b=>b.onclick=()=>{inp.value=Math.min(max,Math.max(min,clamp()+ +b.dataset.d));fire()});
  inp.addEventListener('input',()=>{const c=inp.value.replace(/\D/g,'');if(c!==inp.value)inp.value=c});
  inp.addEventListener('blur',()=>{inp.value=clamp();fire()});
  inp.addEventListener('keydown',e=>{if(e.key==='ArrowUp'||e.key==='ArrowDown'){e.preventDefault();inp.value=Math.min(max,Math.max(min,clamp()+(e.key==='ArrowUp'?1:-1)));fire()}});
});

/* ── свои выпадающие списки ── */
function makeDD(id,onchange){
  const root=$(id),btn=root.querySelector('.dd-btn'),list=root.querySelector('.dd-list'),label=root.querySelector('.dd-label');
  const items=[...list.children];let act=0,closeT;
  items.forEach((li,i)=>li.style.setProperty('--i',i));
  const mark=i=>{act=i;items.forEach((li,k)=>li.classList.toggle('act',k===i))};
  const set=(v,silent)=>{items.forEach((li,i)=>{const on=li.dataset.v===v;li.setAttribute('aria-selected',on);if(on){label.textContent=li.textContent;mark(i)}});
    root.dataset.value=v;if(!silent&&onchange)onchange(v)};
  const closing=()=>list.hidden||list.classList.contains('out');
  const close=()=>{if(closing())return;btn.setAttribute('aria-expanded','false');list.classList.add('out');
    closeT=setTimeout(()=>{list.hidden=true;list.classList.remove('out')},130)};
  const open=()=>{clearTimeout(closeT);list.classList.remove('out');const r=btn.getBoundingClientRect();list.hidden=false;list.style.minWidth=r.width+'px';list.style.left=r.left+'px';
    const h=list.offsetHeight,up=r.bottom+8+h>innerHeight;list.style.top=(up?Math.max(8,r.top-8-h):r.bottom+8)+'px';
    list.style.transformOrigin=up?'bottom center':'top center';
    btn.setAttribute('aria-expanded','true');const sel=items.findIndex(li=>li.getAttribute('aria-selected')==='true');mark(sel<0?0:sel)};
  btn.onclick=()=>closing()?open():close();
  items.forEach(li=>li.onclick=()=>{set(li.dataset.v);close();btn.focus()});
  btn.addEventListener('keydown',e=>{
    if(closing()){if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();open()}return}
    if(e.key==='Escape'){close()}
    else if(e.key==='ArrowDown'){e.preventDefault();mark((act+1)%items.length)}
    else if(e.key==='ArrowUp'){e.preventDefault();mark((act-1+items.length)%items.length)}
    else if(e.key==='Enter'||e.key===' '){e.preventDefault();set(items[act].dataset.v);close()}
    else if(e.key==='Tab'){close()}});
  document.addEventListener('mousedown',e=>{if(!root.contains(e.target))close()});
  addEventListener('resize',close);document.addEventListener('scroll',close,true);
  set(items[0].dataset.v,true);return {set,get:()=>root.dataset.value||''}
}
const ddUnit=makeDD('a_unit',v=>{S.auto_unit=v;save()});
const ddLvl=makeDD('lvl',()=>render());

/* ── адреса ── */
const IPV4=/^(\d{1,3})(\.\d{1,3}){3}$/;
const okIp=s=>IPV4.test(s)&&s.split('.').every(x=>+x<=255);
const ipInt=s=>s.split('.').reduce((a,x)=>a*256+(+x),0);
function plural(n,f){const m=n%10,c=n%100;return f[(c>10&&c<20)?2:m===1?0:(m>=2&&m<=4)?1:2]}
function info(t){let m=t.match(/^(\d+\.\d+\.\d+\.\d+)-(.+)$/);
  if(m){let e=m[2];if(!e.includes('.'))e=m[1].split('.').slice(0,3).concat(e).join('.');
    if(okIp(m[1])&&okIp(e)){const n=Math.abs(ipInt(e)-ipInt(m[1]))+1;return{text:m[1]+' – '+e,n}}}
  m=t.match(/^(\S+)\/(\d+)$/);
  if(m&&+m[2]<=32){const n=Math.max(1,Math.pow(2,32-+m[2])-2);return{text:t,n}}
  return{text:t,n:1}}
/* Интервал = строка адреса. Правая кнопка по нему: только «Изменить» и «Удалить».
   Два независимых списка: targets (прокси) и hosts_targets (hosts). */
const normT=t=>String(t&&t.addr!==undefined?t.addr:t||'').trim();
const BOX={targets:'chips',hosts_targets:'h_chips'};
let popKey='',popIdx=-1;
function renderList(key,cntId){const box=$(BOX[key]),list=S[key];box.textContent='';let total=0;const pi=popKey===key?popIdx:-1;if(popKey===key)popIdx=-1;
  if(!list.length){const e=document.createElement('div');e.className='empty';e.textContent='Список пуст. Добавьте диапазон или адрес.';box.append(e)}
  list.forEach((t,i)=>{const f=info(t);total+=f.n;
    const c=document.createElement('div');c.className='li'+(i===pi?' pop':'');
    c.title='Двойной клик — выбрать пропускаемые IP; правая кнопка — изменить / удалить';
    const a=document.createElement('span');a.className='addr';a.textContent=f.text;a.title=f.text;
    const n=document.createElement('span');n.className='cnt';n.textContent=f.n+' '+plural(f.n,['адрес','адреса','адресов']);
    const sk=skipCount(t);if(sk){const x=document.createElement('b');x.textContent=sk;n.append(' · пропуск: ',x)}
    const b=document.createElement('button');b.textContent='✕';b.title='Убрать';b.setAttribute('aria-label','Убрать '+f.text);
    b.onclick=()=>delTarget(key,t,c);
    c.ondblclick=()=>openSkip(t);
    c.oncontextmenu=e=>{e.preventDefault();showCtx(e.clientX,e.clientY,[
      {l:'Изменить…',f:()=>editTarget(key,t)},{l:'Удалить',danger:true,f:()=>delTarget(key,t)}])};
    c.append(a,n,b);box.append(c)});
  $(cntId).textContent=list.length?`Записей: ${list.length}, всего адресов: ${total}`:''}
function renderChips(){renderList('targets','tcount');renderList('hosts_targets','h_tcount')}
function delTarget(key,t,el){snd('del');if(el)el.classList.add('out');
  setTimeout(()=>{const k=S[key].indexOf(t);if(k>=0)S[key].splice(k,1);renderChips();save()},el?190:0)}
function addTarget(key,v){if(!S[key].includes(v)){snd('add');S[key].push(v);popKey=key;popIdx=S[key].length-1;renderChips();save();const l=$(BOX[key]);l.scrollTop=l.scrollHeight}}
function buildAddr(a,b){if(!a)return{err:'Введите начальный IP'};
  if(b){if(!okIp(a)||!okIp(b))return{err:'Диапазон задаётся двумя корректными IPv4-адресами'};return{addr:a+'-'+b}}
  return{addr:a}}
function wireRange(key,pre,btn){const add=$(btn);
  add.onclick=()=>{const r=buildAddr($(pre+'_from').value.trim(),$(pre+'_to').value.trim());
    if(r.err)return toast(r.err);
    addTarget(key,r.addr);$(pre+'_from').value='';$(pre+'_to').value='';$(pre+'_from').focus()};
  [pre+'_from',pre+'_to'].forEach(id=>$(id).addEventListener('keydown',e=>{if(e.key==='Enter')add.click()}))}
wireRange('targets','ip','addRange');wireRange('hosts_targets','hip','h_addRange');
$('addLocal').onclick=()=>addTarget('targets','localhost');$('h_addLocal').onclick=()=>addTarget('hosts_targets','localhost');


/* ── пропускаемые IP: двойной клик по интервалу ── */
const skipSet=new Set();
const intIp=i=>[Math.floor(i/16777216)%256,(i>>>16)&255,(i>>>8)&255,i&255].join('.');
function ipsOf(t){const CAP=65536;let m=t.match(/^(\d+\.\d+\.\d+\.\d+)-(.+)$/);
  if(m){let e=m[2];if(!e.includes('.'))e=m[1].split('.').slice(0,3).concat(e).join('.');
    if(okIp(m[1])&&okIp(e)){let x=ipInt(m[1]),y=ipInt(e);if(x>y)[x,y]=[y,x];const r=[];for(let i=x;i<=y&&r.length<CAP;i++)r.push(intIp(i));return r}}
  m=t.match(/^(\S+)\/(\d+)$/);
  if(m&&okIp(m[1])&&+m[2]<=32){const p=+m[2],size=2**(32-p),st=Math.floor(ipInt(m[1])/size)*size,r=[];
    const a=p>=31?st:st+1,b=p>=31?st+size-1:st+size-2;for(let i=a;i<=b&&r.length<CAP;i++)r.push(intIp(i));return r}
  return [t]}
function skipCount(t){if(!skipSet.size)return 0;let n=0;for(const ip of ipsOf(t))if(skipSet.has(ip))n++;return n}
function saveSkips(){S.skips=[...skipSet];save()}
let skipIps=[],skipFound=[],skipLim=500,skipTarget='';
function openSkip(t){skipTarget=t;skipIps=ipsOf(t);skipLim=500;$('k_q').value='';$('k_title').textContent='IP интервала: '+info(t).text;
  $('skipModal').hidden=false;renderSkip();$('k_q').focus()}
function closeSkip(){$('skipModal').hidden=true;saveSkips();renderChips()}
function paintSkipInfo(){let n=0;for(const ip of skipIps)if(skipSet.has(ip))n++;
  $('k_info').textContent=`Найдено: ${skipFound.length} из ${skipIps.length} · пропускается: ${n}`}
function renderSkip(){const q=$('k_q').value.trim().toLowerCase(),box=$('k_list');
  skipFound=q?skipIps.filter(ip=>ip.toLowerCase().includes(q)):skipIps;box.textContent='';
  for(const ip of skipFound.slice(0,skipLim)){
    const r=document.createElement('label');r.className='skrow sw'+(skipSet.has(ip)?' on':'');
    const i=document.createElement('input');i.type='checkbox';i.checked=skipSet.has(ip);
    const tr=document.createElement('span');tr.className='trk';
    const a=document.createElement('span');a.className='ip';a.textContent=ip;
    r.append(a,i,tr);
    i.onchange=()=>{i.checked?skipSet.add(ip):skipSet.delete(ip);r.classList.toggle('on',i.checked);snd(i.checked?'del':'pick');paintSkipInfo();saveSkips()};
    box.append(r)}
  if(skipFound.length>skipLim){const m=document.createElement('button');m.className='btn sm';m.style.flex='0 0 auto';
    m.textContent=`Показать ещё (осталось ${skipFound.length-skipLim})`;m.onclick=()=>{skipLim+=500;renderSkip()};box.append(m)}
  if(!skipFound.length){const e=document.createElement('div');e.className='empty';e.textContent='Ничего не найдено';box.append(e)}
  paintSkipInfo()}
$('k_q').oninput=()=>{skipLim=500;renderSkip();$('k_list').scrollTop=0};
$('k_skip').onclick=()=>{skipFound.forEach(ip=>skipSet.add(ip));snd('del');renderSkip();saveSkips()};
$('k_unskip').onclick=()=>{skipFound.forEach(ip=>skipSet.delete(ip));snd('pick');renderSkip();saveSkips()};
$('k_done').onclick=closeSkip;
$('skipModal').addEventListener('mousedown',e=>{if(e.target===$('skipModal'))closeSkip()});
$('skipModal').addEventListener('keydown',e=>{if(e.key==='Escape')closeSkip()});

/* ── контекстное меню: rows = [{l, ck?, danger?, f}] ── */
let ctxEl=null;
function closeCtx(){if(ctxEl){ctxEl.remove();ctxEl=null}}
function showCtx(x,y,rows){closeCtx();const m=document.createElement('ul');m.className='ctx';m.setAttribute('role','menu');
  rows.forEach(r=>{const li=document.createElement('li');
    li.className='it'+(r.danger?' danger':'');li.tabIndex=0;li.setAttribute('role','menuitem');
    const ck=document.createElement('span');ck.className='ck';ck.textContent=r.ck?'●':(r.ck===false?'○':'');
    li.append(ck,document.createTextNode(r.l));
    li.onclick=()=>{closeCtx();r.f()};
    li.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();li.click()}
      else if(e.key==='ArrowDown'){e.preventDefault();li.nextElementSibling?.focus()}
      else if(e.key==='ArrowUp'){e.preventDefault();li.previousElementSibling?.focus()}};
    m.append(li)});
  document.body.append(m);ctxEl=m;
  m.style.left=Math.max(8,Math.min(x,innerWidth-m.offsetWidth-8))+'px';
  m.style.top=Math.max(8,Math.min(y,innerHeight-m.offsetHeight-8))+'px';
  m.querySelector('.it')?.focus()}
document.addEventListener('mousedown',e=>{if(ctxEl&&!ctxEl.contains(e.target))closeCtx()});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeCtx()});
addEventListener('resize',closeCtx);addEventListener('blur',closeCtx);document.addEventListener('scroll',closeCtx,true);
document.addEventListener('contextmenu',e=>{if(!e.target.closest('.li,.ctx,#b_add,#a_start'))closeCtx()});

/* ── «Добавить» и «Запустить»: ПКМ или индикатор переключают «включать прокси» ── */
const PX=[['b_add','i_add','add_proxy'],['a_start','i_auto','auto_proxy']];
function paintPx(){PX.forEach(([,i,k])=>{const on=S[k]!=='0',el=$(i);el.classList.toggle('on',on);
  el.textContent=on?'прокси: вкл':'прокси: выкл';el.setAttribute('aria-pressed',on)})}
function togglePx(k){S[k]=S[k]==='0'?'1':'0';paintPx();save();snd(S[k]==='0'?'off':'on')}
PX.forEach(([b,i,k])=>{$(i).onclick=()=>togglePx(k);
  $(b).addEventListener('contextmenu',e=>{e.preventDefault();
    showCtx(e.clientX,e.clientY,[{l:'Включать прокси',ck:S[k]!=='0',f:()=>togglePx(k)}])})});

/* ── редактирование интервала ── */
let editing=null;
function editTarget(key,t){editing={key,t};const m=t.match(/^(\d+\.\d+\.\d+\.\d+)-(.+)$/);let a=t,b='';
  if(m){a=m[1];b=m[2].includes('.')?m[2]:m[1].split('.').slice(0,3).concat(m[2]).join('.')}
  $('m_from').value=a;$('m_to').value=b;$('m_err').textContent='';$('modal').hidden=false;$('m_from').focus();$('m_from').select()}
function closeEdit(){$('modal').hidden=true;editing=null}
function saveEdit(){if(!editing)return;const {key,t}=editing,r=buildAddr($('m_from').value.trim(),$('m_to').value.trim());
  if(r.err){$('m_err').textContent=r.err;snd('err');return}
  if(r.addr!==t&&S[key].includes(r.addr)){$('m_err').textContent='Такой интервал уже есть в списке';snd('err');return}
  const k=S[key].indexOf(t);if(k>=0)S[key][k]=r.addr;
  closeEdit();snd('ok');renderChips();save()}
$('m_ok').onclick=saveEdit;$('m_cancel').onclick=closeEdit;
$('modal').addEventListener('mousedown',e=>{if(e.target===$('modal'))closeEdit()});
$('modal').addEventListener('keydown',e=>{if(e.key==='Enter')saveEdit();else if(e.key==='Escape')closeEdit()});


/* ── вкладки ── */
function moveThumb(instant){const b=document.querySelector('#seg [aria-selected=true]'),t=$('segThumb');if(!b)return;
  if(instant)t.style.transition='none';
  t.style.width=b.offsetWidth+'px';t.style.transform=`translateX(${b.offsetLeft}px)`;
  if(instant)requestAnimationFrame(()=>requestAnimationFrame(()=>t.style.transition=''))}
addEventListener('resize',()=>moveThumb(true));
$('seg').onclick=e=>{const b=e.target.closest('#seg button'),t=b&&b.dataset.t;if(!t)return;
  document.querySelectorAll('#seg button').forEach(x=>x.setAttribute('aria-selected',x===b));moveThumb();
  ['proxy','local','hosts'].forEach(n=>$('tab-'+n).classList.toggle('hide',t!==n));
  $('common').classList.toggle('hide',t==='local');curTab=t;render();
  try{localStorage.setItem('pt_tab',t)}catch(e){}try{history.replaceState(null,'','#'+t)}catch(e){}
  if(t==='local'){lpLoad();dashRefresh();dvList.refresh(true);setTimeout(drawChart,50)}
  if(t==='hosts'&&!hDirty())hostsLoad()};

/* ── запуск операций ── */
const req=tool=>({tool,targets:S.targets,entries:$('entries').value,workers:$('workers').value,timeout:$('timeout').value});
function flash(){const c=$('jobtxt').closest('.card');c.classList.remove('flash');void c.offsetWidth;c.classList.add('flash')}
async function run(tool){const p=req(tool);if(tool==='proxy_add')p.proxy_on=S.add_proxy!=='0';
  const r=await api('/api/run',p);if(!r.ok)toast(r.error);else{flash();snd('ok')}poll()}
$('b_add').onclick=()=>run('proxy_add');$('b_rm').onclick=()=>run('proxy_remove');$('b_rd').onclick=()=>run('proxy_read');
$('j_stop').onclick=async()=>{await api('/api/stop',{});snd('del');poll()};
$('a_start').onclick=async()=>{const p=req('proxy_add');p.proxy_on=S.auto_proxy!=='0';p.every=$('a_every').value;p.unit=ddUnit.get();
  const r=await api('/api/auto/start',p);if(!r.ok)toast(r.error);else{flash();snd('ok')}poll()};
$('a_stop').onclick=async()=>{await api('/api/auto/stop',{});snd('del');poll()};

/* ── локальный прокси ── */
async function lpLoad(){const d=await api('/api/local');lpOn=d.enable;
  $('power').setAttribute('aria-pressed',d.enable?'true':'false');
  {const el=$('lp_state'),t=d.enable?'Прокси включён':'Прокси выключен';if(el.textContent!==t){el.textContent=t;el.classList.remove('swap');void el.offsetWidth;el.classList.add('swap')}}
  $('lp_view').textContent=d.server?('Сервер: '+d.server):'Сервер не задан';
  if(document.activeElement!==$('lp_server'))$('lp_server').value=d.server||S.lp_server||'';
  if(document.activeElement!==$('lp_override'))$('lp_override').value=d.override||''}
async function lpSet(enable){const r=await api('/api/local/set',{enable,server:$('lp_server').value,override:$('lp_override').value});
  if(!r.ok)toast(r.error);else snd(enable===null?'ok':enable?'on':'off');lpLoad()}
$('power').onclick=()=>{const p=$('power');p.classList.remove('ping');void p.offsetWidth;p.classList.add('ping');lpSet(!lpOn)};
$('lp_save').onclick=()=>lpSet(null);$('lp_reload').onclick=lpLoad;

/* ── журнал ── */
function render(){const f=$('filter').value.toLowerCase(),l=ddLvl.get(),box=$('log');box.textContent='';
  for(const e of all){if(curTab==='hosts'?e.k!=='hosts':e.k==='hosts')continue;if(l&&e.lv!==l)continue;if(f&&!e.msg.toLowerCase().includes(f))continue;
    const d=document.createElement('div');d.className=e.lv;const t=document.createElement('span');t.className='t';t.textContent=e.t;
    d.append(t,document.createTextNode(e.msg));box.append(d)}
  if($('follow').checked)box.scrollTop=box.scrollHeight}
$('filter').oninput=render;$('follow').onchange=render;
$('dl').onclick=()=>{const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([all.map(e=>`${e.t} [${e.lv}] ${e.msg}`).join('\n')],{type:'text/plain'}));
  a.download='proxytool-log.txt';a.click()};
$('clr').onclick=async()=>{await api('/api/logs/clear',{});all=[];lastId=0;render()};

/* ── опрос состояния ── */
const fmt=ts=>new Date(ts*1000).toLocaleTimeString('ru-RU');
async function poll(){try{
  const s=await api('/api/state');
  {const nb=s.ext_unseen||0,bd=$('bdg'),was=bd.hidden;bd.hidden=!nb;bd.textContent=nb;if(was!==bd.hidden)moveThumb(true);
   if(lastSeq>=0&&nb>lastUnseen)notifyExt();lastUnseen=nb;
   const dash=!$('tab-local').classList.contains('hide');
   if(s.ev_seq!==lastSeq){const first=lastSeq<0;lastSeq=s.ev_seq;if(!first){evRefreshAll();if(dash)dashRefresh()}}
   else if(dash&&Date.now()-dashT>30000)dashRefresh();
   if(hostsMt&&s.hosts_mtime&&s.hosts_mtime!==hostsMt&&!hostsBusy){hostsBusy=true;onHostsChanged().finally(()=>{hostsBusy=false})}}
  $('admin').textContent=s.admin?'Администратор':'Без прав администратора';$('admin').className='pill '+(s.admin?'good':'bad');
  const j=s.job;$('jobb').textContent=j.running?'Работает':'Свободен';$('jobb').className='pill '+(j.running?'good':'');
  $('jobtxt').textContent=j.total?`${j.name}: ${j.done} из ${j.total}\nуспешно ${j.ok} · без изменений ${j.skip} · ошибок ${j.err}`:'Нет активных задач';
  $('jobbar').style.width=j.total?Math.round(100*j.done/j.total)+'%':'0';
  const a=s.auto;$('a_start').disabled=a.running;$('a_stop').disabled=!a.running;$('j_stop').disabled=!(j.running||a.running);
  $('a_state').textContent=a.running
    ?`Работает, цикл №${a.cycle}`+(a.next_ts?`, следующий в ${fmt(a.next_ts)}`:' (выполняется)')+(a.last?`\nПоследний: ${a.last}`:'')
    :'Остановлено'+(a.last?`\nПоследний: ${a.last}`:'');
  const g=await api('/api/logs?since='+lastId);
  if(g.logs.length){all=all.concat(g.logs);if(all.length>5000)all=all.slice(-5000);lastId=g.logs[g.logs.length-1].id;render()}
}catch(e){$('jobb').textContent='Нет связи с сервером';$('jobb').className='pill bad'}}

/* ── волна при нажатии ── */
document.addEventListener('pointerdown',e=>{
  const el=e.target.closest('.btn,.step,.iconbtn,.dd-btn,.li button,#seg button,.dd-list li,.ctx .it,.pxi');
  if(!el||el.disabled)return;
  snd(el.matches('#seg button')?'tab':el.matches('.dd-list li')?'pick':'click');
  if(matchMedia('(prefers-reduced-motion:reduce)').matches)return;
  const r=el.getBoundingClientRect(),s=Math.max(r.width,r.height)*2.2;
  const d=document.createElement('span');d.className='rip';
  d.style.cssText=`width:${s}px;height:${s}px;left:${e.clientX-r.left-s/2}px;top:${e.clientY-r.top-s/2}px`;
  el.append(d);d.addEventListener('animationend',()=>d.remove())},{passive:true});

let lastSeq=-1,lastUnseen=0,hostsBusy=false;
async function notifyExt(){try{const r=await api('/api/events?status=ext&limit=1'),e=r.events[0];
  if(e)toast('Изменено извне: '+(KIND[e.kind]||e.kind)+' · '+hostName(e.host)+' — '+((e.diff||'').split('\n')[0]||'см. журнал'))}catch(x){}}
/* ══════════ события: общий список, подробности, история ══════════ */
const WHO={me:'Вы',auto:'Авто-цикл',system:'Система'};
const WHO_LONG={me:'Вы (вручную в интерфейсе ProxyTool)',auto:'Автообновление ProxyTool',system:'Система / внешний источник (не ProxyTool)'};
const ST={ok:['Применено'],err:['Ошибка'],skip:['Пропущено'],ext:['Изменено извне']};
const KIND={proxy:'Proxy',hosts:'Hosts'};
const hostName=h=>h==='local'?'Этот ПК':h;
const p2=n=>String(n).padStart(2,'0');
const fmtDT=ts=>{const d=new Date(ts*1000);return `${p2(d.getDate())}.${p2(d.getMonth()+1)} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`};
const mkEl=(tag,cls,text,title)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;if(title)e.title=title;return e};

function ddMarkup(id,opts){
  return '<div class="dd" id="'+id+'"><button class="dd-btn" type="button" aria-haspopup="listbox" aria-expanded="false"><span class="dd-label">'+opts[0][1]+'</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></button><ul class="dd-list" role="listbox" hidden>'+
    opts.map(o=>'<li role="option" data-v="'+o[0]+'">'+o[1]+'</li>').join('')+'</ul></div>'}

const EVLISTS=[];
function makeEvList(root,pre,fixed,title){
  const stO=[['','Все статусы'],['ok','Применено'],['err','Ошибки'],['skip','Пропущено'],['ext','Изменено извне']];
  const kdO=[['','Proxy и Hosts'],['proxy','Proxy'],['hosts','Hosts']];
  root.innerHTML='<div class="logbar"><h2>'+title+'</h2><input type="text" id="'+pre+'_q" placeholder="Поиск: IP, кто, что изменилось" aria-label="Поиск по истории" autocomplete="off">'+
    ddMarkup(pre+'_st',stO)+(fixed?'':ddMarkup(pre+'_kd',kdO))+'<span class="sp"></span><button class="btn sm" id="'+pre+'_rf">Обновить</button></div><div class="evl" id="'+pre+'_l" role="log" aria-live="off"></div>';
  const q=$(pre+'_q'),box=$(pre+'_l');let rows=[],more=false,busy=false,again=false,stale=true,tm;
  const ddS=makeDD(pre+'_st',()=>load()),ddK=fixed?null:makeDD(pre+'_kd',()=>load());
  async function load(append){
    if(busy){again=true;return}
    busy=true;stale=false;
    try{
      const p=new URLSearchParams({kind:fixed||(ddK?ddK.get():''),status:ddS.get(),q:q.value.trim(),limit:200});
      if(append&&rows.length)p.set('before',rows[rows.length-1].id);
      const r=await api('/api/events?'+p);
      rows=append?rows.concat(r.events):r.events;more=r.events.length>=200;paint();
    }catch(e){}
    busy=false;if(again){again=false;load()}}
  function paint(){
    const keep=box.scrollTop;box.textContent='';
    if(!rows.length)box.append(mkEl('div','empty','Записей нет'));
    rows.forEach(e=>box.append(evRow(e)));
    if(more){const m=mkEl('button','btn sm more','Показать ещё');m.onclick=()=>load(true);box.append(m)}
    box.scrollTop=keep}
  q.addEventListener('input',()=>{clearTimeout(tm);tm=setTimeout(()=>load(),250)});
  $(pre+'_rf').onclick=()=>load();
  const api2={refresh(force){if(!force&&root.offsetParent===null){stale=true;return}load()},isStale:()=>stale,root};
  EVLISTS.push(api2);return api2}

function evRow(e){
  const d=mkEl('div','ev st-'+e.status+(e.status==='ext'&&!e.seen?' blink':''));
  d.tabIndex=0;d.setAttribute('role','button');
  const sum=(e.diff||e.detail||'').split('\n').slice(0,3).join('  ');
  d.append(mkEl('span','et',fmtDT(e.ts)),mkEl('span','chip k-'+e.kind,KIND[e.kind]||e.kind),
    mkEl('span','host',hostName(e.host),hostName(e.host)),mkEl('span','chip who who-'+e.actor,WHO[e.actor]||e.actor),
    mkEl('span','chip st-'+e.status,(ST[e.status]||[e.status])[0]),mkEl('span','sum',sum,sum));
  d.onclick=()=>openEv(e.id);d.onkeydown=ev=>{if(ev.key==='Enter')openEv(e.id)};
  return d}
const evRefreshAll=force=>EVLISTS.forEach(l=>l.refresh(force));

async function openEv(id){
  let r;try{r=await api('/api/event?id='+id)}catch(e){return}
  if(!r.ok)return toast('Запись не найдена');
  const e=r.event;
  $('e_title').textContent=(e.status==='ext'?'Изменено извне · ':'')+(KIND[e.kind]||e.kind)+' · '+hostName(e.host);
  const kv=$('e_kv');kv.textContent='';
  [['Когда',new Date(e.ts*1000).toLocaleString('ru-RU')],['Что менялось',KIND[e.kind]||e.kind],['Компьютер',hostName(e.host)],
   ['Кто изменил',WHO_LONG[e.actor]||e.actor],['Результат',(ST[e.status]||[e.status])[0]],['Протокол / источник',e.protocol||'—'],
   ['Подробности',e.detail||'—']].forEach(([k,v])=>{kv.append(mkEl('dt','',k),mkEl('dd','',v))});
  const df=$('e_diff');df.textContent='';
  (e.diff||'').split('\n').filter(Boolean).forEach(l=>df.append(mkEl('div',l[0]==='+'?'add':l[0]==='-'?'del':'',l)));
  $('e_diffw').hidden=!e.diff;
  $('e_old').textContent=e.old||'(пусто)';$('e_new').textContent=e.new||'(пусто)';
  $('e_cmp').hidden=!(e.old||e.new);
  $('evModal').hidden=false;$('e_close').focus();
  if(!e.seen){await api('/api/events/seen',{ids:[e.id]});evRefreshAll()}}
$('e_close').onclick=()=>{$('evModal').hidden=true};
$('evModal').addEventListener('mousedown',e=>{if(e.target===$('evModal'))$('evModal').hidden=true});
$('evModal').addEventListener('keydown',e=>{if(e.key==='Escape')$('evModal').hidden=true});

let histP,histH;
function openHist(kind){
  $('hs_title').textContent='История изменений · '+KIND[kind];
  $('hist_proxy').hidden=kind!=='proxy';$('hist_hosts').hidden=kind!=='hosts';
  $('histModal').hidden=false;(kind==='proxy'?histP:histH).refresh(true);$('hs_close').focus()}
$('hs_close').onclick=()=>{$('histModal').hidden=true};
$('histModal').addEventListener('mousedown',e=>{if(e.target===$('histModal'))$('histModal').hidden=true});
$('histModal').addEventListener('keydown',e=>{if(e.key==='Escape'&&$('evModal').hidden)$('histModal').hidden=true});
$('p_hist').onclick=()=>openHist('proxy');

/* ══════════ панель: итоги, период внешних сбросов, график ══════════ */
let chartRange='24h',dashT=0,chartData=null,dvList;
function paintTotals(t){
  const tb=$('tot_b');tb.textContent='';
  [['ok','Применено','ok'],['err','Ошибок','err'],['skip','Пропущено','skip'],['ext','Изменено извне','warn']].forEach(([k,l,c])=>{
    const tr=document.createElement('tr');tr.append(mkEl('td',c,l));
    ['today','yesterday','month'].forEach(p=>tr.append(mkEl('td','',String((t[p]||{})[k]||0))));tb.append(tr)})}
const fmtMin=m=>m<90?Math.round(m)+' мин':Math.floor(m/60)+' ч '+Math.round(m%60)+' мин';
const fmtT=ts=>new Date(ts*1000).toLocaleTimeString('ru-RU');
function resetLine(name,color,r){
  const d=mkEl('div'),dot=mkEl('i');dot.style.background=color;
  const s=mkEl('span','');s.append(mkEl('b','',name+': '));
  if(!r.changes)s.append(document.createTextNode('на этом ПК внешних изменений пока не замечено'));
  else{
    let t='последнее изменение '+fmtDT(r.last_ts);
    if(r.median_min)t+=' · период ≈ '+fmtMin(r.median_min)+(r.stable?' (установился)':' (уточняется, замеров: '+r.samples+')');
    if(r.next_ts)t+=r.next_ts*1000<Date.now()?' · следующий ожидается сейчас':' · следующий ≈ '+fmtT(r.next_ts);
    s.append(document.createTextNode(t));
    if((r.times||[]).length>1)s.append(mkEl('span','sub','Точные времена: '+r.times.map(fmtDT).join(' → ')))}
  d.append(dot,s);return d}
function paintResets(r){const b=$('resets');b.textContent='';
  b.append(resetLine('Прокси','var(--c1)',r.proxy||{}),resetLine('Hosts','var(--c2)',r.hosts||{}))}
async function dashRefresh(){dashT=Date.now();
  try{const d=await api('/api/stats?range='+chartRange);paintTotals(d.totals);paintResets(d.resets);chartData=d.series;drawChart()}catch(e){}}
function drawChart(){
  const s=chartData,box=$('chart');if(!s||!box)return;
  const W=Math.max(320,box.clientWidth),H=Math.max(120,box.clientHeight),L=34,R=14,T=12,B=26,n=s.labels.length;
  if(!n){box.textContent='';return}
  const ext=s.ext||[],mx=Math.max(1,...s.proxy,...s.hosts,...ext);let step=1;
  for(const c of [1,2,5,10,20,50,100,200,500,1000,2000,5000,10000,20000,50000]){step=c;if(mx/c<=4)break}
  const top=Math.max(4,Math.ceil(mx/step)*step),X=i=>L+(n<2?(W-L-R)/2:i*(W-L-R)/(n-1)),Y=v=>T+(H-T-B)*(1-v/top);
  let g='';for(let v=0;v<=top;v+=step)g+=`<line class="gl" x1="${L}" x2="${W-R}" y1="${Y(v)}" y2="${Y(v)}"/><text class="tx" x="${L-6}" y="${Y(v)+4}" text-anchor="end">${v}</text>`;
  const k=Math.ceil(n/8);let xl='';s.labels.forEach((l,i)=>{if(i%k===0)xl+=`<text class="tx" x="${X(i)}" y="${H-8}" text-anchor="middle">${l}</text>`});
  const path=a=>a.map((v,i)=>(i?'L':'M')+X(i).toFixed(1)+' '+Y(v).toFixed(1)).join(' ');
  const dots=(a,c)=>a.map((v,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(v).toFixed(1)}" r="3.2" class="dot ${c}"/>`).join('');
  const empty=!s.proxy.some(Boolean)&&!s.hosts.some(Boolean)&&!ext.some(Boolean);
  box.innerHTML=`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="График: на скольких компьютерах исправлены прокси и hosts">${g}${xl}`+
    `<path d="${path(ext)}" class="ln l3"/><path d="${path(s.hosts)}" class="ln l2"/><path d="${path(s.proxy)}" class="ln l1"/>${dots(ext,'l3')}${dots(s.hosts,'l2')}${dots(s.proxy,'l1')}`+
    (empty?`<text class="tx" x="${(W+L)/2}" y="${(H-B)/2}" text-anchor="middle">За этот период исправлений пока нет</text>`:'')+
    `<line id="cg" class="gl" y1="${T}" y2="${H-B}" x1="0" x2="0" style="display:none"/><rect id="cov" x="${L}" y="${T}" width="${W-L-R}" height="${H-T-B}" fill="transparent"/></svg><div class="ctip" id="ctip" hidden></div>`;
  const cov=$('cov'),tip=$('ctip'),cg=$('cg');
  cov.onmousemove=e=>{const r=cov.getBoundingClientRect(),x=(e.clientX-r.left)/r.width*(W-L-R);
    const i=Math.max(0,Math.min(n-1,Math.round(n<2?0:x/((W-L-R)/(n-1)))));
    cg.setAttribute('x1',X(i));cg.setAttribute('x2',X(i));cg.style.display='';
    tip.hidden=false;tip.textContent='';
    const a=mkEl('b','',s.labels[i]);tip.append(a,document.createElement('br'),
      document.createTextNode('Прокси: '+s.proxy[i]+' ПК'),document.createElement('br'),document.createTextNode('Hosts: '+s.hosts[i]+' ПК'),document.createElement('br'),document.createTextNode('Извне на этом ПК: '+(ext[i]||0)));
    tip.style.left=X(i)+'px';tip.style.top=Math.max(60,Math.min(Y(s.proxy[i]),Y(s.hosts[i]),Y(ext[i]||0)))+'px'};
  cov.onmouseleave=()=>{tip.hidden=true;cg.style.display='none'}}
addEventListener('resize',()=>{if(!$('tab-local').classList.contains('hide'))drawChart()});

/* ══════════ вкладка hosts ══════════ */
let hostsBase='',hostsMt=0,hostsMeta=null;
const normH=t=>String(t).replace(/\r\n?/g,'\n').split('\n').map(l=>l.replace(/\s+$/,'')).join('\n').replace(/^\n+|\n+$/g,'');
const hDirty=()=>normH($('h_edit').value)!==normH(hostsBase);
const fmtSize=n=>n<1024?n+' Б':(n/1024).toFixed(1)+' КБ';
const IPRE=/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.%]*)$/;
function parseHosts(t){const out=[];
  t.split(/\r?\n/).forEach((raw,i)=>{const line=raw.trim();if(!line)return;
    if(line[0]==='#'){out.push({n:i+1,c:true,cm:line});return}
    const k=line.indexOf('#'),body=(k<0?line:line.slice(0,k)).trim(),cm=k<0?'':line.slice(k).trim(),p=body.split(/\s+/);
    out.push({n:i+1,ip:p[0],names:p.slice(1),cm,bad:!IPRE.test(p[0])||p.length<2})});
  return out}
function paintHosts(){
  const rows=parseHosts($('h_edit').value),box=$('h_struct');box.textContent='';
  let ent=0,com=0,bad=0;const names=new Set();
  const showC=$('h_com').checked,vis=showC?rows:rows.filter(r=>!r.c);
  vis.slice(0,3000).forEach(r=>{
    const d=mkEl('div','hr'+(r.c?' c':'')+(r.bad?' bad':''));d.append(mkEl('span','n',String(r.n)));
    if(r.c)d.append(mkEl('span','cm',r.cm));
    else{d.append(mkEl('span','ip',r.ip),mkEl('span','nm',r.names.join(' ')+(r.cm?'   '+r.cm:''),r.names.join(' ')))}
    d.onclick=()=>gotoLine(r.n);box.append(d)});
  rows.forEach(r=>{if(r.c)com++;else{ent++;if(r.bad)bad++;r.names.forEach(n=>names.add(n.toLowerCase()))}});
  if(!vis.length)box.append(mkEl('div','empty',rows.length?'Только комментарии (включите их показ выше)':'Файл пуст'));
  if(vis.length>3000)box.append(mkEl('div','empty','Показаны первые 3000 строк'));
  const sm=$('h_sum');sm.className='hint'+(bad?' bad':'');
  sm.textContent=`Записей: ${ent} · комментариев: ${com} · уникальных имён: ${names.size}`+(bad?` · с ошибками формата: ${bad}`:'');
  $('h_dirty').hidden=!hDirty()}
function gotoLine(n){const ta=$('h_edit'),lines=ta.value.split('\n');let a=0;for(let i=0;i<n-1;i++)a+=lines[i].length+1;
  ta.focus();ta.setSelectionRange(a,a+(lines[n-1]||'').length);
  ta.scrollTop=Math.max(0,n-4)*(parseFloat(getComputedStyle(ta).lineHeight)||20)}
function paintHostsMeta(){const d=hostsMeta;if(!d)return;
  $('h_meta').textContent=d.exists?`${d.path} · ${fmtSize(d.size)} · изменён ${fmtDT(d.mtime)}`:`${d.path} · файл не прочитан${d.error?': '+d.error:''}`}
async function hostsLoad(){
  let d;try{d=await api('/api/hosts')}catch(e){return}
  hostsMeta=d;hostsMt=d.mtime||0;hostsBase=d.text||'';$('h_edit').value=hostsBase;$('h_ext').hidden=true;paintHostsMeta();paintHosts()}
async function onHostsChanged(){
  let d;try{d=await api('/api/hosts')}catch(e){return}
  hostsMeta=d;hostsMt=d.mtime||0;paintHostsMeta();
  if(normH(d.text||'')===normH($('h_edit').value)){hostsBase=d.text||'';paintHosts();$('h_ext').hidden=true;return}
  if(!hDirty()){hostsBase=d.text||'';$('h_edit').value=hostsBase;paintHosts();$('h_ext').hidden=true;
    const c=$('h_edit').closest('.card');c.classList.remove('flash');void c.offsetWidth;c.classList.add('flash')}
  else $('h_ext').hidden=false}
async function runHosts(only){
  const content=$('h_edit').value;
  if(!content.trim())return toast('Файл hosts пуст — применять нечего');
  if(!only&&!S.hosts_targets.length)return toast('Нет адресов: добавьте интервал выше');
  const r=await api('/api/run',{tool:'hosts_apply',targets:only?['localhost']:S.hosts_targets,content,workers:$('h_workers').value,timeout:$('h_timeout').value});
  if(!r.ok)toast(r.error);else{flash();snd('ok')}poll()}
$('h_edit').addEventListener('input',paintHosts);$('h_com').onchange=paintHosts;
$('h_apply').onclick=()=>runHosts(false);$('h_local').onclick=()=>runHosts(true);
let pcText='',pcMt=0,pcSrc='local',pcScan=new Map(),pcFrom=0,pcRun=false,pcDone=0,pcTot=0,pcT=0;
function pcStep(n){$('pc_pick').hidden=n!==1;$('pc_q').hidden=n!==1;$('pc_rescan').hidden=n!==1;
  $('pc_list').hidden=n!==2;$('pc_back').hidden=$('pc_replace').hidden=$('pc_add').hidden=n!==2}
function pcRender(){const box=$('pc_pick'),q=$('pc_q').value.trim();box.textContent='';
  const mk=(src,name,ms,on)=>{const r=mkEl('div','skrow pcrow'+(on?'':' off'));r.tabIndex=on?0:-1;r.setAttribute('role','button');
    const nm=mkEl('span','nm');nm.append(mkEl('span','wdot'+(on?' on':'')),mkEl('span','ip',name),mkEl('span','ms',ms));
    r.append(nm);if(on){r.onclick=()=>pcPick(src);r.onkeydown=e=>{if(e.key==='Enter')pcPick(src)}}box.append(r)};
  if(!q||'мой пк'.includes(q.toLowerCase()))mk('local','Мой ПК','этот компьютер',true);
  const arr=[...pcScan.keys()].filter(ip=>!q||ip.includes(q));
  arr.sort((a,b)=>((pcScan.get(b)!=null)-(pcScan.get(a)!=null))||(ipInt(a)-ipInt(b))||(a<b?-1:1));
  arr.slice(0,600).forEach(ip=>{const ms=pcScan.get(ip);mk(ip,ip,ms!=null?ms+' мс':'нет ответа',ms!=null)});
  let on=0;pcScan.forEach(v=>{if(v!=null)on++});
  $('pc_foot').textContent=(pcRun?`Проверено ${pcDone} из ${pcTot} · `:'')+`на связи: ${on} из ${pcScan.size}`+(arr.length>600?' · показаны первые 600':'')}
async function pcStartScan(){pcScan=new Map();pcFrom=0;pcRun=true;pcDone=pcTot=0;pcRender();
  try{const r=await api('/api/scan/start',{kind:'hosts'});if(!r.ok&&!/уже идёт/.test(r.error||'')){pcRun=false;$('pc_info').textContent=r.error}}catch(e){pcRun=false}
  pcPoll()}
async function pcPoll(){clearTimeout(pcT);if($('pcModal').hidden||$('pc_pick').hidden)return;
  try{const r=await api('/api/scan?from='+pcFrom);r.items.forEach(([ip,ms])=>pcScan.set(ip,ms));pcFrom+=r.items.length;pcRun=r.running;pcDone=r.done;pcTot=r.total;pcRender()}catch(e){}
  if(pcRun)pcT=setTimeout(pcPoll,600)}
function openPc(){pcStep(1);$('pc_title').textContent='Откуда загрузить hosts';$('pc_q').value='';
  $('pc_info').textContent='Адреса из интервалов проверяются ping-ом. Выберите компьютер — загрузится его файл hosts.';
  $('pcModal').hidden=false;pcStartScan()}
async function pcPick(src){
  $('pc_info').textContent='Читаю hosts…';let d;
  try{d=await api('/api/hosts'+(src==='local'?'':'?ip='+encodeURIComponent(src)))}catch(e){$('pc_info').textContent='';return}
  if(!d.exists){$('pc_info').textContent='Выберите компьютер — загрузится его файл hosts.';return toast('Не удалось прочитать hosts '+(src==='local'?'этого ПК':src)+': '+(d.error||''))}
  pcSrc=src;pcText=d.text||'';pcMt=src==='local'?(d.mtime||0):0;clearTimeout(pcT);
  const rows=parseHosts(pcText).filter(r=>!r.c),box=$('pc_list');box.textContent='';
  rows.forEach(r=>{const x=mkEl('div','hr'+(r.bad?' bad':''));
    x.append(mkEl('span','n',String(r.n)),mkEl('span','ip',r.ip),mkEl('span','nm',r.names.join(' ')+(r.cm?'   '+r.cm:'')));box.append(x)});
  if(!rows.length)box.append(mkEl('div','empty','В файле нет записей'));
  $('pc_title').textContent='hosts: '+(src==='local'?'мой ПК':src);
  $('pc_info').textContent=`Записей: ${rows.length}. «Заменить» — всё в окне заменится этим файлом; «Добавить» — недостающие записи допишутся в конец.`;
  $('pc_foot').textContent='';pcStep(2);$('pc_replace').focus()}
const closePc=()=>{$('pcModal').hidden=true;clearTimeout(pcT)};
$('h_reload').onclick=openPc;$('pc_cancel').onclick=closePc;
$('pc_back').onclick=()=>{pcStep(1);$('pc_title').textContent='Откуда загрузить hosts';$('pc_info').textContent='Выберите компьютер — загрузится его файл hosts.';pcRender();if(pcRun)pcPoll()};
$('pc_rescan').onclick=()=>{snd('click');pcStartScan()};$('pc_q').oninput=pcRender;
$('pcModal').addEventListener('mousedown',e=>{if(e.target===$('pcModal'))closePc()});
$('pcModal').addEventListener('keydown',e=>{if(e.key==='Escape')closePc()});
$('pc_replace').onclick=()=>{$('h_edit').value=pcText;
  if(pcSrc==='local'){hostsBase=pcText;hostsMt=pcMt;$('h_ext').hidden=true}
  paintHosts();closePc();snd('ok')};
$('pc_add').onclick=()=>{const norm=l=>l.trim().replace(/\s+/g,' ').toLowerCase(),ta=$('h_edit'),have=new Set(ta.value.split(/\r?\n/).map(norm));
  const add=pcText.split(/\r?\n/).filter(l=>l.trim()&&l.trim()[0]!=='#'&&!have.has(norm(l)));
  if(add.length)ta.value=ta.value.replace(/\s+$/,'')+'\n'+add.map(l=>l.trim()).join('\n')+'\n';
  paintHosts();closePc();snd(add.length?'add':'pick')};
$('h_editsw').onchange=()=>{const e=$('h_editsw').checked;$('h_edit').hidden=!e;$('h_struct').hidden=e;if(e)$('h_edit').focus()};
bind('h_workers','h_workers');bind('h_timeout','h_timeout');

/* ══════════ наблюдение за компьютерами (общее окно для Proxy и Hosts) ══════════ */
const watchSets={proxy:new Set(),hosts:new Set()};
let wKind='proxy',scanMap=new Map(),scanFrom=0,scanRun=false,scanDone=0,scanTot=0,wStates=new Map(),wLim=300,wT1=0,wT2=0,wPend=false;
const ddW=makeDD('w_flt',()=>{wLim=300;wRender()});
const paintWcnt=()=>{const n=watchSets.proxy.size,b=$('wcnt');b.hidden=!n;b.textContent=n;b.title='Под наблюдением: '+n+' ПК'};
const wSave=()=>{S.watch_proxy=[...watchSets.proxy];S.watch_hosts=[...watchSets.hosts];paintWcnt();save()};
const wOnline=ip=>scanMap.get(ip)!=null||!!(wStates.get(wKind+'|'+ip)||{}).online;
function wList(){const set=watchSets[wKind],q=$('w_q').value.trim(),f=ddW.get();
  const arr=[...new Set([...scanMap.keys(),...set])].filter(ip=>(!q||ip.includes(q))&&
    (f===''||(f==='on'&&wOnline(ip))||(f==='off'&&!wOnline(ip))||(f==='watch'&&set.has(ip))));
  arr.sort((a,b)=>(wOnline(b)-wOnline(a))||(ipInt(a)-ipInt(b))||(a<b?-1:1));return arr}
function wRender(){
  const set=watchSets[wKind],box=$('w_list'),arr=wList();box.textContent='';
  arr.slice(0,wLim).forEach(ip=>{
    const st=wStates.get(wKind+'|'+ip),on=wOnline(ip);
    const r=mkEl('label','skrow sw wrow'+(set.has(ip)?' w-on':''));
    const nm=mkEl('span','nm');nm.append(mkEl('span','wdot'+(on?(st&&st.err?' bad':' on'):'')),mkEl('span','ip',ip));
    const ms=scanMap.get(ip);
    nm.append(mkEl('span','ms',ms!=null?ms+' мс':(on?'на связи':'нет ответа'),st&&st.err?st.err:(st&&st.checked?'проверен '+new Date(st.checked*1000).toLocaleTimeString('ru-RU'):'')));
    const i=document.createElement('input');i.type='checkbox';i.checked=set.has(ip);i.setAttribute('aria-label','Наблюдать за '+ip);
    i.onchange=()=>{i.checked?set.add(ip):set.delete(ip);r.classList.toggle('w-on',i.checked);snd(i.checked?'on':'off');wSave();wInfo()};
    r.append(nm,i,mkEl('span','trk'));box.append(r)});
  if(arr.length>wLim){const m=mkEl('button','btn main',`Показать ещё (осталось ${arr.length-wLim})`);m.style.cssText='padding:12px 28px;font-size:14px;margin:6px 0';m.onclick=()=>{wLim+=300;wRender()};box.append(m)}
  if(!arr.length)box.append(mkEl('div','empty',scanRun?'Идёт проверка…':'Ничего не найдено'));
  wInfo()}
function wInfo(){let on=0;scanMap.forEach(v=>{if(v!=null)on++});
  $('w_info').textContent=(scanRun?`Проверено ${scanDone} из ${scanTot} · `:'')+`на связи: ${on} из ${scanMap.size} · под наблюдением: ${watchSets[wKind].size}`}
function wPaint(){if(wPend)return;wPend=true;setTimeout(()=>{wPend=false;if(!$('watchModal').hidden)wRender()},250)}
async function wStartScan(){scanMap=new Map();scanFrom=0;scanRun=true;scanDone=0;scanTot=0;wRender();
  try{const r=await api('/api/scan/start',{kind:wKind});if(!r.ok&&!/уже идёт/.test(r.error||'')){toast(r.error);scanRun=false}}catch(e){scanRun=false}
  wPollScan()}
async function wPollScan(){clearTimeout(wT1);if($('watchModal').hidden)return;
  try{const r=await api('/api/scan?from='+scanFrom);r.items.forEach(([ip,ms])=>scanMap.set(ip,ms));scanFrom+=r.items.length;
    scanRun=r.running;scanDone=r.done;scanTot=r.total;wPaint()}catch(e){}
  if(scanRun)wT1=setTimeout(wPollScan,600);else wPaint()}
async function wPollWatch(){clearTimeout(wT2);if($('watchModal').hidden)return;
  try{const r=await api('/api/watch');wStates=new Map(r.states.map(x=>[x.kind+'|'+x.ip,x]));wPaint()}catch(e){}
  wT2=setTimeout(wPollWatch,3000)}
function openWatch(k){wKind=k;$('w_title').textContent='Наблюдение за компьютерами · '+KIND[k];
  $('w_every').value=S.watch_every;$('w_local').value=S.mon_every;$('w_q').value='';ddW.set('',true);wLim=300;
  $('watchModal').hidden=false;wStartScan();wPollWatch()}
function closeWatch(){$('watchModal').hidden=true;clearTimeout(wT1);clearTimeout(wT2)}
$('w_done').onclick=closeWatch;$('w_scan').onclick=()=>{snd('click');wStartScan()};
$('watchModal').addEventListener('mousedown',e=>{if(e.target===$('watchModal'))closeWatch()});
$('watchModal').addEventListener('keydown',e=>{if(e.key==='Escape')closeWatch()});
$('w_q').oninput=()=>{wLim=300;wRender()};
$('w_on').onclick=()=>{wList().filter(wOnline).forEach(ip=>watchSets[wKind].add(ip));snd('on');wSave();wRender()};
$('w_off').onclick=()=>{wList().forEach(ip=>watchSets[wKind].delete(ip));snd('off');wSave();wRender()};
$('p_watch').onclick=()=>openWatch('proxy');
bind('w_every','watch_every');bind('w_local','mon_every');

/* ── старт: подгружаем данные из AppData ── */
(async()=>{try{const d=await api('/api/settings');Object.assign(S,d)}catch(e){toast('Не удалось прочитать настройки')}
  S.targets=(S.targets||[]).map(normT).filter(Boolean);(S.skips||[]).forEach(ip=>skipSet.add(ip));
  $('entries').value=S.entries;$('workers').value=S.workers;$('timeout').value=S.timeout;
  S.hosts_targets=(S.hosts_targets||[]).map(normT).filter(Boolean);$('h_workers').value=S.h_workers;$('h_timeout').value=S.h_timeout;
  $('a_every').value=S.auto_every;ddUnit.set(S.auto_unit,true);$('lp_server').value=S.lp_server;$('lp_override').value=S.lp_override;
  if(S.theme)applyTheme(S.theme);paintSound();
  (S.watch_proxy||[]).forEach(ip=>watchSets.proxy.add(ip));(S.watch_hosts||[]).forEach(ip=>watchSets.hosts.add(ip));paintWcnt();
  dvList=makeEvList($('dash_log'),'dv','','Журнал изменений');
  histP=makeEvList($('hist_proxy'),'hp','proxy','Записи');histH=makeEvList($('hist_hosts'),'hh','hosts','Записи');
  renderChips();paintPx();moveThumb(true);poll();setInterval(poll,1000);hostsLoad();
  {let h=location.hash.slice(1);if(!h)try{h=localStorage.getItem('pt_tab')||''}catch(e){}
   if(h==='local'||h==='hosts')document.querySelector('[data-t='+h+']').click()}})();
</script></body></html>
"""


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP-СЕРВЕР
# ═════════════════════════════════════════════════════════════════════════════
class Handler(BaseHTTPRequestHandler):
    server_version = "ProxyTool/2.0"
    allowed_hosts = None  # в loopback-режиме защита от DNS-rebinding

    def log_message(self, *a):
        pass

    def _host_ok(self):
        if self.allowed_hosts is None:
            return True
        return (self.headers.get("Host") or "").lower() in self.allowed_hosts

    def _send(self, code, data, ctype="application/json; charset=utf-8"):
        raw = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _guard(self):
        if not self._host_ok():
            self._send(403, {"ok": False, "error": "Хост не разрешён"})
            return False
        return True

    def do_GET(self):
        if not self._guard():
            return
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        if self.headers.get("X-Requested-With") != "ProxyTool":
            return self._send(403, {"ok": False, "error": "Нет служебного заголовка"})
        if u.path == "/api/state":
            with _JOB_LOCK:
                job = dict(JOB)
            return self._send(200, {"admin": is_admin(), "job": job, "auto": AUTO.state(),
                                    "ev_seq": EV_SEQ, "ext_unseen": unseen_ext(),
                                    "hosts_mtime": hosts_mtime()})
        if u.path == "/api/logs":
            try:
                since = int(parse_qs(u.query).get("since", ["0"])[0])
            except ValueError:
                since = 0
            return self._send(200, {"logs": get_logs(since)})
        if u.path == "/api/local":
            return self._send(200, local_proxy_info())
        if u.path == "/api/settings":
            return self._send(200, load_settings())
        qs = parse_qs(u.query)

        def arg(name, default=""):
            return (qs.get(name) or [default])[0]

        def num(name, default=0):
            try:
                return int(arg(name, str(default)))
            except ValueError:
                return default

        if u.path == "/api/hosts":
            ip = arg("ip").strip()
            if not ip or is_local(ip):
                return self._send(200, hosts_info())
            if not re.match(r"^[A-Za-z0-9.\-]{1,64}$", ip):
                return self._send(200, {"exists": False, "error": "Некорректный адрес"})
            _CTX.bg = True                    # чтение не должно зависеть от кнопки «Стоп»
            text, err = hosts_remote_read(ip, 8)
            if err:
                return self._send(200, {"exists": False, "error": err})
            return self._send(200, {"path": _hosts_unc(ip), "exists": True, "text": text,
                                    "size": len(text.encode("utf-8")), "mtime": 0})
        if u.path == "/api/events":
            return self._send(200, {"events": query_events(arg("kind"), arg("status"), arg("q").strip()[:100],
                                                           num("before"), num("limit", 200))})
        if u.path == "/api/event":
            ev = get_event(num("id"))
            return self._send(200, {"ok": bool(ev), "event": ev})
        if u.path == "/api/stats":
            return self._send(200, event_stats(arg("range", "24h")))
        if u.path == "/api/scan":
            start = max(0, num("from"))
            with _SCAN_LOCK:
                res = {"running": SCAN["running"], "done": SCAN["done"], "total": SCAN["total"],
                       "items": SCAN["items"][start:start + 5000]}
            return self._send(200, res)
        if u.path == "/api/watch":
            return self._send(200, {"states": MON.states()})
        self._send(404, {"ok": False, "error": "Не найдено"})

    def do_POST(self):
        if not self._guard():
            return
        if self.headers.get("X-Requested-With") != "ProxyTool":
            return self._send(403, {"ok": False, "error": "Нет служебного заголовка"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                return self._send(413, {"ok": False, "error": "Слишком большой запрос"})
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._send(400, {"ok": False, "error": "Некорректный JSON"})
        p = urlparse(self.path).path
        try:
            if p == "/api/run":
                tool, items, params, workers, timeout = build_request(body)
                ok, msg = start_job(tool, items, params, workers, timeout)
                return self._send(200, {"ok": ok, "error": None if ok else msg})
            if p == "/api/auto/start":
                cfg, raw = auto_cfg_from_body(body)
                ok, msg = AUTO.start(cfg, raw)
                return self._send(200, {"ok": ok, "error": None if ok else msg})
            if p in ("/api/auto/stop", "/api/stop"):
                with _JOB_LOCK:
                    was_busy = JOB["running"]
                AUTO.stop()                       # цикл + текущая задача + все reg/sc/сокеты
                if was_busy or p == "/api/stop":
                    log("warn", "СТОП: все операции прерваны, новые запросы не отправляются")
                return self._send(200, {"ok": True})
            if p == "/api/events/seen":
                ids = body.get("ids")
                if isinstance(ids, list):
                    mark_seen(ids)
                elif body.get("all") is True:
                    mark_seen(None)
                return self._send(200, {"ok": True})
            if p == "/api/scan/start":
                ok, msg = scan_start("hosts" if body.get("kind") == "hosts" else "proxy")
                return self._send(200, {"ok": ok, "error": None if ok else msg})
            if p == "/api/logs/clear":
                clear_logs()
                return self._send(200, {"ok": True})
            if p == "/api/settings":
                return self._send(200, {"ok": save_settings(body)})
            if p == "/api/local/set":
                enable = body.get("enable")           # True / False / None (не менять)
                server = (body.get("server") or "").strip()
                override = body.get("override")
                if enable is True and not server and not local_proxy_info()["server"]:
                    raise ValueError("Укажите сервер прокси (хост:порт)")
                ok = local_proxy_set(
                    enable=None if enable is None else bool(enable),
                    server=server if server else None,
                    override=override.strip() if isinstance(override, str) else None)
                if enable is None:
                    what = "параметры сохранены"
                else:
                    what = "ВКЛЮЧЁН" if enable else "ВЫКЛЮЧЕН"
                log("ok" if ok else "err",
                    f"[локально] прокси: {what}" + ("" if ok else " — ошибка реестра"))
                return self._send(200, {"ok": ok, "error": None if ok else "Ошибка записи в реестр"})
        except ValueError as e:
            return self._send(200, {"ok": False, "error": str(e)})
        except Exception as e:
            log("err", f"Ошибка сервера: {e}")
            return self._send(500, {"ok": False, "error": str(e)})
        self._send(404, {"ok": False, "error": "Не найдено"})


class SingleServer(ThreadingHTTPServer):
    # На Windows SO_REUSEADDR (его включает http.server по умолчанию) разрешает ДВУМ процессам
    # слушать один порт, и вторая копия не получала бы ошибку «порт занят». Отключаем:
    # теперь вторая копия честно падает на bind и выходит, остаётся ровно один сервер.
    allow_reuse_address = False
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description="ProxyTool — мультиинструмент для прокси")
    ap.add_argument("--host", default="127.0.0.1",
                    help="адрес прослушивания (по умолчанию 127.0.0.1 — только этот компьютер)")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--console", action="store_true", help="дублировать журнал и изменения в консоль")
    ap.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    ap.add_argument("--respect-stop", action="store_true",
                    help="не запускаться, если сервер остановлен вручную (метка stopped.flag); "
                         "нужен для сторожевой задачи планировщика")
    a = ap.parse_args()
    global CONSOLE
    CONSOLE = a.console

    if a.respect_stop and os.path.exists(STOP_FLAG):
        sys.exit(0)   # пользователь остановил сервер через ProxyTool.bat (0) — не поднимаем заново

    if a.host in ("127.0.0.1", "localhost"):
        Handler.allowed_hosts = {f"127.0.0.1:{a.port}", f"localhost:{a.port}"}
    else:
        print("!!! ВНИМАНИЕ: сервер открыт для сети и не защищён паролем.")

    try:
        srv = SingleServer((a.host, a.port), Handler)
    except OSError as e:
        # скорее всего ProxyTool уже запущен — это не ошибка (код 0, чтобы планировщик не перезапускал)
        print(f"Порт {a.port} занят или недоступен: {e}")
        log("warn", f"Порт {a.port} занят — вторая копия не запущена ({e})")
        sys.exit(0)

    try:  # обычный запуск (вход в Windows, ProxyTool.bat → 1) снимает метку ручной остановки
        os.remove(STOP_FLAG)
    except OSError:
        pass

    url = f"http://127.0.0.1:{a.port}"
    print(f"ProxyTool запущен: {url}   (остановка: Ctrl+C)")
    print(f"Данные: {DATA_DIR}")
    if not is_admin():
        print("Примечание: запущено без прав администратора — удалённые операции могут не работать.")
    log("info", f"ProxyTool запущен ({a.host}:{a.port})")
    db_init()
    try:
        cur = load_settings()
        if cur.get("mon_every") == "10":          # прежнее значение по умолчанию
            save_settings({"mon_every": "2"})
    except Exception:
        pass
    write_change_log(f"{'#' * 78}\n{datetime.now():%Y-%m-%d %H:%M:%S} | ProxyTool запущен | "
                     f"администратор: {'да' if is_admin() else 'НЕТ'} | наблюдение за proxy и hosts активно\n\n")
    MON.start()
    restore_auto()
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        MON.stop.set()
        MON.kick.set()
        AUTO.stop(persist=False)   # выход программы: состояние автообновления не сбрасываем
        srv.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception:  # без консоли (pythonw) ошибку иначе не увидеть
        import traceback
        _ensure_dir()
        try:
            with open(CRASH_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n--- {datetime.now():%Y-%m-%d %H:%M:%S} ---\n{traceback.format_exc()}")
        except OSError:
            pass
        sys.exit(1)
