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
import ctypes
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
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

DEFAULT_SETTINGS = {
    "targets": [],          # список строк: "10.0.0.5", "10.0.0.1-10.0.0.50", "10.0.0.0/24", "localhost"
    "entries": "",          # исключения прокси (через ; или с новой строки)
    "workers": "50",
    "timeout": "5",
    "auto_every": "1",
    "auto_unit": "soat",    # soat = часы, daqiqa = минуты (внутренние значения)
    "lp_server": "",
    "lp_override": "",
    "theme": "",            # "", "light" или "dark" (пусто = как в системе)
    "sound": "1",           # "1" — звуки включены, "0" — выключены
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


def clean_settings(src):
    """Оставляет только известные ключи нужного типа и размера."""
    out = {}
    for key, default in DEFAULT_SETTINGS.items():
        if key not in src:
            continue
        v = src[key]
        if isinstance(default, list):
            if isinstance(v, list):
                out[key] = [str(x)[:200] for x in v[:2000]]
        elif isinstance(v, (str, int, float)):
            out[key] = str(v)[:20000]
    if out.get("auto_unit") not in (None, "soat", "daqiqa"):
        out["auto_unit"] = "soat"
    if out.get("theme") not in (None, "", "light", "dark"):
        out["theme"] = ""
    if out.get("sound") not in (None, "0", "1"):
        out["sound"] = "1"
    return out


def save_settings(new):
    """Атомарная запись: сначала во временный файл, затем замена."""
    with _SETTINGS_LOCK:
        cur = load_settings()
        cur.update(clean_settings(new))
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


def log(level, msg):
    """level: ok | err | warn | skip | head | info"""
    global _LOG_SEQ
    ts = datetime.now().strftime("%H:%M:%S")
    with _LOG_LOCK:
        _LOG_SEQ += 1
        _LOG.append({"id": _LOG_SEQ, "t": ts, "lv": level, "msg": msg})
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


def _run(args, timeout=8):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        return _decode_best(r.stdout), r.returncode
    except Exception:
        return "", -1


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
    for p in (445, 135):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, p))
            s.close()
            if rc == 0:
                return True
        except Exception:
            pass
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


def proxy_add(ip, entries, timeout=5.0):
    entries = [e.strip() for e in entries if e.strip()]
    if not entries:
        return True, "Нет записей для добавления"
    if is_local(ip):
        cur = _local_get_override()
        if cur is None:
            return False, "Не удалось открыть локальный реестр"
        new_val, added = _merge(cur, entries)
        if not added:
            return True, f"{NOCHG}: все записи уже есть"
        if _local_set_override(new_val):
            return True, f"[локально] Добавлено: {', '.join(added)}"
        return False, "Ошибка записи в локальный реестр (нет прав?)"

    sids, err = _remote_prepare(ip, timeout)
    if err:
        return False, err
    all_added, fail = [], 0
    for sid in sids:
        cur = _remote_get_override(ip, sid, timeout)
        new_val, added = _merge(cur, entries)
        if not added:
            continue
        if _remote_set_override(ip, sid, new_val, timeout):
            all_added.extend(added)
        else:
            fail += 1
    if all_added:
        return True, f"Добавлено: {', '.join(sorted(set(all_added)))}"
    if fail:
        return False, "Ошибка записи в реестр"
    return True, f"{NOCHG}: все записи уже есть"


def proxy_remove(ip, entries, timeout=5.0):
    entries = [e.strip() for e in entries if e.strip()]
    if not entries:
        return True, "Нет записей для удаления"
    if is_local(ip):
        cur = _local_get_override()
        if cur is None:
            return False, "Не удалось открыть локальный реестр"
        new_val, removed = _unmerge(cur, entries)
        if not removed:
            return True, f"{NOCHG}: совпадений нет"
        if _local_set_override(new_val):
            return True, f"[локально] Удалено: {', '.join(removed)}"
        return False, "Ошибка записи в локальный реестр (нет прав?)"

    sids, err = _remote_prepare(ip, timeout)
    if err:
        return False, err
    all_rm, fail = [], 0
    for sid in sids:
        cur = _remote_get_override(ip, sid, timeout)
        new_val, removed = _unmerge(cur, entries)
        if not removed:
            continue
        if _remote_set_override(ip, sid, new_val, timeout):
            all_rm.extend(removed)
        else:
            fail += 1
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
    ok = True
    if server is not None:
        ok &= _local_set_value("ProxyServer", server)
    if override is not None:
        ok &= _local_set_value("ProxyOverride", override)
    if enable is not None:
        ok &= _local_set_value("ProxyEnable", 1 if enable else 0, winreg.REG_DWORD)
    _broadcast_settings_change()
    return bool(ok)


# ═════════════════════════════════════════════════════════════════════════════
#  ЗАДАЧИ и АВТО-ТАЙМЛАЙН
# ═════════════════════════════════════════════════════════════════════════════
TOOLS = {
    "proxy_add":    ("Прокси: добавить",  lambda ip, p, t: proxy_add(ip, p["entries"], t)),
    "proxy_remove": ("Прокси: удалить",   lambda ip, p, t: proxy_remove(ip, p["entries"], t)),
    "proxy_read":   ("Прокси: прочитать", lambda ip, p, t: proxy_read(ip, t)),
}

JOB = {"running": False, "name": "", "done": 0, "total": 0, "ok": 0, "skip": 0, "err": 0}
_JOB_LOCK = threading.Lock()


def run_over_targets(tool, ips, params, workers, timeout, prefix=""):
    title, fn = TOOLS[tool]
    log("head", f"== {prefix}{title} | адресов: {len(ips)} | потоков: {workers} ==")
    ok_n = skip_n = err_n = 0

    def task(ip):
        try:
            ok, msg = fn(ip, params, timeout)
        except Exception as e:  # один адрес не должен ронять весь цикл
            ok, msg = False, f"Исключение: {e}"
        return ip, ok, msg

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(task, ip) for ip in ips]
        for f in as_completed(futs):
            ip, ok, msg = f.result()
            if not ok:
                lv = "err"; err_n += 1
            elif NOCHG in msg:
                lv = "skip"; skip_n += 1
            else:
                lv = "ok"; ok_n += 1
            log(lv, f"{ip:16s} {msg}")
            with _JOB_LOCK:
                JOB["done"] += 1
                JOB["ok"], JOB["skip"], JOB["err"] = ok_n, skip_n, err_n
    log("head", f"-> успешно: {ok_n} | без изменений: {skip_n} | ошибок: {err_n}")
    return ok_n, skip_n, err_n


def start_job(tool, ips, params, workers, timeout):
    with _JOB_LOCK:
        if JOB["running"]:
            return False, "Уже выполняется другая задача"
        JOB.update(running=True, name=TOOLS[tool][0], done=0, total=len(ips), ok=0, skip=0, err=0)

    def runner():
        try:
            run_over_targets(tool, ips, params, workers, timeout)
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
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def start(self, cfg, raw=None, restored=False):
        """raw — исходные параметры запроса: их сохраняем в AppData, чтобы после
        перезапуска/перезагрузки автообновление продолжилось само."""
        with self._lock:
            if self.running:
                return False, "Автообновление уже запущено"
            self.running, self.cycle, self.cfg, self.last = True, 0, cfg, ""
            self.initial_delay = 15 if restored else 0   # дать сети подняться после загрузки
            self._stop.clear()
        if not restored:
            save_auto_state(True, raw)
        threading.Thread(target=self._loop, daemon=True).start()
        unit = "ч" if cfg["unit"] == "soat" else "мин"
        src = "ВОССТАНОВЛЕНО после перезапуска" if restored else "ЗАПУЩЕНО"
        log("info", f"Автообновление {src}: каждые {cfg['every']} {unit} ({TOOLS[cfg['tool']][0]})")
        return True, "Запущено"

    def stop(self, persist=True):
        """persist=False — это выход программы, а не команда пользователя:
        флаг «работало» остаётся в файле, и при следующем старте цикл возобновится."""
        with self._lock:
            was = self.running
            self.running = False
            self.next_ts = None
        self._stop.set()
        if persist:
            save_auto_state(False, None)
            if was:
                log("info", "Автообновление ОСТАНОВЛЕНО")

    def _loop(self):
        c = self.cfg
        secs = max(1, int(c["every"])) * (3600 if c["unit"] == "soat" else 60)
        if self.initial_delay and self._stop.wait(self.initial_delay):
            self.running = False
            return
        while self.running:
            self.cycle += 1
            with _JOB_LOCK:
                busy = JOB["running"]
            if busy:
                log("warn", f"Цикл №{self.cycle}: выполняется другая задача — пропущен")
            else:
                with _JOB_LOCK:
                    JOB.update(running=True, name=f"АВТО №{self.cycle}: {TOOLS[c['tool']][0]}",
                               done=0, total=len(c["ips"]), ok=0, skip=0, err=0)
                try:
                    o, s, e = run_over_targets(c["tool"], c["ips"], c["params"], c["workers"],
                                               c["timeout"], prefix=f"Цикл №{self.cycle} | ")
                    self.last = f"№{self.cycle}: обновлено {o}, без изменений {s}, ошибок {e}"
                finally:
                    with _JOB_LOCK:
                        JOB["running"] = False
            if not self.running:
                break
            self.next_ts = (datetime.now() + timedelta(seconds=secs)).timestamp()
            if self._stop.wait(secs):
                break
        self.running = False
        self.next_ts = None

    def state(self):
        return {"running": self.running, "cycle": self.cycle, "next_ts": self.next_ts,
                "last": self.last,
                "cfg": None if not self.cfg else {
                    "tool": self.cfg["tool"], "every": self.cfg["every"], "unit": self.cfg["unit"],
                    "targets": len(self.cfg["ips"])}}


AUTO = AutoTimeline()


def build_request(body):
    tool = body.get("tool", "")
    if tool not in TOOLS:
        raise ValueError("Неизвестная операция")
    targets = body.get("targets", "")
    if isinstance(targets, list):
        targets = "\n".join(str(t) for t in targets)
    ips = parse_targets(targets)
    if not ips:
        raise ValueError("Добавьте хотя бы один адрес")
    entries = split_entries(body.get("entries", ""))
    if tool in ("proxy_add", "proxy_remove") and not entries:
        raise ValueError("Список исключений пуст")
    try:
        workers = min(200, max(1, int(body.get("workers", 50))))
    except (TypeError, ValueError):
        workers = 50
    try:
        timeout = max(1.0, float(body.get("timeout", 5)))
    except (TypeError, ValueError):
        timeout = 5.0
    return tool, ips, {"entries": entries}, workers, timeout


def auto_cfg_from_body(body):
    """-> (cfg для AutoTimeline, raw для сохранения в AppData)"""
    tool, ips, params, workers, timeout = build_request(body)
    if tool != "proxy_add":
        raise ValueError("Эта операция не подходит для автообновления")
    unit = body.get("unit") if body.get("unit") in ("soat", "daqiqa") else "soat"
    try:
        every = max(1, int(body.get("every", 1)))
    except (TypeError, ValueError):
        every = 1
    cfg = {"tool": tool, "ips": ips, "params": params, "workers": workers,
           "timeout": timeout, "every": every, "unit": unit}
    targets = body.get("targets", "")
    if isinstance(targets, list):
        targets = [str(t)[:200] for t in targets[:2000]]
    raw = {"tool": tool, "targets": targets, "entries": str(body.get("entries", ""))[:20000],
           "workers": workers, "timeout": timeout, "every": every, "unit": unit}
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
  --ok:#17825a; --err:#c0303f; --warn:#9a6a00; --skip:#6a7487; --head:#3d6df5;
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
  --ok:#4fd39a; --err:#ff7b88; --warn:#f0c15a; --skip:#8d97ab; --head:#8aa8ff;}}
:root[data-theme=dark]{
  color-scheme:dark;
  --bg:#262b35; --hi:#323946; --lo:#1a1e26;
  --text:#e3e8f2; --sub:#9aa5ba; --acc:#6f95ff;
  --ok:#4fd39a; --err:#ff7b88; --warn:#f0c15a; --skip:#8d97ab; --head:#8aa8ff;}
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
.li .cnt{color:var(--sub);font-size:12px;white-space:nowrap}
.li button{width:26px;height:26px;border:0;border-radius:50%;background:var(--bg);color:var(--err);
  box-shadow:var(--sink-s);cursor:pointer;line-height:1;font-size:12px;flex:0 0 auto;position:relative;overflow:hidden;transition:transform .12s}
.li button:active{transform:scale(.86)}
.empty{color:var(--sub);font-size:13px;margin:auto;text-align:center;padding:10px}

/* ── главный выключатель ── */
.power-card{flex:1 1 0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:22px;text-align:center}
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
@media (max-width:1000px),(max-height:600px){
  html,body{overflow:auto}
  .app{height:auto;min-height:100vh}
  main{display:flex;flex-direction:column}
  .col{overflow:visible}
  .logcard{min-height:380px;flex:none}
  .card.grow{flex:none}
  header{flex-wrap:wrap}
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
    <button role="tab" data-t="local" aria-selected="false">Локальный прокси</button>
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
          <button class="btn main" id="b_add">Добавить</button>
          <button class="btn danger" id="b_rm">Удалить</button>
          <button class="btn" id="b_rd">Прочитать текущие</button>
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
          <button class="btn main" id="a_start">Запустить</button>
          <button class="btn danger" id="a_stop" disabled>Остановить</button>
        </div>
        <div class="kv" id="a_state" style="margin-top:10px">Остановлено</div>
      </div>
    </div>
  </section>

  <!-- ─────────── вкладка: локальный прокси ─────────── -->
  <section id="tab-local" class="tab hide">
    <div class="col">
      <div class="card power-card">
        <button class="power" id="power" aria-pressed="false" aria-label="Включить или выключить прокси">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/></svg>
        </button>
        <div class="power-info"><b id="lp_state">…</b><span id="lp_view"></span></div>
      </div>
    </div>
    <div class="col">
      <div class="card grow">
        <h2>Параметры</h2>
        <label for="lp_server" style="margin-top:0">Сервер прокси (хост:порт)</label>
        <input type="text" id="lp_server" placeholder="proxy.example.local:8080" autocomplete="off">
        <label for="lp_override">Исключения</label>
        <textarea id="lp_override"></textarea>
        <div class="btns">
          <button class="btn main" id="lp_save">Сохранить параметры</button>
          <button class="btn" id="lp_reload">Обновить</button>
        </div>
      </div>
    </div>
  </section>

  <!-- ─────────── общая колонка: задача + журнал ─────────── -->
  <div class="col">
    <div class="card">
      <h2 style="margin-bottom:6px">Текущая задача</h2>
      <div class="kv" id="jobtxt">Нет активных задач</div>
      <div class="track"><i id="jobbar"></i></div>
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
<div id="toast" role="alert"></div>

<script>
const $=id=>document.getElementById(id);
const H={'X-Requested-With':'ProxyTool','Content-Type':'application/json'};
const api=(u,b)=>fetch(u,b===undefined?{headers:H}:{method:'POST',headers:H,body:JSON.stringify(b)}).then(r=>r.json());
let S={targets:[],entries:'',workers:'50',timeout:'5',auto_every:'1',auto_unit:'soat',lp_server:'',lp_override:'',theme:'',sound:'1'};
let lastId=0, all=[], lpOn=0, toastT, popIdx=-1;

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
function renderChips(){const box=$('chips');box.textContent='';let total=0;const pi=popIdx;popIdx=-1;
  if(!S.targets.length){const e=document.createElement('div');e.className='empty';e.textContent='Список пуст. Добавьте диапазон или адрес.';box.append(e)}
  S.targets.forEach((t,i)=>{const f=info(t);total+=f.n;
    const c=document.createElement('div');c.className='li'+(i===pi?' pop':'');
    const a=document.createElement('span');a.className='addr';a.textContent=f.text;a.title=f.text;
    const n=document.createElement('span');n.className='cnt';n.textContent=f.n+' '+plural(f.n,['адрес','адреса','адресов']);
    const b=document.createElement('button');b.textContent='✕';b.title='Убрать';b.setAttribute('aria-label','Убрать '+f.text);
    b.onclick=()=>{snd('del');c.classList.add('out');setTimeout(()=>{const k=S.targets.indexOf(t);if(k>=0)S.targets.splice(k,1);renderChips();save()},190)};c.append(a,n,b);box.append(c)});
  $('tcount').textContent=S.targets.length?`Записей: ${S.targets.length}, всего адресов: ${total}`:''}
function addTarget(v){if(!S.targets.includes(v)){snd('add');S.targets.push(v);popIdx=S.targets.length-1;renderChips();save();const l=$('chips');l.scrollTop=l.scrollHeight}}
$('addRange').onclick=()=>{const a=$('ip_from').value.trim(),b=$('ip_to').value.trim();
  if(!a)return toast('Введите начальный IP');
  if(b){if(!okIp(a)||!okIp(b))return toast('Диапазон задаётся двумя корректными IPv4-адресами');addTarget(a+'-'+b)}
  else addTarget(a);
  $('ip_from').value='';$('ip_to').value='';$('ip_from').focus()};
['ip_from','ip_to'].forEach(id=>$(id).addEventListener('keydown',e=>{if(e.key==='Enter')$('addRange').click()}));
$('addLocal').onclick=()=>addTarget('localhost');

/* ── вкладки ── */
function moveThumb(instant){const b=document.querySelector('#seg [aria-selected=true]'),t=$('segThumb');if(!b)return;
  if(instant)t.style.transition='none';
  t.style.width=b.offsetWidth+'px';t.style.transform=`translateX(${b.offsetLeft}px)`;
  if(instant)requestAnimationFrame(()=>requestAnimationFrame(()=>t.style.transition=''))}
addEventListener('resize',()=>moveThumb(true));
$('seg').onclick=e=>{const t=e.target.dataset.t;if(!t)return;
  document.querySelectorAll('#seg button').forEach(b=>b.setAttribute('aria-selected',b===e.target));moveThumb();
  $('tab-proxy').classList.toggle('hide',t!=='proxy');$('tab-local').classList.toggle('hide',t!=='local');
  if(t==='local')lpLoad()};

/* ── запуск операций ── */
const req=tool=>({tool,targets:S.targets,entries:$('entries').value,workers:$('workers').value,timeout:$('timeout').value});
function flash(){const c=$('jobtxt').closest('.card');c.classList.remove('flash');void c.offsetWidth;c.classList.add('flash')}
async function run(tool){const r=await api('/api/run',req(tool));if(!r.ok)toast(r.error);else{flash();snd('ok')}poll()}
$('b_add').onclick=()=>run('proxy_add');$('b_rm').onclick=()=>run('proxy_remove');$('b_rd').onclick=()=>run('proxy_read');
$('a_start').onclick=async()=>{const p=req('proxy_add');p.every=$('a_every').value;p.unit=ddUnit.get();
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
  for(const e of all){if(l&&e.lv!==l)continue;if(f&&!e.msg.toLowerCase().includes(f))continue;
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
  $('admin').textContent=s.admin?'Администратор':'Без прав администратора';$('admin').className='pill '+(s.admin?'good':'bad');
  const j=s.job;$('jobb').textContent=j.running?'Работает':'Свободен';$('jobb').className='pill '+(j.running?'good':'');
  $('jobtxt').textContent=j.total?`${j.name}: ${j.done} из ${j.total}\nуспешно ${j.ok} · без изменений ${j.skip} · ошибок ${j.err}`:'Нет активных задач';
  $('jobbar').style.width=j.total?Math.round(100*j.done/j.total)+'%':'0';
  const a=s.auto;$('a_start').disabled=a.running;$('a_stop').disabled=!a.running;
  $('a_state').textContent=a.running
    ?`Работает, цикл №${a.cycle}`+(a.next_ts?`, следующий в ${fmt(a.next_ts)}`:' (выполняется)')+(a.last?`\nПоследний: ${a.last}`:'')
    :'Остановлено'+(a.last?`\nПоследний: ${a.last}`:'');
  const g=await api('/api/logs?since='+lastId);
  if(g.logs.length){all=all.concat(g.logs);if(all.length>5000)all=all.slice(-5000);lastId=g.logs[g.logs.length-1].id;render()}
}catch(e){$('jobb').textContent='Нет связи с сервером';$('jobb').className='pill bad'}}

/* ── волна при нажатии ── */
document.addEventListener('pointerdown',e=>{
  const el=e.target.closest('.btn,.step,.iconbtn,.dd-btn,.li button,#seg button,.dd-list li');
  if(!el||el.disabled)return;
  snd(el.matches('#seg button')?'tab':el.matches('.dd-list li')?'pick':'click');
  if(matchMedia('(prefers-reduced-motion:reduce)').matches)return;
  const r=el.getBoundingClientRect(),s=Math.max(r.width,r.height)*2.2;
  const d=document.createElement('span');d.className='rip';
  d.style.cssText=`width:${s}px;height:${s}px;left:${e.clientX-r.left-s/2}px;top:${e.clientY-r.top-s/2}px`;
  el.append(d);d.addEventListener('animationend',()=>d.remove())},{passive:true});

/* ── старт: подгружаем данные из AppData ── */
(async()=>{try{const d=await api('/api/settings');Object.assign(S,d)}catch(e){toast('Не удалось прочитать настройки')}
  $('entries').value=S.entries;$('workers').value=S.workers;$('timeout').value=S.timeout;
  $('a_every').value=S.auto_every;ddUnit.set(S.auto_unit,true);$('lp_server').value=S.lp_server;$('lp_override').value=S.lp_override;
  if(S.theme)applyTheme(S.theme);paintSound();
  renderChips();moveThumb(true);poll();setInterval(poll,1000);
  if(location.hash==='#local')document.querySelector('[data-t=local]').click()})();
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
            return self._send(200, {"admin": is_admin(), "job": job, "auto": AUTO.state()})
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
                tool, ips, params, workers, timeout = build_request(body)
                ok, msg = start_job(tool, ips, params, workers, timeout)
                return self._send(200, {"ok": ok, "error": None if ok else msg})
            if p == "/api/auto/start":
                cfg, raw = auto_cfg_from_body(body)
                ok, msg = AUTO.start(cfg, raw)
                return self._send(200, {"ok": ok, "error": None if ok else msg})
            if p == "/api/auto/stop":
                AUTO.stop()
                return self._send(200, {"ok": True})
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
    ap.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    ap.add_argument("--respect-stop", action="store_true",
                    help="не запускаться, если сервер остановлен вручную (метка stopped.flag); "
                         "нужен для сторожевой задачи планировщика")
    a = ap.parse_args()

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
    restore_auto()
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
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
