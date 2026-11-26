#!/usr/bin/env python3
"""clipsync — общий буфер обмена компьютера и Android-телефонов.

Связь: телефон ⇄ сервер ⇄ компьютер, плюс напрямую по кабелю (adb reverse).
Подробности — в README.md. Запускается через ./clipsync (из .venv проекта).
"""

import argparse
import asyncio
import hashlib
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))

import relay  # noqa: E402  протокол общий с сервером
import sync  # noqa: E402

VENV = os.path.join(ROOT, ".venv")
CONF = os.path.join(ROOT, "config.env")
AGENT_JAR = os.path.join(VENV, "share", "clipsync-agent.jar")
SCRCPY_JAR = os.path.join(VENV, "share", "scrcpy-server.jar")
PHONE_DIR = "/data/local/tmp/clipsync"
AGENT_NAME = "clipsync-agent"
DEFAULTS = {
    "SERVER": "",
    "SECRET": "",
    "USB_PORT": "27360",
    "PHONES": "",
    "CLIPBOARD": "auto",
    "NAME": "",
    "SHARE_DIR": "~/Downloads/share",
    "PHONE_SHARE_DIR": "/sdcard/Download/share",
    "FILE_MAX_MB": "2048",
}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------- настройки ----------

def load_config(path=CONF):
    conf = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                conf[k.strip()] = v
    for k in DEFAULTS:  # переменные окружения CLIPSYNC_* важнее файла
        if "CLIPSYNC_" + k in os.environ:
            conf[k] = os.environ["CLIPSYNC_" + k]
    conf["NAME"] = conf["NAME"] or socket.gethostname()
    return conf


def save_config_value(key, value, path=CONF):
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path + ".tmp", 0o600)
    os.replace(path + ".tmp", path)


def parse_hostport(s):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"SERVER должен быть вида адрес:порт, а не «{s}»")
    return host.strip("[]"), int(port)


# ---------- буфер обмена ПК ----------

class Clipboard:
    """Чтение/запись буфера обмена и уведомления об изменениях."""

    def __init__(self, kind):
        self.kind = kind

    @staticmethod
    def detect(setting):
        if setting.startswith("file:"):
            return FileClipboard(setting[5:])
        fix_display_env()
        if setting in ("auto", "wayland") and os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
            return WaylandClipboard()
        if setting in ("auto", "x11") and os.environ.get("DISPLAY") and shutil.which("xclip"):
            return X11Clipboard()
        raise RuntimeError("не найден буфер обмена: нужен wl-clipboard (Wayland) или xclip (X11) "
                           "и графический сеанс")


def fix_display_env():
    """Служба systemd может стартовать без WAYLAND_DISPLAY/DISPLAY — ищем сокеты сами."""
    run = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not os.environ.get("WAYLAND_DISPLAY") and os.path.isdir(run):
        socks = sorted(n for n in os.listdir(run) if n.startswith("wayland-") and not n.endswith(".lock"))
        if socks:
            os.environ["WAYLAND_DISPLAY"] = socks[0]
    if not os.environ.get("DISPLAY") and os.path.exists("/tmp/.X11-unix/X0"):
        os.environ["DISPLAY"] = ":0"


async def run_cmd(*cmd, data=None, timeout=10):
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(data), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 1, b""
    return proc.returncode, out


class WaylandClipboard(Clipboard):
    def __init__(self):
        super().__init__("Wayland (wl-clipboard)")

    async def get(self):
        rc, out = await run_cmd("wl-paste", "-n", "-t", "text")
        return out.decode("utf-8", "replace") if rc == 0 else None

    async def set(self, text):
        # wl-copy уходит в фон и держит буфер; stdout не перехватываем, иначе communicate ждёт его
        proc = await asyncio.create_subprocess_exec(
            "wl-copy", stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await proc.communicate(text.encode("utf-8"))

    async def watch(self, on_change):
        while True:
            proc = await asyncio.create_subprocess_exec(
                "wl-paste", "--watch", "sh", "-c", "cat >/dev/null; echo",
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            while await proc.stdout.readline():
                await on_change()
            await proc.wait()
            log("wl-paste --watch завершился, перезапускаю")
            await asyncio.sleep(2)


class PollingClipboard(Clipboard):
    interval = 0.5

    async def watch(self, on_change):
        last = await self.get()
        while True:
            await asyncio.sleep(self.interval)
            now = await self.get()
            if now is not None and now != last:
                last = now
                await on_change()


class X11Clipboard(PollingClipboard):
    def __init__(self):
        super().__init__("X11 (xclip)")

    async def get(self):
        rc, out = await run_cmd("xclip", "-selection", "clipboard", "-o", "-t", "UTF8_STRING")
        return out.decode("utf-8", "replace") if rc == 0 else None

    async def set(self, text):
        proc = await asyncio.create_subprocess_exec(
            "xclip", "-selection", "clipboard", "-i", stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await proc.communicate(text.encode("utf-8"))


class FileClipboard(PollingClipboard):
    """Буфер обмена-файл — для тестов."""
    interval = 0.2

    def __init__(self, path):
        super().__init__(f"файл {path}")
        self.path = path

    async def get(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return None

    async def set(self, text):
        with open(self.path + ".tmp", "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(self.path + ".tmp", self.path)


# ---------- телефоны (adb) ----------

def adb_bin():
    return shutil.which("adb") or os.path.join(VENV, "platform-tools", "adb")


def adb(serial, *args, timeout=30, check=True):
    cmd = [adb_bin()] + (["-s", serial] if serial else []) + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args[:2])}: {(r.stderr or r.stdout).strip()}")
    return r.stdout


def adb_devices():
    try:
        out = adb(None, "devices", timeout=10)
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return {}
    devs = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devs[parts[0]] = parts[1]
    return devs


def agent_conf(conf, serial, model):
    auth, enc = relay.derive_keys(conf["SECRET"])
    lines = [
        f"auth={auth.hex()}",
        f"enc={enc.hex()}",
        f"server={conf['SERVER']}",
        f"usb_port={conf['USB_PORT']}",
        f"name={model or serial}",
        f"log={PHONE_DIR}/agent.log",
        f"share_dir={conf['PHONE_SHARE_DIR']}",
        f"state={PHONE_DIR}/share.state",
        f"file_max_mb={conf['FILE_MAX_MB']}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def phone_state(serial):
    """(stamp на телефоне, запущен ли агент)."""
    out = adb(serial, "shell", f"cat {PHONE_DIR}/stamp 2>/dev/null; echo; pidof {AGENT_NAME} || true", timeout=15)
    lines = out.splitlines()
    stamp = lines[0].strip() if lines else ""
    running = any(line.strip() and line.strip()[0].isdigit() for line in lines[1:])
    return stamp, running


def phone_deploy(conf, serial, force=False):
    """Ставит/обновляет агент на телефоне и запускает его. Возвращает True, если запускали."""
    model = adb(serial, "shell", "getprop ro.product.model", timeout=15).strip()
    cfg = agent_conf(conf, serial, model)
    h = hashlib.sha256()
    for path in (AGENT_JAR, SCRCPY_JAR):
        with open(path, "rb") as f:
            h.update(f.read())
    h.update(cfg)
    stamp = h.hexdigest()[:16]
    have, running = phone_state(serial)
    if have == stamp and running and not force:
        return False
    tmp = os.path.join(VENV, "run", f"agent-{serial}.conf")
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    with open(tmp, "wb") as f:
        f.write(cfg)
    os.chmod(tmp, 0o600)
    try:
        adb(serial, "shell", f"mkdir -p {PHONE_DIR} && chmod 700 {PHONE_DIR}")
        adb(serial, "push", AGENT_JAR, f"{PHONE_DIR}/agent.jar")
        adb(serial, "push", SCRCPY_JAR, f"{PHONE_DIR}/scrcpy.jar")
        adb(serial, "push", tmp, f"{PHONE_DIR}/agent.conf")
    finally:
        os.remove(tmp)
    d = PHONE_DIR
    adb(serial, "shell",
        f"chmod 600 {d}/agent.conf; echo {stamp} > {d}/stamp; "
        f"for p in $(pidof {AGENT_NAME}); do kill $p; done; "
        f"CLASSPATH={d}/agent.jar:{d}/scrcpy.jar setsid nohup app_process / --nice-name={AGENT_NAME} "
        f"clipsync.Agent {d}/agent.conf </dev/null >{d}/agent.err 2>&1 &")
    time.sleep(1.5)
    _, running = phone_state(serial)
    if not running:
        err = adb(serial, "shell", f"tail -n 5 {d}/agent.err {d}/agent.log 2>/dev/null", check=False)
        raise RuntimeError(f"агент не запустился:\n{err.strip()}")
    return True


def phone_reverse(conf, serial):
    port = conf["USB_PORT"]
    if not port or port == "0":
        return
    if f"tcp:{port} tcp:{port}" not in adb(serial, "reverse", "--list", check=False):
        adb(serial, "reverse", f"tcp:{port}", f"tcp:{port}")


def phone_remove(serial):
    adb(serial, "reverse", "--remove-all", check=False)
    adb(serial, "shell", f"rm -rf {PHONE_DIR}; for p in $(pidof {AGENT_NAME}); do kill $p; done; true")


def wanted(conf, serial):
    allowed = conf["PHONES"].replace(",", " ").split()
    return not allowed or serial in allowed


async def phones_loop(conf):
    """Следит за телефонами по кабелю: настраивает агент и adb reverse."""
    if not os.path.exists(adb_bin()):
        log("adb не найден — телефоны по кабелю не настраиваются")
        return
    known, failed = {}, {}
    while True:
        devs = await asyncio.to_thread(adb_devices)
        for serial, state in devs.items():
            if not wanted(conf, serial):
                continue
            if state == "unauthorized" and known.get(serial) != state:
                log(f"{serial}: подтвердите отладку по USB на экране телефона")
            if state == "device" and (known.get(serial) != "device" or time.time() - failed.get(serial, 0) > 30):
                try:
                    started = await asyncio.to_thread(phone_deploy, conf, serial)
                    await asyncio.to_thread(phone_reverse, conf, serial)
                    failed.pop(serial, None)
                    if started:
                        log(f"{serial}: агент установлен и запущен")
                    elif known.get(serial) != "device":
                        log(f"{serial}: подключён, агент уже работает")
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                    failed[serial] = time.time()
                    log(f"{serial}: не удалось настроить: {e}")
                    continue
            elif state == "device":
                # переподключение adb сбрасывает reverse — проверяем раз в цикл
                try:
                    await asyncio.to_thread(phone_reverse, conf, serial)
                except (RuntimeError, OSError, subprocess.TimeoutExpired):
                    pass
        known = {s: devs[s] for s in devs if wanted(conf, s)}
        await asyncio.sleep(3)


# ---------- команды ----------

def require_ready(conf):
    missing = [p for p in (AGENT_JAR, SCRCPY_JAR) if not os.path.exists(p)]
    if missing:
        sys.exit("Окружение не готово: ./clipsync setup")
    if not conf["SECRET"]:
        sys.exit(f"Нет SECRET в {CONF}: ./clipsync setup создаст его, или возьмите секрет с сервера")


async def cmd_run(conf):
    clipboard = Clipboard.detect(conf["CLIPBOARD"])
    share = os.path.expanduser(conf["SHARE_DIR"]) if conf["SHARE_DIR"] else None
    run_dir = os.environ.get("CLIPSYNC_RUN_DIR") or os.path.join(VENV, "run")
    os.makedirs(run_dir, exist_ok=True)
    hub = sync.Hub(conf["NAME"], conf["SECRET"], clipboard, share,
                   os.path.join(run_dir, "share-state.json"), int(conf["FILE_MAX_MB"]))
    text = await clipboard.get()
    if text:
        hub.current = sync.Clip(bytes(16), 0, text)  # ts=0: не рассылаем то, что было до запуска
    log(f"clipsync: «{conf['NAME']}», буфер обмена: {clipboard.kind}, общая папка: {share or 'выключена'}")
    tasks = [asyncio.create_task(clipboard.watch(hub.on_local_change)), asyncio.create_task(hub.pinger())]
    if conf["SERVER"]:
        host, port = parse_hostport(conf["SERVER"])
        hub.add_link("Сервер", host, port)
    else:
        log("SERVER не задан — только по кабелю")
    if conf["USB_PORT"] and conf["USB_PORT"] != "0":
        # встроенный relay: к нему по adb reverse подключаются телефоны, и этот ПК тоже
        port = int(conf["USB_PORT"])
        usb = relay.Relay([hub.auth_key], os.path.join(run_dir, "usb-store"), int(conf["FILE_MAX_MB"]), quiet=True)
        server = await asyncio.start_server(usb.handle, "127.0.0.1", port)
        tasks.append(asyncio.create_task(server.serve_forever()))
        hub.add_link("Кабель", "127.0.0.1", port)
        if os.environ.get("CLIPSYNC_NO_ADB") != "1":
            tasks.append(asyncio.create_task(phones_loop(conf)))
    tasks += [asyncio.create_task(link.run()) for link in hub.links]
    if hub.files:
        tasks.append(asyncio.create_task(hub.files.scan_loop()))
    await asyncio.gather(*tasks)


def check_server(conf):
    host, port = parse_hostport(conf["SERVER"])

    async def probe():
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
        try:
            auth = relay.derive_keys(conf["SECRET"])[0]
            ch = await asyncio.wait_for(relay.client_handshake(reader, writer, auth, conf["NAME"] + " (проверка)"), 5)
            ftype, payload = await asyncio.wait_for(ch.recv(), 5)
            while ftype != relay.T_FINDEX:
                ftype, payload = await asyncio.wait_for(ch.recv(), 5)
            return len(payload) // relay.FINDEX_ENT.size
        finally:
            writer.close()

    try:
        n = asyncio.run(probe())
        return f"доступен, секрет подходит, файлов на сервере: {n}"
    except PermissionError as e:
        return str(e)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as e:
        return f"недоступен ({e or type(e).__name__})"


def cmd_status(conf):
    print(f"Проект:     {ROOT}")
    print(f"Настройки:  {CONF}{'' if os.path.exists(CONF) else ' (нет)'}")
    print(f"Имя:        {conf['NAME']}")
    print(f"Секрет:     {'задан' if conf['SECRET'] else 'НЕ ЗАДАН'}")
    if conf["SERVER"]:
        print(f"Сервер:     {conf['SERVER']} — {check_server(conf) if conf['SECRET'] else 'нет секрета'}")
    else:
        print("Сервер:     не задан (только по кабелю)")
    print(f"По кабелю:  {'выключено' if conf['USB_PORT'] in ('', '0') else 'порт ' + conf['USB_PORT']}")
    print(f"Папка ПК:   {os.path.expanduser(conf['SHARE_DIR']) if conf['SHARE_DIR'] else 'выключена'}")
    print(f"Папка тел.: {conf['PHONE_SHARE_DIR'] or 'выключена'}")
    try:
        cb = Clipboard.detect(conf["CLIPBOARD"])
        print(f"Буфер:      {cb.kind}")
    except RuntimeError as e:
        print(f"Буфер:      {e}")
    r = subprocess.run(["systemctl", "--user", "is-active", "clipsync"], capture_output=True, text=True) \
        if shutil.which("systemctl") else None
    print(f"Служба:     {r.stdout.strip() if r else 'systemd нет'}")
    if os.path.exists(adb_bin()):
        devs = adb_devices()
        if not devs:
            print("Телефоны:   по кабелю не подключены")
        for serial, state in devs.items():
            if state != "device":
                print(f"Телефон:    {serial} — {state}")
                continue
            try:
                _, running = phone_state(serial)
                print(f"Телефон:    {serial} — агент {'работает' if running else 'не запущен'}"
                      f"{'' if wanted(conf, serial) else ' (не в PHONES)'}")
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                print(f"Телефон:    {serial} — {e}")
    else:
        print("adb:        не найден")


def pick_phones(serial):
    if serial:
        return [serial]
    devs = [s for s, st in adb_devices().items() if st == "device"]
    if not devs:
        sys.exit("Нет подключённых телефонов (adb devices)")
    return devs


def main():
    ap = argparse.ArgumentParser(prog="clipsync")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run", help="запустить синхронизацию в терминале")
    sub.add_parser("status", help="состояние")
    p = sub.add_parser("phone-setup", help="(пере)установить агент на телефон сейчас")
    p.add_argument("serial", nargs="?")
    p = sub.add_parser("phone-remove", help="удалить агент с телефона")
    p.add_argument("serial", nargs="?")
    p = sub.add_parser("phone-log", help="журнал агента на телефоне")
    p.add_argument("serial", nargs="?")
    sub.add_parser("gen-secret", help="напечатать новый секрет")
    p = sub.add_parser("config", help="записать параметр в config.env")
    p.add_argument("key")
    p.add_argument("value")
    p = sub.add_parser("server", help="запустить relay-сервер здесь (для проверки)")
    p.add_argument("--port", type=int, default=relay.DEFAULT_PORT)
    a = ap.parse_args()
    conf = load_config()

    if a.cmd == "run":
        require_ready(conf)
        try:
            asyncio.run(cmd_run(conf))
        except KeyboardInterrupt:
            print()
        except RuntimeError as e:
            sys.exit(f"Ошибка: {e}")
    elif a.cmd == "status":
        cmd_status(conf)
    elif a.cmd == "phone-setup":
        require_ready(conf)
        for s in pick_phones(a.serial):
            phone_deploy(conf, s, force=True)
            phone_reverse(conf, s)
            print(f"{s}: агент установлен и запущен")
    elif a.cmd == "phone-remove":
        for s in pick_phones(a.serial):
            phone_remove(s)
            print(f"{s}: агент удалён")
    elif a.cmd == "phone-log":
        for s in pick_phones(a.serial):
            print(f"== {s}")
            print(adb(s, "shell", f"cat {PHONE_DIR}/agent.log {PHONE_DIR}/agent.err 2>/dev/null | tail -n 40",
                      check=False))
    elif a.cmd == "gen-secret":
        print(relay.gen_secret())
    elif a.cmd == "config":
        if a.key not in DEFAULTS:
            sys.exit(f"Неизвестный параметр {a.key}; есть: {', '.join(DEFAULTS)}")
        save_config_value(a.key, shlex.quote(a.value) if a.value else "")
        print(f"{a.key} записан в {CONF}")
    elif a.cmd == "server":
        if not conf["SECRET"]:
            sys.exit("Нет SECRET в config.env")
        relay.main(["serve", "--port", str(a.port), "--secret", conf["SECRET"]])
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
