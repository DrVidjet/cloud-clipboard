"""Ядро синхронизации на компьютере: соединения, буфер обмена, общая папка.

Та же логика реализована в агенте телефона (android/src/clipsync/Agent.java):
меняя протокол здесь, меняйте и там.
"""

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import time
from collections import OrderedDict

import relay
from relay import CHUNK, FCHUNK_HDR, FINDEX_ENT, FMETA_HDR

CLIP_AAD = b"clipsync1"
PING_INTERVAL = 25
SKIP_SUFFIXES = (".part", ".crdownload", ".tmp", ".partial", ".download")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def preview(text):
    t = text.replace("\n", "⏎")
    return repr(t[:40] + "…") + f" ({len(text)} симв.)" if len(t) > 40 else repr(t)


class Clip:
    __slots__ = ("id", "ts", "text")

    def __init__(self, cid, ts, text):
        self.id, self.ts, self.text = cid, ts, text


class Crypto:
    """Сквозное шифрование содержимого (ключ из секрета, у сервера его нет)."""

    def __init__(self, enc_key):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.key = enc_key
        self.aes = AESGCM(enc_key)

    def seal(self, plain, aad):
        nonce = secrets.token_bytes(12)
        return nonce + self.aes.encrypt(nonce, plain, aad)

    def open(self, blob, aad):
        return self.aes.decrypt(blob[:12], blob[12:], aad)

    def clip_encrypt(self, clip):
        return self.seal(clip.id + struct.pack(">Q", clip.ts) + clip.text.encode("utf-8"), CLIP_AAD)

    def clip_decrypt(self, blob):
        plain = self.open(blob, CLIP_AAD)
        return Clip(plain[:16], struct.unpack(">Q", plain[16:24])[0], plain[24:].decode("utf-8", "replace"))

    def path_key(self, path):
        return hmac.new(self.key, b"path:" + path.encode("utf-8"), hashlib.sha256).digest()


# ---------- общая папка ----------

class Entry:
    __slots__ = ("key", "ver", "ts", "sha", "size", "deleted", "mtime")

    def __init__(self, key, ver, ts, sha, size, deleted, mtime=0):
        self.key, self.ver, self.ts, self.sha = key, ver, ts, sha
        self.size, self.deleted, self.mtime = size, deleted, mtime

    def to_json(self):
        return [self.key.hex(), self.ver.hex(), self.ts, self.sha.hex(), self.size, self.deleted, self.mtime]

    @classmethod
    def from_json(cls, a):
        return cls(bytes.fromhex(a[0]), bytes.fromhex(a[1]), a[2], bytes.fromhex(a[3]), a[4], a[5], a[6])


class Incoming:
    """Принимаемый файл: части приходят по порядку и пишутся во временный файл."""

    def __init__(self, path, ver, ts, sha, size, n, tmp):
        self.path, self.ver, self.ts, self.sha, self.size, self.n = path, ver, ts, sha, size, n
        self.tmp, self.idx, self.hash = tmp, 0, hashlib.sha256()
        self.f = open(tmp, "wb")

    def discard(self):
        self.f.close()
        try:
            os.remove(self.tmp)
        except FileNotFoundError:
            pass


def valid_rel(path):
    parts = path.split("/")
    return path and "\0" not in path and not path.startswith("/") and all(p not in ("", ".", "..") for p in parts)


def skip_name(name):
    return name.startswith(".clipsync") or name.endswith(SKIP_SUFFIXES)


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.digest()


class FileSync:
    def __init__(self, hub, root, state_path, max_mb):
        self.hub, self.root, self.state_path = hub, root, state_path
        self.max_bytes = max_mb << 20
        self.state = {}   # путь → Entry
        self.by_key = {}  # key → путь
        self.rx = {}      # (link, key) → Incoming
        self.dirty = False
        os.makedirs(root, exist_ok=True)
        try:
            with open(state_path, encoding="utf-8") as f:
                for p, a in json.load(f).items():
                    self.state[p] = Entry.from_json(a)
                    self.by_key[self.state[p].key] = p
        except (FileNotFoundError, ValueError):
            pass

    @property
    def crypto(self):
        return self.hub.crypto

    def save(self):
        if not self.dirty:
            return
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({p: e.to_json() for p, e in self.state.items()}, f)
        os.replace(tmp, self.state_path)
        self.dirty = False

    def put(self, path, e):
        self.state[path] = e
        self.by_key[e.key] = path
        self.dirty = True

    def abs(self, path):
        return os.path.join(self.root, *path.split("/"))

    # --- локальные изменения ---

    def _walk(self):
        found = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".clipsync")]
            for name in filenames:
                if skip_name(name):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full, follow_symlinks=False)
                except OSError:
                    continue
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                try:
                    rel.encode("utf-8")
                except UnicodeEncodeError:
                    continue  # имя не в UTF-8 — не синхронизируем
                found[rel] = st
        return found

    async def scan_loop(self):
        while True:
            try:
                await self.scan()
            except Exception as e:  # noqa: BLE001 — сканер не должен останавливаться
                log(f"Общая папка: ошибка сканирования: {e}")
            await asyncio.sleep(2)

    async def scan(self):
        found = await asyncio.to_thread(self._walk)
        now = time.time()
        changed = []
        for rel, st in found.items():
            e = self.state.get(rel)
            if e and not e.deleted and e.size == st.st_size and e.mtime == st.st_mtime_ns:
                continue
            if now - st.st_mtime < 2:
                continue  # файл ещё пишется
            if st.st_size > self.max_bytes:
                if not e or e.mtime != st.st_mtime_ns:
                    log(f"Общая папка: {rel} больше FILE_MAX_MB — не синхронизируется")
                    self.put(rel, Entry(self.crypto.path_key(rel), bytes(16), 0, bytes(32), st.st_size, True,
                                        st.st_mtime_ns))
                continue
            if any(k[1] == (e.key if e else None) for k in self.rx):
                continue  # как раз принимаем этот файл
            sha = await asyncio.to_thread(file_sha, self.abs(rel))
            if e and not e.deleted and e.sha == sha:
                e.size, e.mtime = st.st_size, st.st_mtime_ns
                self.dirty = True
                continue
            ts = max(int(now * 1000), (e.ts + 1) if e else 0)
            ne = Entry(self.crypto.path_key(rel), secrets.token_bytes(16), ts, sha, st.st_size, False, st.st_mtime_ns)
            self.put(rel, ne)
            changed.append(rel)
            log(f"Общая папка: {rel} изменён на этом ПК")
        for rel, e in list(self.state.items()):
            if not e.deleted and rel not in found and not os.path.exists(self.abs(rel)):
                ts = max(int(now * 1000), e.ts + 1)
                self.put(rel, Entry(e.key, secrets.token_bytes(16), ts, bytes(32), 0, True))
                changed.append(rel)
                log(f"Общая папка: {rel} удалён на этом ПК")
        self.save()
        for rel in changed:
            for link in self.hub.live_links():
                link.spawn_upload(rel)

    # --- отправка ---

    def meta_payload(self, path, e):
        n = 0 if e.deleted else (e.size + CHUNK - 1) // CHUNK
        hdr = FMETA_HDR.pack(e.key, e.ver, e.ts, n)
        plain = e.sha + struct.pack(">QB", e.size, 1 if e.deleted else 0) + path.encode("utf-8")
        return hdr + self.crypto.seal(plain, b"clipsync-fmeta" + hdr), n

    async def upload(self, link, path):
        e = self.state.get(path)
        if e is None or (e.ver == bytes(16)):
            return
        meta, n = self.meta_payload(path, e)
        if e.deleted:
            link.ch.send(relay.T_FMETA, meta)
            await link.ch.drain()
            return
        try:
            with open(self.abs(path), "rb") as f:
                link.ch.send(relay.T_FMETA, meta)
                h = hashlib.sha256()
                for i in range(n):
                    data = f.read(CHUNK)
                    h.update(data)
                    hdr = FCHUNK_HDR.pack(e.key, e.ver, i)
                    if link.ch is None:
                        return
                    link.ch.send(relay.T_FCHUNK, hdr + self.crypto.seal(data, b"clipsync-fchunk" + hdr))
                    await link.ch.drain()
        except FileNotFoundError:
            return  # удалён во время отправки — сканер разошлёт удаление
        if h.digest() != e.sha:
            log(f"Общая папка: {path} изменился во время отправки — отправлю заново")

    # --- приём ---

    def on_index(self, link, payload):
        remote = {}
        for off in range(0, len(payload) - FINDEX_ENT.size + 1, FINDEX_ENT.size):
            k, ver, ts = FINDEX_ENT.unpack_from(payload, off)
            remote[k] = (ver, ts)
        for k, (ver, ts) in remote.items():
            path = self.by_key.get(k)
            e = self.state.get(path) if path else None
            if e is None or (e.ver != ver and ts > e.ts):
                link.ch.send(relay.T_FGET, k + ver)
        for path, e in self.state.items():
            if e.ver == bytes(16):
                continue
            r = remote.get(e.key)
            if r is None or (r[0] != e.ver and e.ts > r[1]):
                if not (r is None and e.deleted):
                    link.spawn_upload(path)

    def on_meta(self, link, payload):
        hdr = payload[:FMETA_HDR.size]
        k, ver, ts, n = FMETA_HDR.unpack(hdr)
        try:
            plain = self.crypto.open(payload[FMETA_HDR.size:], b"clipsync-fmeta" + hdr)
        except Exception:  # noqa: BLE001
            log(f"{link.name}: метаданные файла не расшифровались — другой SECRET?")
            return
        sha = plain[:32]
        size, deleted = struct.unpack(">QB", plain[32:41])
        path = plain[41:].decode("utf-8", "replace")
        if not valid_rel(path) or self.crypto.path_key(path) != k:
            log(f"{link.name}: недопустимое имя файла {path!r} — пропускаю")
            return
        old = self.rx.pop((link, k), None)
        if old:
            old.discard()
        e = self.state.get(path)
        if e and e.ver == ver:
            return
        if e and e.ts > ts:
            link.spawn_upload(path)  # у нас новее
            return
        full = self.abs(path)
        if deleted:
            if e and not e.deleted and os.path.exists(full):
                try:
                    st = os.stat(full)
                    if st.st_size == e.size and st.st_mtime_ns == e.mtime:
                        os.remove(full)
                        self._prune_dirs(os.path.dirname(full))
                        log(f"Общая папка: {path} удалён ({link.name})")
                except OSError as err:
                    log(f"Общая папка: не удалось удалить {path}: {err}")
            self.put(path, Entry(k, ver, ts, bytes(32), 0, True))
            self.save()
            self.hub.forward_file(link, path)
            return
        if e and not e.deleted and e.sha == sha and os.path.exists(full):
            e.ver, e.ts = ver, ts  # содержимое то же — просто принимаем версию
            self.dirty = True
            self.save()
            self.hub.forward_file(link, path)
            return
        if size > self.max_bytes:
            log(f"Общая папка: {path} больше FILE_MAX_MB — пропускаю")
            return
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = os.path.join(os.path.dirname(full), f".clipsync-{ver.hex()}.tmp")
        inc = Incoming(path, ver, ts, sha, size, n, tmp)
        self.rx[(link, k)] = inc
        if n == 0:
            self._finish(link, k, inc)

    def on_chunk(self, link, payload):
        hdr = payload[:FCHUNK_HDR.size]
        k, ver, idx = FCHUNK_HDR.unpack(hdr)
        inc = self.rx.get((link, k))
        if inc is None or inc.ver != ver:
            return
        if idx != inc.idx:
            log(f"{link.name}: части файла {inc.path} пришли не по порядку — жду повтора")
            self.rx.pop((link, k)).discard()
            return
        try:
            data = self.crypto.open(payload[FCHUNK_HDR.size:], b"clipsync-fchunk" + hdr)
        except Exception:  # noqa: BLE001
            self.rx.pop((link, k)).discard()
            log(f"{link.name}: часть файла {inc.path} не расшифровалась")
            return
        inc.f.write(data)
        inc.hash.update(data)
        inc.idx += 1
        if inc.idx == inc.n:
            self._finish(link, k, inc)

    def _finish(self, link, k, inc):
        self.rx.pop((link, k), None)
        inc.f.close()
        if inc.hash.digest() != inc.sha or os.path.getsize(inc.tmp) != inc.size:
            inc.discard()
            log(f"Общая папка: {inc.path} пришёл повреждённым — пропускаю")
            return
        full = self.abs(inc.path)
        e = self.state.get(inc.path)
        if e and e.ts > inc.ts:
            inc.discard()
            return
        os.replace(inc.tmp, full)
        st = os.stat(full)
        self.put(inc.path, Entry(k, inc.ver, inc.ts, inc.sha, inc.size, False, st.st_mtime_ns))
        self.save()
        log(f"Общая папка: {inc.path} получен ({link.name}, {inc.size} байт)")
        self.hub.forward_file(link, inc.path)

    def _prune_dirs(self, d):
        root = os.path.abspath(self.root)
        while os.path.abspath(d) != root and d.startswith(root):
            try:
                os.rmdir(d)
            except OSError:
                return
            d = os.path.dirname(d)

    def link_down(self, link):
        for key in [k for k in self.rx if k[0] is link]:
            self.rx.pop(key).discard()


# ---------- соединения ----------

class Link:
    """Соединение с relay: облачный сервер или встроенный relay для кабеля."""

    def __init__(self, hub, name, host, port):
        self.hub, self.name, self.host, self.port = hub, name, host, port
        self.ch = None
        self.known = None  # id последнего сообщения буфера, которое знает та сторона
        self.uploads = None
        self.queued = set()

    @property
    def up(self):
        return self.ch is not None and not self.ch.closing

    def send_clip(self, clip):
        if self.up:
            self.ch.send(relay.T_CLIP, self.hub.crypto.clip_encrypt(clip))
            self.known = clip.id

    def spawn_upload(self, path):
        if self.up and path not in self.queued:
            self.queued.add(path)
            self.uploads.put_nowait(path)

    async def _uploader(self):
        while True:
            path = await self.uploads.get()
            self.queued.discard(path)
            if self.up and self.hub.files:
                await self.hub.files.upload(self, path)

    async def run(self):
        delay, reported = 1, False
        while True:
            up_task = None
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), 10)
                sock = writer.get_extra_info("socket")
                if sock is not None:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.ch = await asyncio.wait_for(
                    relay.client_handshake(reader, writer, self.hub.auth_key, self.hub.name), 10)
                log(f"{self.name}: подключено ({self.host}:{self.port})")
                delay, reported = 1, False
                self.uploads, self.queued = asyncio.Queue(), set()
                up_task = asyncio.create_task(self._uploader())
                cur = self.hub.current
                if cur is not None and cur.ts > 0 and cur.id != self.known:
                    self.send_clip(cur)
                while True:
                    ftype, payload = await asyncio.wait_for(self.ch.recv(), relay.IDLE_TIMEOUT)
                    await self.hub.on_frame(self, ftype, payload)
                    await self.ch.drain()
            except PermissionError as e:
                log(f"{self.name}: {e}")
                delay = 60
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as e:
                if self.ch is not None or not reported:
                    log(f"{self.name}: нет связи ({e or type(e).__name__}), переподключаюсь")
                    reported = True
            finally:
                if up_task:
                    up_task.cancel()
                if self.ch is not None:
                    self.ch.close()
                    self.ch = None
                    if self.hub.files:
                        self.hub.files.link_down(self)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)


class Hub:
    def __init__(self, name, secret, clipboard, share_dir=None, state_path=None, max_mb=2048):
        self.name = name
        self.clipboard = clipboard
        self.auth_key, enc_key = relay.derive_keys(secret)
        self.crypto = Crypto(enc_key)
        self.links = []
        self.seen = OrderedDict()
        self.current = None
        self.lock = asyncio.Lock()
        self.files = FileSync(self, share_dir, state_path, max_mb) if share_dir else None

    def add_link(self, name, host, port):
        link = Link(self, name, host, port)
        self.links.append(link)
        return link

    def live_links(self):
        return [link for link in self.links if link.up]

    def mark_seen(self, cid):
        if cid in self.seen:
            return False
        self.seen[cid] = True
        while len(self.seen) > 1000:
            self.seen.popitem(last=False)
        return True

    def forward_file(self, src, path):
        for link in self.live_links():
            if link is not src:
                link.spawn_upload(path)

    async def on_frame(self, link, ftype, payload):
        if ftype == relay.T_CLIP:
            await self.on_remote_clip(link, payload)
        elif ftype == relay.T_PING:
            link.ch.send(relay.T_PONG)
        elif self.files is None:
            return
        elif ftype == relay.T_FINDEX:
            self.files.on_index(link, payload)
        elif ftype == relay.T_FMETA and len(payload) > FMETA_HDR.size:
            self.files.on_meta(link, payload)
        elif ftype == relay.T_FCHUNK and len(payload) > FCHUNK_HDR.size:
            self.files.on_chunk(link, payload)

    async def on_local_change(self):
        async with self.lock:
            text = await self.clipboard.get()
            if not text or (self.current is not None and text == self.current.text):
                return
            ts = int(time.time() * 1000)
            if self.current is not None and ts <= self.current.ts:
                ts = self.current.ts + 1
            clip = Clip(secrets.token_bytes(16), ts, text)
            self.mark_seen(clip.id)
            self.current = clip
        log("ПК →", preview(text))
        for link in self.links:
            link.send_clip(clip)

    async def on_remote_clip(self, link, blob):
        try:
            clip = self.crypto.clip_decrypt(blob)
        except Exception:  # noqa: BLE001 — InvalidTag и мусор
            log(f"{link.name}: буфер обмена не расшифровался — на той стороне другой SECRET?")
            return
        link.known = clip.id
        async with self.lock:
            if not self.mark_seen(clip.id):
                return
            mine = self.current
            if mine is not None and clip.ts < mine.ts:
                link.send_clip(mine)  # у нас новее — пусть та сторона догонит
                return
            self.current = clip
            if clip.text != await self.clipboard.get():
                await self.clipboard.set(clip.text)
        log(f"{link.name} →", preview(clip.text))
        for other in self.links:
            if other is not link:
                other.send_clip(clip)

    async def pinger(self):
        while True:
            await asyncio.sleep(PING_INTERVAL)
            for link in self.live_links():
                link.ch.send(relay.T_PING)
