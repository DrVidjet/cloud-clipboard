#!/usr/bin/env python3
"""clipsync relay — сервер-посредник для общего буфера обмена и общей папки.

Телефоны и компьютеры подключаются к нему и обмениваются сообщениями.
Сервер хранит последнее значение буфера обмена (в памяти) и файлы общей папки
(на диске) и раздаёт их всем клиентам с тем же ключом («комнате»).

Шифрование двухуровневое:
  * канал клиент ⇄ сервер шифруется AES-256-GCM, ключи свои для каждого
    направления и каждого соединения; клиент и сервер взаимно доказывают
    знание ключа авторизации (подменить сервер нельзя);
  * содержимое (текст буфера, имена и данные файлов) шифруется на клиентах
    ключом, которого у сервера нет: сервер не может их прочитать.

  relay.py serve [--host 0.0.0.0] [--port 8765] [--keys-file F] [--store DIR]
  relay.py gen-secret               новый случайный секрет
  relay.py auth-key SECRET          ключ авторизации для секрета (его хранит сервер)

Протокол (TCP):
  S→C  b"CSYN" + версия(1) + sn(32)
  C→S  cn(32) + HMAC(auth, "c" + sn + cn)
  S→C  HMAC(auth, "s" + sn + cn)
  дальше кадры: len(u32) + AES-GCM(ключ направления, nonce = счётчик, тип(1) + данные)
  ключи: HMAC(auth, "c2s" + sn + cn), HMAC(auth, "s2c" + sn + cn)

Типы кадров:
  1 CLIP   зашифрованный текст буфера обмена (сервер хранит последний)
  2 PING, 3 PONG
  4 FMETA  key(32) ver(16) ts(u64) nchunks(u32) + зашифрованные метаданные файла
  5 FCHUNK key(32) ver(16) idx(u32) + зашифрованная часть файла
  6 FINDEX сервер → клиент при подключении: [key(32) ver(16) ts(u64)]…
  7 FGET   key(32) ver(16) — прислать файл
  8 HELLO  имя клиента (первый кадр клиента)
"""

import argparse
import asyncio
import hashlib
import hmac
import os
import secrets
import shutil
import struct
import sys
import time

MAGIC = b"CSYN"
PROTO = 2
T_CLIP, T_PING, T_PONG, T_FMETA, T_FCHUNK, T_FINDEX, T_FGET, T_HELLO = 1, 2, 3, 4, 5, 6, 7, 8
MAX_FRAME = 4 << 20
CHUNK = 1 << 20
FMETA_HDR = struct.Struct(">32s16sQI")
FCHUNK_HDR = struct.Struct(">32s16sI")
FINDEX_ENT = struct.Struct(">32s16sQ")
KDF_SALT = b"clipsync-v1"
KDF_ITERATIONS = 200_000
DEFAULT_PORT = 8765
IDLE_TIMEOUT = 90  # клиенты пингуют каждые 25 с
HANDSHAKE_TIMEOUT = 10


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


# ---------- ключи ----------

def derive_keys(secret):
    """Секрет → (ключ авторизации, ключ шифрования содержимого), по 32 байта."""
    master = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), KDF_SALT, KDF_ITERATIONS, 32)
    auth = hmac.new(master, b"auth", hashlib.sha256).digest()
    enc = hmac.new(master, b"enc", hashlib.sha256).digest()
    return auth, enc


def gen_secret():
    return secrets.token_urlsafe(24)


def _h(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


# ---------- зашифрованный канал ----------

class Channel:
    """Кадры поверх TCP, зашифрованные AES-GCM; nonce — счётчик кадров."""

    def __init__(self, reader, writer, k_send, k_recv, name="?"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.reader, self.writer, self.name = reader, writer, name
        self._send, self._recv = AESGCM(k_send), AESGCM(k_recv)
        self._ns = self._nr = 0

    def send(self, ftype, payload=b""):
        """Ставит кадр в очередь записи (атомарно: счётчик и запись без await)."""
        nonce = struct.pack(">4xQ", self._ns)
        self._ns += 1
        ct = self._send.encrypt(nonce, bytes([ftype]) + payload, None)
        self.writer.write(struct.pack(">I", len(ct)) + ct)

    async def drain(self):
        await self.writer.drain()

    async def recv(self):
        (n,) = struct.unpack(">I", await self.reader.readexactly(4))
        if n < 17 or n > MAX_FRAME + 64:
            raise ConnectionError("неверный размер кадра")
        ct = await self.reader.readexactly(n)
        nonce = struct.pack(">4xQ", self._nr)
        self._nr += 1
        try:
            data = self._recv.decrypt(nonce, ct, None)
        except Exception:  # noqa: BLE001 — InvalidTag
            raise ConnectionError("кадр не прошёл проверку подлинности") from None
        return data[0], data[1:]

    @property
    def closing(self):
        return self.writer.is_closing()

    def buffered(self):
        return self.writer.transport.get_write_buffer_size()

    def close(self):
        self.writer.close()


async def server_handshake(reader, writer, auth_keys):
    """Проверка клиента. Возвращает (ключ авторизации, Channel)."""
    sn = secrets.token_bytes(32)
    writer.write(MAGIC + bytes([PROTO]) + sn)
    await writer.drain()
    data = await reader.readexactly(64)
    cn, mac = data[:32], data[32:]
    for key in auth_keys:
        if hmac.compare_digest(mac, _h(key, b"c", sn, cn)):
            writer.write(_h(key, b"s", sn, cn))
            await writer.drain()
            ch = Channel(reader, writer, _h(key, b"s2c", sn, cn), _h(key, b"c2s", sn, cn))
            ftype, payload = await ch.recv()
            if ftype == T_HELLO:
                ch.name = payload.decode("utf-8", "replace")[:100]
            return key, ch
    raise PermissionError("неверный ключ авторизации")


async def client_handshake(reader, writer, auth_key, name):
    hello = await reader.readexactly(len(MAGIC) + 1 + 32)
    if hello[:4] != MAGIC:
        raise ConnectionError("это не сервер clipsync")
    if hello[4] != PROTO:
        raise ConnectionError(f"другая версия протокола у сервера ({hello[4]}, нужна {PROTO}) — обновите")
    sn = hello[5:]
    cn = secrets.token_bytes(32)
    writer.write(cn + _h(auth_key, b"c", sn, cn))
    await writer.drain()
    try:
        smac = await reader.readexactly(32)
    except asyncio.IncompleteReadError:
        raise PermissionError("сервер отклонил авторизацию: неверный секрет") from None
    if not hmac.compare_digest(smac, _h(auth_key, b"s", sn, cn)):
        raise PermissionError("сервер не подтвердил знание ключа — это чужой сервер")
    ch = Channel(reader, writer, _h(auth_key, b"c2s", sn, cn), _h(auth_key, b"s2c", sn, cn), name)
    ch.send(T_HELLO, name.encode("utf-8")[:255])
    await ch.drain()
    return ch


# ---------- хранилище файлов ----------

class FileStore:
    """Файлы комнаты на диске: DIR/<key>/<ver>/{meta,0,1,…,done}. Сервер не может их прочитать."""

    def __init__(self, root):
        self.root = root
        self.index = {}    # key → (ver, ts, nchunks) — только полностью загруженные версии
        self.pending = {}  # key → [ver, ts, nchunks, следующий idx]
        os.makedirs(root, exist_ok=True)
        for kh in os.listdir(root):
            kdir = os.path.join(root, kh)
            best = None
            for vh in os.listdir(kdir):
                vdir = os.path.join(kdir, vh)
                if not os.path.exists(os.path.join(vdir, "done")):
                    shutil.rmtree(vdir, ignore_errors=True)
                    continue
                with open(os.path.join(vdir, "meta"), "rb") as f:
                    key, ver, ts, n = FMETA_HDR.unpack(f.read(FMETA_HDR.size))
                if best is None or ts > best[1]:
                    best = (ver, ts, n)
            if best:
                self.index[bytes.fromhex(kh)] = best

    def _vdir(self, key, ver):
        return os.path.join(self.root, key.hex(), ver.hex())

    def entries(self):
        return b"".join(FINDEX_ENT.pack(k, v[0], v[1]) for k, v in self.index.items())

    def newest_ts(self, key):
        cur = self.index.get(key)
        return cur[1] if cur else -1

    def put_meta(self, payload):
        """Возвращает True, если это новая версия (её надо разослать)."""
        key, ver, ts, n = FMETA_HDR.unpack_from(payload)
        cur = self.index.get(key)
        if cur and (cur[0] == ver or cur[1] > ts):
            return False
        pend = self.pending.get(key)
        if pend and (pend[0] == ver or pend[1] > ts):
            return False
        if pend:
            shutil.rmtree(self._vdir(key, pend[0]), ignore_errors=True)
        vdir = self._vdir(key, ver)
        os.makedirs(vdir, exist_ok=True)
        with open(os.path.join(vdir, "meta"), "wb") as f:
            f.write(payload)
        self.pending[key] = [ver, ts, n, 0]
        if n == 0:
            self._complete(key)
        return True

    def put_chunk(self, payload):
        key, ver, idx = FCHUNK_HDR.unpack_from(payload)
        pend = self.pending.get(key)
        if not pend or pend[0] != ver or pend[3] != idx:
            return False
        with open(os.path.join(self._vdir(key, ver), str(idx)), "wb") as f:
            f.write(payload[FCHUNK_HDR.size:])
        pend[3] += 1
        if pend[3] == pend[2]:
            self._complete(key)
            return "done"
        return True

    def _complete(self, key):
        ver, ts, n, _ = self.pending.pop(key)
        vdir = self._vdir(key, ver)
        open(os.path.join(vdir, "done"), "wb").close()
        old = self.index.get(key)
        self.index[key] = (ver, ts, n)
        if old and old[0] != ver:
            shutil.rmtree(self._vdir(key, old[0]), ignore_errors=True)

    async def send_file(self, ch, key):
        """Шлёт текущую версию файла клиенту (FMETA + все FCHUNK)."""
        cur = self.index.get(key)
        if not cur:
            return
        ver, _, n = cur
        vdir = self._vdir(key, ver)
        try:
            with open(os.path.join(vdir, "meta"), "rb") as f:
                ch.send(T_FMETA, f.read())
            for i in range(n):
                with open(os.path.join(vdir, str(i)), "rb") as f:
                    ch.send(T_FCHUNK, FCHUNK_HDR.pack(key, ver, i) + f.read())
                await ch.drain()
        except FileNotFoundError:
            pass  # версию как раз заменили — клиент получит новую рассылкой


# ---------- relay ----------

class Room:
    def __init__(self, store_dir):
        self.clients = set()
        self.latest = None
        self.files = FileStore(store_dir)


class Relay:
    def __init__(self, auth_keys, store_root, max_file_mb=2048, quiet=False):
        self.auth_keys = list(auth_keys)
        self.max_chunks = max(1, max_file_mb)  # кусок = 1 МиБ
        self.quiet = quiet
        self.rooms = {k: Room(os.path.join(store_root, hashlib.sha256(k).hexdigest()[:16])) for k in self.auth_keys}
        self.got_meta = {}  # key → клиенты, которым разослан FMETA загружаемой версии

    def _log(self, *a):
        if not self.quiet:
            log(*a)

    def _forward(self, room, src, ftype, payload):
        sent = set()
        for ch in list(room.clients):
            if ch is src or ch.closing:
                continue
            if ch.buffered() > 64 * CHUNK:
                self._log(f"«{ch.name}» не успевает принимать — отключаю, догонит при переподключении")
                ch.close()
                continue
            ch.send(ftype, payload)
            sent.add(ch)
        return sent

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        addr = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else "?"
        try:
            key, ch = await asyncio.wait_for(server_handshake(reader, writer, self.auth_keys), HANDSHAKE_TIMEOUT)
        except PermissionError as e:
            self._log(f"{addr}: {e}")
            writer.close()
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            writer.close()
            return
        room = self.rooms[key]
        who = f"«{ch.name}» ({addr})"
        room.clients.add(ch)
        self._log(f"+ {who}, в комнате {len(room.clients)}")
        try:
            if room.latest is not None:
                ch.send(T_CLIP, room.latest)
            ch.send(T_FINDEX, room.files.entries())
            while True:
                ftype, payload = await asyncio.wait_for(ch.recv(), IDLE_TIMEOUT)
                if ftype == T_CLIP:
                    room.latest = payload
                    self._forward(room, ch, T_CLIP, payload)
                elif ftype == T_FMETA and len(payload) >= FMETA_HDR.size:
                    k, _, ts, n = FMETA_HDR.unpack_from(payload)
                    if n > self.max_chunks:
                        self._log(f"{who}: файл больше лимита ({n} МиБ) — не принят")
                    elif room.files.put_meta(payload):
                        self.got_meta[k] = self._forward(room, ch, T_FMETA, payload) | {ch}
                        if n == 0:
                            self.got_meta.pop(k, None)
                    elif room.files.newest_ts(k) > ts:
                        await room.files.send_file(ch, k)  # у сервера новее — пусть клиент догонит
                elif ftype == T_FCHUNK and len(payload) >= FCHUNK_HDR.size:
                    res = room.files.put_chunk(payload)
                    if res:
                        self._forward(room, ch, T_FCHUNK, payload)
                    if res == "done":
                        # кто подключился во время загрузки, не видел FMETA — шлём ему файл целиком
                        k = payload[:32]
                        for other in room.clients - self.got_meta.pop(k, set()):
                            asyncio.ensure_future(room.files.send_file(other, k))
                elif ftype == T_FGET and len(payload) >= 32:
                    await room.files.send_file(ch, payload[:32])
                elif ftype == T_PING:
                    ch.send(T_PONG)
                await ch.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            room.clients.discard(ch)
            ch.close()
            self._log(f"- {who}, в комнате {len(room.clients)}")


def load_keys(path):
    keys = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                keys.append(bytes.fromhex(line))
    return keys


async def serve(host, port, keys, store, max_file_mb):
    relay = Relay(keys, store, max_file_mb)
    server = await asyncio.start_server(relay.handle, host, port)
    addrs = ", ".join(f"{s.getsockname()[0]}:{s.getsockname()[1]}" for s in server.sockets)
    log(f"clipsync relay слушает {addrs}, комнат: {len(keys)}, файлы: {store}")
    async with server:
        await server.serve_forever()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="relay.py", description="clipsync relay")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="запустить сервер")
    s.add_argument("--host", default=os.environ.get("CLIPSYNC_HOST", "0.0.0.0"))
    s.add_argument("--port", type=int, default=int(os.environ.get("CLIPSYNC_PORT", DEFAULT_PORT)))
    s.add_argument("--keys-file", help="файл с ключами авторизации (hex, по одному в строке); "
                   "по умолчанию $CREDENTIALS_DIRECTORY/auth.keys")
    s.add_argument("--secret", help="секрет вместо файла ключей (для проверки)")
    s.add_argument("--store", default=os.environ.get("STATE_DIRECTORY") or "store",
                   help="папка для файлов (по умолчанию $STATE_DIRECTORY или ./store)")
    s.add_argument("--max-file-mb", type=int, default=int(os.environ.get("CLIPSYNC_MAX_FILE_MB", 2048)))
    sub.add_parser("gen-secret", help="напечатать новый случайный секрет")
    k = sub.add_parser("auth-key", help="ключ авторизации для секрета")
    k.add_argument("secret")
    a = ap.parse_args(argv)

    if a.cmd == "gen-secret":
        print(gen_secret())
    elif a.cmd == "auth-key":
        print(derive_keys(a.secret)[0].hex())
    elif a.cmd == "serve":
        if a.secret:
            keys = [derive_keys(a.secret)[0]]
        else:
            path = a.keys_file or os.path.join(os.environ.get("CREDENTIALS_DIRECTORY", ""), "auth.keys")
            try:
                keys = load_keys(path)
            except (OSError, ValueError) as e:
                sys.exit(f"Не удалось прочитать ключи {path}: {e}")
        if not keys:
            sys.exit("Нет ни одного ключа авторизации")
        try:
            asyncio.run(serve(a.host, a.port, keys, a.store, a.max_file_mb))
        except KeyboardInterrupt:
            pass
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
