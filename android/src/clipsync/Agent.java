package clipsync;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Агент clipsync на телефоне.
 *
 * Запускается с ПК через adb (app_process от пользователя shell) и дальше живёт
 * сам: переживает отключение кабеля, работает до перезагрузки телефона.
 * Подключается к relay-серверам: к ПК по кабелю (adb reverse на 127.0.0.1:usb_port)
 * и к облачному серверу; синхронизирует буфер обмена и общую папку.
 *
 * Протокол и логика — те же, что в pc/sync.py и server/relay.py.
 *
 * Доступ к буферу обмена — через классы scrcpy-server (лежит рядом в CLASSPATH),
 * только рефлексией, поэтому для сборки не нужен Android SDK.
 * Для тестов на обычной JVM: clipboard_file=путь — буфер обмена заменяется файлом.
 */
public final class Agent {

    static final String VERSION = "2";

    // ---------- протокол ----------
    static final byte[] MAGIC = "CSYN".getBytes(StandardCharsets.US_ASCII);
    static final int PROTO = 2;
    static final int T_CLIP = 1, T_PING = 2, T_PONG = 3, T_FMETA = 4, T_FCHUNK = 5, T_FINDEX = 6, T_FGET = 7,
            T_HELLO = 8;
    static final int MAX_FRAME = 4 << 20;
    static final int CHUNK = 1 << 20;
    static final int FMETA_HDR = 32 + 16 + 8 + 4, FCHUNK_HDR = 32 + 16 + 4, FINDEX_ENT = 32 + 16 + 8;
    static final byte[] CLIP_AAD = ascii("clipsync1");
    static final int PING_MS = 25_000, READ_TIMEOUT_MS = 90_000;
    static final byte[] ZERO16 = new byte[16];

    static final SecureRandom RNG = new SecureRandom();
    static PrintStream log = System.out;

    static void log(String s) {
        synchronized (Agent.class) {
            log.println(new SimpleDateFormat("MM-dd HH:mm:ss").format(new Date()) + " " + s);
            log.flush();
        }
    }

    // ---------- криптография ----------
    static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] p : parts) {
                mac.update(p);
            }
            return mac.doFinal();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] data, int off, int len, byte[] aad)
            throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        if (aad != null) {
            c.updateAAD(aad);
        }
        return c.doFinal(data, off, len);
    }

    /** Сквозное шифрование содержимого: nonce(12) + шифротекст. */
    byte[] seal(byte[] plain, byte[] aad) throws Exception {
        byte[] nonce = random(12);
        return concat(nonce, gcm(Cipher.ENCRYPT_MODE, encKey, nonce, plain, 0, plain.length, aad));
    }

    byte[] open(byte[] blob, int off, byte[] aad) throws Exception {
        return gcm(Cipher.DECRYPT_MODE, encKey, Arrays.copyOfRange(blob, off, off + 12), blob, off + 12,
                blob.length - off - 12, aad);
    }

    byte[] pathKey(String path) {
        return hmac(encKey, ascii("path:"), utf8(path));
    }

    // ---------- буфер обмена ----------
    interface Clipboard {
        String get() throws Exception;

        void set(String text) throws Exception;

        /** Вызывает onReady, затем onChange при каждом изменении; блокирует поток. */
        void loop(Runnable onReady, Runnable onChange) throws Exception;
    }

    /** Буфер обмена Android через scrcpy-server. */
    static final class AndroidClipboard implements Clipboard {
        private Object manager;

        @Override
        public synchronized String get() throws Exception {
            Object cs = manager.getClass().getMethod("getText").invoke(manager);
            return cs == null ? null : cs.toString();
        }

        @Override
        public synchronized void set(String text) throws Exception {
            manager.getClass().getMethod("setText", CharSequence.class).invoke(manager, text);
        }

        @Override
        public void loop(Runnable onReady, final Runnable onChange) throws Exception {
            Class<?> looper = Class.forName("android.os.Looper");
            looper.getMethod("prepareMainLooper").invoke(null);
            Class.forName("com.genymobile.scrcpy.Workarounds").getMethod("apply").invoke(null);
            manager = Class.forName("com.genymobile.scrcpy.wrappers.ServiceManager")
                    .getMethod("getClipboardManager").invoke(null);
            if (manager == null) {
                throw new IllegalStateException("на телефоне нет ClipboardManager");
            }
            Class<?> iface = Class.forName("android.content.ClipboardManager$OnPrimaryClipChangedListener");
            Object listener = Proxy.newProxyInstance(Agent.class.getClassLoader(), new Class<?>[]{iface},
                    new InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, Method m, Object[] a) {
                            switch (m.getName()) {
                                case "onPrimaryClipChanged":
                                    // не блокируем главный поток: чтение буфера — отдельно
                                    new Thread(onChange, "clip-change").start();
                                    return null;
                                case "hashCode":
                                    return System.identityHashCode(proxy);
                                case "equals":
                                    return proxy == a[0];
                                case "toString":
                                    return "clipsync-listener";
                                default:
                                    return null;
                            }
                        }
                    });
            manager.getClass().getMethod("addPrimaryClipChangedListener", iface).invoke(manager, listener);
            log("Буфер обмена Android подключён");
            onReady.run();
            looper.getMethod("loop").invoke(null);
        }
    }

    /** Буфер обмена-файл: для тестов на JVM. */
    static final class FileClipboard implements Clipboard {
        private final File file;

        FileClipboard(File file) {
            this.file = file;
        }

        @Override
        public synchronized String get() throws IOException {
            return file.exists() ? new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8) : null;
        }

        @Override
        public synchronized void set(String text) throws IOException {
            File tmp = new File(file.getPath() + ".tmp");
            Files.write(tmp.toPath(), utf8(text));
            if (!tmp.renameTo(file)) {
                throw new IOException("не удалось записать " + file);
            }
        }

        @Override
        public void loop(Runnable onReady, Runnable onChange) throws Exception {
            String last = get();
            onReady.run();
            while (true) {
                Thread.sleep(200);
                String now = get();
                if (now != null && !now.equals(last)) {
                    last = now;
                    onChange.run();
                }
            }
        }
    }

    // ---------- состояние ----------
    static final class Clip {
        final byte[] id;
        final long ts;
        final String text;

        Clip(byte[] id, long ts, String text) {
            this.id = id;
            this.ts = ts;
            this.text = text;
        }
    }

    final Map<String, String> conf;
    final byte[] authKey, encKey;
    final String name;
    final Clipboard clipboard;
    final List<Link> links = new ArrayList<>();
    final Set<String> seen = new HashSet<>();
    final ArrayDeque<String> seenOrder = new ArrayDeque<>();
    final Object clipLock = new Object();
    Clip current;
    FileSync files;

    Agent(Map<String, String> conf, Clipboard clipboard) {
        this.conf = conf;
        this.authKey = unhex(conf.get("auth"));
        this.encKey = unhex(conf.get("enc"));
        this.name = conf.getOrDefault("name", "phone");
        this.clipboard = clipboard;
    }

    boolean markSeen(byte[] id) {
        String h = hex(id);
        if (!seen.add(h)) {
            return false;
        }
        seenOrder.add(h);
        while (seenOrder.size() > 1000) {
            seen.remove(seenOrder.poll());
        }
        return true;
    }

    // ---------- буфер обмена: логика ----------
    byte[] clipEncrypt(Clip c) throws Exception {
        byte[] text = utf8(c.text);
        ByteBuffer b = ByteBuffer.allocate(24 + text.length);
        b.put(c.id).putLong(c.ts).put(text);
        return seal(b.array(), CLIP_AAD);
    }

    Clip clipDecrypt(byte[] blob) throws Exception {
        byte[] p = open(blob, 0, CLIP_AAD);
        ByteBuffer b = ByteBuffer.wrap(p);
        byte[] id = new byte[16];
        b.get(id);
        long ts = b.getLong();
        return new Clip(id, ts, new String(p, 24, p.length - 24, StandardCharsets.UTF_8));
    }

    void onLocalClip() {
        String text;
        try {
            text = clipboard.get();
        } catch (Exception e) {
            log("Не удалось прочитать буфер обмена: " + e);
            return;
        }
        Clip clip;
        synchronized (clipLock) {
            if (text == null || text.isEmpty() || (current != null && text.equals(current.text))) {
                return;
            }
            byte[] id = random16();
            long ts = System.currentTimeMillis();
            if (current != null && ts <= current.ts) {
                ts = current.ts + 1;
            }
            clip = new Clip(id, ts, text);
            markSeen(id);
            current = clip;
        }
        log("телефон → " + preview(text));
        for (Link l : links) {
            l.sendClip(clip);
        }
    }

    void onRemoteClip(Link from, byte[] blob) {
        Clip clip;
        try {
            clip = clipDecrypt(blob);
        } catch (Exception e) {
            log(from.name + ": буфер обмена не расшифровался (другой секрет?)");
            return;
        }
        from.known = hex(clip.id);
        synchronized (clipLock) {
            if (!markSeen(clip.id)) {
                return;
            }
            if (current != null && clip.ts < current.ts) {
                from.sendClip(current); // у нас новее — пусть та сторона догонит
                return;
            }
            current = clip;
            try {
                if (!clip.text.equals(clipboard.get())) {
                    clipboard.set(clip.text);
                }
            } catch (Exception e) {
                log("Не удалось записать буфер обмена: " + e);
            }
        }
        log(from.name + " → телефон: " + preview(clip.text));
        for (Link l : links) {
            if (l != from) {
                l.sendClip(clip);
            }
        }
    }

    // ---------- общая папка ----------
    static final class Entry {
        byte[] key, ver, sha;
        long ts, size, mtime;
        boolean deleted;

        Entry(byte[] key, byte[] ver, long ts, byte[] sha, long size, boolean deleted, long mtime) {
            this.key = key;
            this.ver = ver;
            this.ts = ts;
            this.sha = sha;
            this.size = size;
            this.deleted = deleted;
            this.mtime = mtime;
        }
    }

    static final class Incoming {
        final String path;
        final byte[] ver, sha;
        final long ts, size;
        final int n;
        final File tmp;
        final OutputStream out;
        final MessageDigest hash;
        int idx;

        Incoming(String path, byte[] ver, long ts, byte[] sha, long size, int n, File tmp) throws Exception {
            this.path = path;
            this.ver = ver;
            this.ts = ts;
            this.sha = sha;
            this.size = size;
            this.n = n;
            this.tmp = tmp;
            this.out = new FileOutputStream(tmp);
            this.hash = MessageDigest.getInstance("SHA-256");
        }

        void discard() {
            try {
                out.close();
            } catch (IOException ignored) {
                // уже закрыт
            }
            if (!tmp.delete() && tmp.exists()) {
                log("Не удалось удалить " + tmp);
            }
        }
    }

    final class FileSync {
        final File root, stateFile;
        final long maxBytes;
        final Map<String, Entry> state = new HashMap<>();
        final Map<String, String> byKey = new HashMap<>();
        final Map<String, Incoming> rx = new HashMap<>(); // linkId/keyHex → приём

        FileSync(File root, File stateFile, long maxMb) {
            this.root = root;
            this.stateFile = stateFile;
            this.maxBytes = maxMb << 20;
            if (!root.isDirectory() && !root.mkdirs()) {
                log("Не удалось создать папку " + root);
            }
            load();
        }

        void load() {
            if (!stateFile.exists()) {
                return;
            }
            try {
                for (String line : Files.readAllLines(stateFile.toPath(), StandardCharsets.UTF_8)) {
                    String[] f = line.split("\t");
                    if (f.length != 8) {
                        continue;
                    }
                    String path = new String(Base64.getDecoder().decode(f[0]), StandardCharsets.UTF_8);
                    put(path, new Entry(unhex(f[1]), unhex(f[2]), Long.parseLong(f[3]), unhex(f[4]),
                            Long.parseLong(f[5]), "1".equals(f[6]), Long.parseLong(f[7])));
                }
            } catch (Exception e) {
                log("Не удалось прочитать состояние папки: " + e);
            }
        }

        void save() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Entry> me : state.entrySet()) {
                Entry e = me.getValue();
                sb.append(Base64.getEncoder().encodeToString(utf8(me.getKey()))).append('\t')
                        .append(hex(e.key)).append('\t').append(hex(e.ver)).append('\t').append(e.ts).append('\t')
                        .append(hex(e.sha)).append('\t').append(e.size).append('\t')
                        .append(e.deleted ? "1" : "0").append('\t').append(e.mtime).append('\n');
            }
            File tmp = new File(stateFile.getPath() + ".tmp");
            try {
                Files.write(tmp.toPath(), utf8(sb.toString()));
                if (!tmp.renameTo(stateFile)) {
                    throw new IOException("rename");
                }
            } catch (IOException e) {
                log("Не удалось сохранить состояние папки: " + e);
            }
        }

        void put(String path, Entry e) {
            state.put(path, e);
            byKey.put(hex(e.key), path);
        }

        File abs(String path) {
            return new File(root, path);
        }

        // --- локальные изменения ---
        void walk(File dir, String prefix, Map<String, File> out) {
            File[] list = dir.listFiles();
            if (list == null) {
                return;
            }
            for (File f : list) {
                String n = f.getName();
                if (skipName(n)) {
                    continue;
                }
                String rel = prefix.isEmpty() ? n : prefix + "/" + n;
                if (f.isDirectory()) {
                    walk(f, rel, out);
                } else if (f.isFile()) {
                    out.put(rel, f);
                }
            }
        }

        void scanLoop() {
            while (true) {
                try {
                    Thread.sleep(3000);
                    scan();
                } catch (InterruptedException e) {
                    return;
                } catch (Exception e) {
                    log("Общая папка: ошибка сканирования: " + e);
                }
            }
        }

        void scan() throws Exception {
            Map<String, File> found = new HashMap<>();
            walk(root, "", found);
            long now = System.currentTimeMillis();
            List<String> changed = new ArrayList<>();
            for (Map.Entry<String, File> me : found.entrySet()) {
                String rel = me.getKey();
                File f = me.getValue();
                long size = f.length(), mtime = f.lastModified();
                Entry e;
                synchronized (this) {
                    e = state.get(rel);
                    if (e != null && !e.deleted && e.size == size && e.mtime == mtime) {
                        continue;
                    }
                }
                if (now - mtime < 2000) {
                    continue; // файл ещё пишется
                }
                if (size > maxBytes) {
                    synchronized (this) {
                        if (e == null || e.mtime != mtime) {
                            log("Общая папка: " + rel + " больше лимита — не синхронизируется");
                            put(rel, new Entry(pathKey(rel), ZERO16, 0, new byte[32], size, true, mtime));
                        }
                    }
                    continue;
                }
                byte[] sha = fileSha(f);
                synchronized (this) {
                    e = state.get(rel);
                    if (e != null && !e.deleted && Arrays.equals(e.sha, sha)) {
                        e.size = size;
                        e.mtime = mtime;
                        continue;
                    }
                    long ts = Math.max(now, e != null ? e.ts + 1 : 0);
                    put(rel, new Entry(pathKey(rel), random16(), ts, sha, size, false, mtime));
                }
                changed.add(rel);
                log("Общая папка: " + rel + " изменён на телефоне");
            }
            synchronized (this) {
                for (Map.Entry<String, Entry> me : new ArrayList<>(state.entrySet())) {
                    Entry e = me.getValue();
                    if (!e.deleted && !found.containsKey(me.getKey()) && !abs(me.getKey()).exists()) {
                        put(me.getKey(), new Entry(e.key, random16(), Math.max(now, e.ts + 1), new byte[32], 0,
                                true, 0));
                        changed.add(me.getKey());
                        log("Общая папка: " + me.getKey() + " удалён на телефоне");
                    }
                }
                save();
            }
            for (String rel : changed) {
                for (Link l : links) {
                    l.queueUpload(rel);
                }
            }
        }

        // --- отправка ---
        void upload(Link link, String path) throws Exception {
            Entry e;
            synchronized (this) {
                Entry s = state.get(path);
                if (s == null || Arrays.equals(s.ver, ZERO16)) {
                    return;
                }
                e = new Entry(s.key, s.ver, s.ts, s.sha, s.size, s.deleted, s.mtime);
            }
            int n = e.deleted ? 0 : (int) ((e.size + CHUNK - 1) / CHUNK);
            byte[] hdr = ByteBuffer.allocate(FMETA_HDR).put(e.key).put(e.ver).putLong(e.ts).putInt(n).array();
            byte[] p = utf8(path);
            byte[] plain = ByteBuffer.allocate(32 + 9 + p.length).put(e.sha).putLong(e.size)
                    .put((byte) (e.deleted ? 1 : 0)).put(p).array();
            byte[] meta = concat(hdr, seal(plain, concat(ascii("clipsync-fmeta"), hdr)));
            if (e.deleted) {
                link.send(T_FMETA, meta);
                return;
            }
            try (InputStream in = new FileInputStream(abs(path))) {
                link.send(T_FMETA, meta);
                byte[] buf = new byte[CHUNK];
                for (int i = 0; i < n && link.up(); i++) {
                    int got = readFully(in, buf);
                    byte[] ch = ByteBuffer.allocate(FCHUNK_HDR).put(e.key).put(e.ver).putInt(i).array();
                    link.send(T_FCHUNK,
                            concat(ch, seal(Arrays.copyOf(buf, got), concat(ascii("clipsync-fchunk"), ch))));
                }
            } catch (java.io.FileNotFoundException ex) {
                // удалён во время отправки — сканер разошлёт удаление
            }
        }

        // --- приём ---
        void onIndex(Link link, byte[] p) {
            Map<String, Object[]> remote = new HashMap<>();
            for (int off = 0; off + FINDEX_ENT <= p.length; off += FINDEX_ENT) {
                ByteBuffer b = ByteBuffer.wrap(p, off, FINDEX_ENT);
                byte[] k = new byte[32], v = new byte[16];
                b.get(k);
                b.get(v);
                remote.put(hex(k), new Object[]{k, v, b.getLong()});
            }
            List<String> uploads = new ArrayList<>();
            List<byte[]> gets = new ArrayList<>();
            synchronized (this) {
                for (Object[] r : remote.values()) {
                    String path = byKey.get(hex((byte[]) r[0]));
                    Entry e = path != null ? state.get(path) : null;
                    if (e == null || (!Arrays.equals(e.ver, (byte[]) r[1]) && (long) r[2] > e.ts)) {
                        gets.add(concat((byte[]) r[0], (byte[]) r[1]));
                    }
                }
                for (Map.Entry<String, Entry> me : state.entrySet()) {
                    Entry e = me.getValue();
                    if (Arrays.equals(e.ver, ZERO16)) {
                        continue;
                    }
                    Object[] r = remote.get(hex(e.key));
                    if (r == null ? !e.deleted : (!Arrays.equals((byte[]) r[1], e.ver) && e.ts > (long) r[2])) {
                        uploads.add(me.getKey());
                    }
                }
            }
            for (byte[] g : gets) {
                link.send(T_FGET, g);
            }
            for (String u : uploads) {
                link.queueUpload(u);
            }
        }

        synchronized void onMeta(Link link, byte[] p) {
            byte[] hdr = Arrays.copyOf(p, FMETA_HDR);
            ByteBuffer b = ByteBuffer.wrap(hdr);
            byte[] k = new byte[32], ver = new byte[16];
            b.get(k);
            b.get(ver);
            long ts = b.getLong();
            int n = b.getInt();
            byte[] plain;
            try {
                plain = open(p, FMETA_HDR, concat(ascii("clipsync-fmeta"), hdr));
            } catch (Exception e) {
                log(link.name + ": метаданные файла не расшифровались");
                return;
            }
            ByteBuffer pb = ByteBuffer.wrap(plain);
            byte[] sha = new byte[32];
            pb.get(sha);
            long size = pb.getLong();
            boolean deleted = pb.get() != 0;
            String path = new String(plain, 41, plain.length - 41, StandardCharsets.UTF_8);
            if (!validRel(path) || !Arrays.equals(pathKey(path), k)) {
                log(link.name + ": недопустимое имя файла — пропускаю");
                return;
            }
            String rxKey = link.id + "/" + hex(k);
            Incoming old = rx.remove(rxKey);
            if (old != null) {
                old.discard();
            }
            Entry e = state.get(path);
            if (e != null && Arrays.equals(e.ver, ver)) {
                return;
            }
            if (e != null && e.ts > ts) {
                link.queueUpload(path); // у нас новее
                return;
            }
            File full = abs(path);
            if (deleted) {
                if (e != null && !e.deleted && full.exists() && full.length() == e.size
                        && full.lastModified() == e.mtime) {
                    if (full.delete()) {
                        pruneDirs(full.getParentFile());
                        log("Общая папка: " + path + " удалён (" + link.name + ")");
                    }
                }
                put(path, new Entry(k, ver, ts, new byte[32], 0, true, 0));
                save();
                forward(link, path);
                return;
            }
            if (e != null && !e.deleted && Arrays.equals(e.sha, sha) && full.exists()) {
                e.ver = ver;
                e.ts = ts;
                save();
                forward(link, path);
                return;
            }
            if (size > maxBytes) {
                log("Общая папка: " + path + " больше лимита — пропускаю");
                return;
            }
            File dir = full.getParentFile();
            if (!dir.isDirectory() && !dir.mkdirs()) {
                log("Не удалось создать " + dir);
                return;
            }
            try {
                Incoming inc = new Incoming(path, ver, ts, sha, size, n,
                        new File(dir, ".clipsync-" + hex(ver) + ".tmp"));
                rx.put(rxKey, inc);
                if (n == 0) {
                    finish(link, rxKey, k, inc);
                }
            } catch (Exception ex) {
                log("Общая папка: не удалось принять " + path + ": " + ex);
            }
        }

        synchronized void onChunk(Link link, byte[] p) {
            byte[] hdr = Arrays.copyOf(p, FCHUNK_HDR);
            ByteBuffer b = ByteBuffer.wrap(hdr);
            byte[] k = new byte[32], ver = new byte[16];
            b.get(k);
            b.get(ver);
            int idx = b.getInt();
            String rxKey = link.id + "/" + hex(k);
            Incoming inc = rx.get(rxKey);
            if (inc == null || !Arrays.equals(inc.ver, ver)) {
                return;
            }
            try {
                if (idx != inc.idx) {
                    throw new IOException("части пришли не по порядку");
                }
                byte[] data = open(p, FCHUNK_HDR, concat(ascii("clipsync-fchunk"), hdr));
                inc.out.write(data);
                inc.hash.update(data);
                inc.idx++;
                if (inc.idx == inc.n) {
                    finish(link, rxKey, k, inc);
                }
            } catch (Exception ex) {
                rx.remove(rxKey);
                inc.discard();
                log("Общая папка: ошибка приёма " + inc.path + ": " + ex.getMessage());
            }
        }

        void finish(Link link, String rxKey, byte[] k, Incoming inc) throws IOException {
            rx.remove(rxKey);
            inc.out.close();
            if (!Arrays.equals(inc.hash.digest(), inc.sha) || inc.tmp.length() != inc.size) {
                inc.discard();
                log("Общая папка: " + inc.path + " пришёл повреждённым — пропускаю");
                return;
            }
            Entry e = state.get(inc.path);
            if (e != null && e.ts > inc.ts) {
                inc.discard();
                return;
            }
            File full = abs(inc.path);
            if (!inc.tmp.renameTo(full)) {
                inc.discard();
                throw new IOException("не удалось переименовать в " + full);
            }
            put(inc.path, new Entry(k, inc.ver, inc.ts, inc.sha, inc.size, false, full.lastModified()));
            save();
            log("Общая папка: " + inc.path + " получен (" + link.name + ", " + inc.size + " байт)");
            forward(link, inc.path);
        }

        void forward(Link from, String path) {
            for (Link l : links) {
                if (l != from) {
                    l.queueUpload(path);
                }
            }
        }

        void pruneDirs(File d) {
            while (d != null && !d.equals(root) && d.getPath().startsWith(root.getPath())) {
                if (!d.delete()) {
                    return;
                }
                d = d.getParentFile();
            }
        }

        synchronized void linkDown(Link link) {
            String prefix = link.id + "/";
            for (String key : new ArrayList<>(rx.keySet())) {
                if (key.startsWith(prefix)) {
                    rx.remove(key).discard();
                }
            }
        }
    }

    // ---------- соединение ----------
    final class Link implements Runnable {
        final String name, host;
        final int id, port;
        final boolean quietRetry;
        volatile String known;
        volatile Socket sock;
        volatile OutputStream out;
        volatile ExecutorService uploads;
        final Set<String> queued = new HashSet<>();
        byte[] kSend, kRecv;
        long nSend, nRecv;

        Link(int id, String name, String host, int port, boolean quietRetry) {
            this.id = id;
            this.name = name;
            this.host = host;
            this.port = port;
            this.quietRetry = quietRetry;
        }

        boolean up() {
            return out != null;
        }

        /** Зашифрованный кадр; ошибка записи закрывает соединение. */
        void send(int type, byte[] payload) {
            OutputStream o = out;
            if (o == null) {
                return;
            }
            try {
                synchronized (this) {
                    byte[] plain = new byte[1 + payload.length];
                    plain[0] = (byte) type;
                    System.arraycopy(payload, 0, plain, 1, payload.length);
                    byte[] ct = gcm(Cipher.ENCRYPT_MODE, kSend, counterNonce(nSend++), plain, 0, plain.length, null);
                    o.write(concat(ByteBuffer.allocate(4).putInt(ct.length).array(), ct));
                    o.flush();
                }
            } catch (Exception e) {
                close();
            }
        }

        void sendClip(Clip c) {
            if (!up()) {
                return;
            }
            try {
                send(T_CLIP, clipEncrypt(c));
                known = hex(c.id);
            } catch (Exception e) {
                close();
            }
        }

        void queueUpload(final String path) {
            ExecutorService ex = uploads;
            if (ex == null || files == null) {
                return;
            }
            synchronized (queued) {
                if (!queued.add(path)) {
                    return;
                }
            }
            try {
                ex.execute(() -> {
                    synchronized (queued) {
                        queued.remove(path);
                    }
                    try {
                        if (up()) {
                            files.upload(this, path);
                        }
                    } catch (Exception e) {
                        log(name + ": не удалось отправить " + path + ": " + e);
                    }
                });
            } catch (RejectedExecutionException ignored) {
                // соединение закрывается
            }
        }

        void close() {
            Socket s = sock;
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ignored) {
                    // уже закрыт
                }
            }
        }

        @Override
        public void run() {
            int delay = 1000;
            boolean wasUp = false, reported = false;
            while (true) {
                Socket s = new Socket();
                try {
                    s.connect(new InetSocketAddress(host, port), 10_000);
                    s.setTcpNoDelay(true);
                    s.setSoTimeout(READ_TIMEOUT_MS);
                    sock = s;
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    handshake(in, s.getOutputStream());
                    synchronized (queued) {
                        queued.clear();
                    }
                    uploads = Executors.newSingleThreadExecutor();
                    out = s.getOutputStream();
                    send(T_HELLO, utf8(Agent.this.name));
                    wasUp = true;
                    reported = false;
                    delay = 1000;
                    log(name + ": подключено (" + host + ":" + port + ")");
                    Clip c;
                    synchronized (clipLock) {
                        c = current;
                    }
                    if (c != null && c.ts > 0 && !hex(c.id).equals(known)) {
                        sendClip(c);
                    }
                    readLoop(in);
                } catch (Exception e) {
                    if (wasUp || (!quietRetry && !reported)) {
                        log(name + ": нет связи (" + e.getMessage() + "), повторяю");
                        reported = true;
                    }
                    wasUp = false;
                } finally {
                    out = null;
                    sock = null;
                    ExecutorService ex = uploads;
                    uploads = null;
                    if (ex != null) {
                        ex.shutdownNow();
                    }
                    if (files != null) {
                        files.linkDown(this);
                    }
                    try {
                        s.close();
                    } catch (IOException ignored) {
                        // уже закрыт
                    }
                }
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    return;
                }
                delay = quietRetry ? 2000 : Math.min(delay * 2, 30_000);
            }
        }

        void handshake(DataInputStream in, OutputStream o) throws Exception {
            byte[] hello = new byte[5 + 32];
            in.readFully(hello);
            if (!Arrays.equals(Arrays.copyOf(hello, 4), MAGIC)) {
                throw new IOException("это не сервер clipsync");
            }
            if (hello[4] != PROTO) {
                throw new IOException("другая версия протокола у сервера: " + hello[4]);
            }
            byte[] sn = Arrays.copyOfRange(hello, 5, 37);
            byte[] cn = random(32);
            o.write(concat(cn, hmac(authKey, ascii("c"), sn, cn)));
            o.flush();
            byte[] smac = new byte[32];
            try {
                in.readFully(smac);
            } catch (IOException e) {
                throw new IOException("сервер отклонил авторизацию (неверный секрет)");
            }
            if (!MessageDigest.isEqual(smac, hmac(authKey, ascii("s"), sn, cn))) {
                throw new IOException("сервер не подтвердил ключ — чужой сервер");
            }
            kSend = hmac(authKey, ascii("c2s"), sn, cn);
            kRecv = hmac(authKey, ascii("s2c"), sn, cn);
            nSend = 0;
            nRecv = 0;
        }

        void readLoop(DataInputStream in) throws Exception {
            while (true) {
                int len;
                try {
                    len = in.readInt();
                } catch (SocketTimeoutException e) {
                    throw new IOException("сервер не отвечает");
                }
                if (len < 17 || len > MAX_FRAME + 64) {
                    throw new IOException("неверный кадр");
                }
                byte[] ct = new byte[len];
                in.readFully(ct);
                byte[] data;
                try {
                    data = gcm(Cipher.DECRYPT_MODE, kRecv, counterNonce(nRecv++), ct, 0, ct.length, null);
                } catch (Exception e) {
                    throw new IOException("кадр не прошёл проверку подлинности");
                }
                int type = data[0] & 0xff;
                byte[] payload = Arrays.copyOfRange(data, 1, data.length);
                if (type == T_CLIP) {
                    onRemoteClip(this, payload);
                } else if (type == T_PING) {
                    send(T_PONG, new byte[0]);
                } else if (files != null && type == T_FINDEX) {
                    files.onIndex(this, payload);
                } else if (files != null && type == T_FMETA && payload.length > FMETA_HDR) {
                    files.onMeta(this, payload);
                } else if (files != null && type == T_FCHUNK && payload.length > FCHUNK_HDR) {
                    files.onChunk(this, payload);
                }
            }
        }
    }

    void start() {
        String usb = conf.get("usb_port");
        if (usb != null && !usb.isEmpty() && !"0".equals(usb)) {
            links.add(new Link(1, "ПК по кабелю", "127.0.0.1", Integer.parseInt(usb), true));
        }
        String server = conf.get("server");
        if (server != null && !server.isEmpty()) {
            int i = server.lastIndexOf(':');
            String host = server.substring(0, i);
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            links.add(new Link(2, "сервер", host, Integer.parseInt(server.substring(i + 1)), false));
        }
        String share = conf.get("share_dir");
        if (share != null && !share.isEmpty()) {
            files = new FileSync(new File(share), new File(conf.getOrDefault("state", share + ".clipsync-state")),
                    Long.parseLong(conf.getOrDefault("file_max_mb", "2048")));
            daemon(files::scanLoop, "scan");
        }
        for (Link l : links) {
            daemon(l, "link-" + l.id);
        }
        daemon(() -> {
            while (true) {
                try {
                    Thread.sleep(PING_MS);
                } catch (InterruptedException e) {
                    return;
                }
                for (Link l : links) {
                    l.send(T_PING, new byte[0]);
                }
            }
        }, "pinger");
    }

    /** Выход, когда конфиг удалён (clipsync phone-remove) или запущен другой агент. */
    static void watchConfig(final File confFile, final String myStamp) {
        daemon(() -> {
            File stamp = new File(confFile.getParentFile(), "stamp");
            while (true) {
                try {
                    Thread.sleep(5_000);
                } catch (InterruptedException e) {
                    return;
                }
                String now = readStamp(stamp);
                if (!confFile.exists() || (myStamp != null && now != null && !now.equals(myStamp))) {
                    log("Конфигурация удалена или обновлена — выхожу");
                    System.exit(0);
                }
            }
        }, "conf-watch");
    }

    // ---------- утилиты ----------
    static void daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
    }

    static byte[] counterNonce(long n) {
        return ByteBuffer.allocate(12).putInt(0).putLong(n).array();
    }

    static boolean skipName(String n) {
        return n.startsWith(".clipsync") || n.endsWith(".part") || n.endsWith(".crdownload") || n.endsWith(".tmp")
                || n.endsWith(".partial") || n.endsWith(".download");
    }

    static boolean validRel(String path) {
        if (path.isEmpty() || path.startsWith("/") || path.indexOf('\0') >= 0) {
            return false;
        }
        for (String part : path.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                return false;
            }
        }
        return true;
    }

    static byte[] fileSha(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        }
        return md.digest();
    }

    static int readFully(InputStream in, byte[] buf) throws IOException {
        int got = 0;
        while (got < buf.length) {
            int n = in.read(buf, got, buf.length - got);
            if (n < 0) {
                break;
            }
            got += n;
        }
        return got;
    }

    static String readStamp(File f) {
        try {
            return f.exists() ? new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim() : null;
        } catch (IOException e) {
            return null;
        }
    }

    static String preview(String t) {
        String s = t.replace("\n", "⏎");
        return s.length() > 40 ? s.substring(0, 40) + "… (" + t.length() + " симв.)" : s;
    }

    static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    static byte[] random16() {
        return random(16);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    static byte[] unhex(String s) {
        if (s == null || s.length() % 2 != 0) {
            throw new IllegalArgumentException("неверный hex в конфиге");
        }
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    static Map<String, String> readConf(File f) throws IOException {
        Properties p = new Properties();
        try (InputStream in = new FileInputStream(f)) {
            p.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        Map<String, String> m = new LinkedHashMap<>();
        for (String k : p.stringPropertyNames()) {
            m.put(k, p.getProperty(k).trim());
        }
        return m;
    }

    /** Свой журнал с ограничением размера. */
    static PrintStream openLog(File f) throws IOException {
        if (f.exists() && f.length() > 256 * 1024) {
            File old = new File(f.getPath() + ".1");
            if ((old.exists() && !old.delete()) || !f.renameTo(old)) {
                throw new IOException("не удалось сменить журнал " + f);
            }
        }
        final long start = f.length();
        OutputStream os = new FileOutputStream(f, true) {
            long written = start;

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (written < 1024 * 1024) {
                    super.write(b, off, len);
                    written += len;
                }
            }
        };
        return new PrintStream(os, true, "UTF-8");
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: clipsync.Agent <agent.conf>");
            System.exit(2);
        }
        File confFile = new File(args[0]).getAbsoluteFile();
        Map<String, String> conf = readConf(confFile);
        if (conf.containsKey("log")) {
            log = openLog(new File(conf.get("log")));
        }
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> log("Ошибка в потоке " + t.getName() + ": " + e));
        Clipboard cb = conf.containsKey("clipboard_file")
                ? new FileClipboard(new File(conf.get("clipboard_file")))
                : new AndroidClipboard();
        final Agent agent = new Agent(conf, cb);
        log("clipsync-агент " + VERSION + " запущен: сервер=" + conf.getOrDefault("server", "")
                + ", кабель=" + conf.getOrDefault("usb_port", "") + ", папка=" + conf.getOrDefault("share_dir", ""));
        watchConfig(confFile, readStamp(new File(confFile.getParentFile(), "stamp")));
        cb.loop(() -> {
            try {
                String text = cb.get();
                if (text != null) {
                    agent.current = new Clip(new byte[16], 0, text); // ts=0: не рассылаем то, что было до запуска
                }
            } catch (Exception e) {
                log("Не удалось прочитать буфер обмена: " + e);
            }
            agent.start();
        }, agent::onLocalClip);
        log("Главный цикл завершился");
        System.exit(1);
    }
}
