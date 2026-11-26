#!/usr/bin/env bash
# Тесты clipsync без телефона и графического сеанса: relay-сервер, два «компьютера»
# (pc/clipsync.py с буфером обмена-файлом) и агент телефона на обычной JVM.
# Проверяются буфер обмена, общая папка (файлы, подпапки, большие файлы, удаление),
# доставка «офлайн» через сервер, путь «по кабелю» через встроенный relay ПК,
# отказ при неверном секрете и подделке сервера.
#   tests/run.sh          (нужны: ./clipsync setup, javac)
set -uo pipefail

ROOT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "окружение не готово: ./clipsync setup"; exit 1; }

T=$(mktemp -d)
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    if [ "${KEEP:-0}" = 1 ]; then echo "файлы теста: $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT

pass=0 fail=0
ok() { echo "  ok    $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; [ -n "${2:-}" ] && echo "        $2"; fail=$((fail + 1)); }
# wait_for описание команда… — ждёт до 20 с, пока команда не станет успешной
wait_for() {
    local name=$1 _
    shift
    for _ in $(seq 100); do "$@" >/dev/null 2>&1 && { ok "$name"; return 0; }; sleep 0.2; done
    bad "$name"
    return 1
}
same() { [ "$(cat "$1" 2>/dev/null)" = "$2" ]; }
# sha256sum (coreutils) вместо cmp: в минимальных образах нет diffutils
same_file() { [ -f "$1" ] && [ -f "$2" ] && [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]; }
gone() { [ ! -e "$1" ]; }
free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

SECRET=test-secret-$RANDOM
PORT=$(free_port)
USB=$(free_port)

echo "== сборка агента для JVM"
mkdir -p "$T/classes"
if javac -nowarn --release 11 -encoding UTF-8 -d "$T/classes" "$ROOT"/android/src/clipsync/*.java; then
    ok "агент компилируется"
else
    bad "агент компилируется"; exit 1
fi

start_pc() { # имя порт_кабеля [сервер]
    mkdir -p "$T/$1/share" "$T/$1/run"
    CLIPSYNC_NAME=$1 CLIPSYNC_SECRET=$SECRET CLIPSYNC_SERVER=${3-127.0.0.1:$PORT} CLIPSYNC_USB_PORT=$2 \
        CLIPSYNC_CLIPBOARD="file:$T/$1/clip" CLIPSYNC_SHARE_DIR="$T/$1/share" CLIPSYNC_RUN_DIR="$T/$1/run" \
        CLIPSYNC_NO_ADB=1 "$PY" "$ROOT/pc/clipsync.py" run >"$T/$1.log" 2>&1 &
    PIDS+=($!)
    eval "PID_$1=$!"
}

start_phone() { # имя порт_кабеля сервер
    mkdir -p "$T/$1/share"
    read -r AUTH ENC < <("$PY" -c "import sys; sys.path.insert(0,'$ROOT/server'); import relay; a,e=relay.derive_keys('$SECRET'); print(a.hex(), e.hex())")
    cat >"$T/$1/agent.conf" <<CONF
auth=$AUTH
enc=$ENC
server=$3
usb_port=$2
name=$1
share_dir=$T/$1/share
state=$T/$1/share.state
clipboard_file=$T/$1/clip
log=$T/$1.log
CONF
    # на Android имена файлов всегда в UTF-8; на JVM они берутся из локали — задаём UTF-8
    LC_ALL=C.UTF-8 java -cp "$T/classes" clipsync.Agent "$T/$1/agent.conf" >>"$T/$1.log" 2>&1 &
    PIDS+=($!)
    eval "PID_$1=$!"
}

echo "== relay"
"$PY" "$ROOT/server/relay.py" serve --host 127.0.0.1 --port "$PORT" --secret "$SECRET" --store "$T/store" >"$T/relay.log" 2>&1 &
PID_relay=$!
PIDS+=("$PID_relay")
wait_for "relay запущен" grep -q слушает "$T/relay.log"

echo "== буфер обмена через сервер: ПК A, ПК B, телефон P"
start_pc A 0
start_pc B 0
start_phone P 0 "127.0.0.1:$PORT"
wait_for "все подключились" sh -c "grep -c '^.*+ «' '$T/relay.log' | grep -q 3"
printf 'привет от A' >"$T/A/clip"
wait_for "A → B" same "$T/B/clip" 'привет от A'
wait_for "A → телефон" same "$T/P/clip" 'привет от A'
printf 'from phone\nмногострочный' >"$T/P/clip"
wait_for "телефон → A" same "$T/A/clip" $'from phone\nмногострочный'
wait_for "телефон → B" same "$T/B/clip" $'from phone\nмногострочный'

echo "== общая папка"
head -c 2500000 /dev/urandom >"$T/A/share/big.bin"
mkdir -p "$T/A/share/папка"
echo "текст" >"$T/A/share/папка/файл.txt"
wait_for "большой файл A → B" same_file "$T/A/share/big.bin" "$T/B/share/big.bin"
wait_for "большой файл A → телефон" same_file "$T/A/share/big.bin" "$T/P/share/big.bin"
wait_for "подпапка и кириллица A → телефон" same_file "$T/A/share/папка/файл.txt" "$T/P/share/папка/файл.txt"
echo "с телефона" >"$T/P/share/photo.txt"
wait_for "телефон → A" same_file "$T/P/share/photo.txt" "$T/A/share/photo.txt"
echo "изменено" >"$T/B/share/photo.txt"
wait_for "изменение B → телефон" same "$T/P/share/photo.txt" "изменено"
rm "$T/P/share/папка/файл.txt"
wait_for "удаление с телефона → A" gone "$T/A/share/папка/файл.txt"
wait_for "пустая папка убрана на A" gone "$T/A/share/папка"
: >"$T/A/share/empty.txt"
wait_for "пустой файл A → телефон" test -f "$T/P/share/empty.txt"

echo "== доставка офлайн: B выключен, пока A меняет данные"
kill "$PID_B"
wait "$PID_B" 2>/dev/null
printf 'пока B спал' >"$T/A/clip"
echo "офлайн" >"$T/A/share/offline.txt"
rm "$T/A/share/big.bin"
sleep 3
start_pc B 0
wait_for "B получил буфер после включения" same "$T/B/clip" 'пока B спал'
wait_for "B получил новый файл" same "$T/B/share/offline.txt" "офлайн"
wait_for "B получил удаление" gone "$T/B/share/big.bin"

echo "== по кабелю: ПК C без сервера, телефон Q только через встроенный relay C"
start_pc C "$USB" ""
start_phone Q "$USB" ""
wait_for "телефон подключился к ПК по кабелю" grep -q "ПК по кабелю: подключено" "$T/Q.log"
printf 'по кабелю' >"$T/Q/clip"
wait_for "телефон → ПК по кабелю" same "$T/C/clip" 'по кабелю'
echo "usb" >"$T/C/share/usb.txt"
wait_for "файл ПК → телефон по кабелю" same "$T/Q/share/usb.txt" "usb"

echo "== ПК пересылает между кабелем и сервером"
kill "$PID_C"
wait "$PID_C" 2>/dev/null
start_pc C "$USB"
wait_for "C подключился к серверу" grep -q "Сервер: подключено" "$T/C.log"
wait_for "телефон без интернета получил файлы сервера через ПК" same "$T/Q/share/offline.txt" "офлайн"
wait_for "файл телефона по кабелю дошёл до A через сервер" same "$T/A/share/usb.txt" "usb"
printf 'через ПК' >"$T/Q/clip"
wait_for "буфер телефона по кабелю дошёл до B" same "$T/B/clip" 'через ПК'

echo "== безопасность"
CLIPSYNC_SECRET=wrong CLIPSYNC_SERVER=127.0.0.1:$PORT "$PY" "$ROOT/pc/clipsync.py" status >"$T/wrong.txt" 2>&1
if grep -q "неверный секрет" "$T/wrong.txt"; then ok "неверный секрет отклонён"; else bad "неверный секрет отклонён" "$(grep Сервер "$T/wrong.txt")"; fi
FAKE=$(free_port)
"$PY" "$ROOT/server/relay.py" serve --host 127.0.0.1 --port "$FAKE" --secret other --store "$T/fake-store" >"$T/fake.log" 2>&1 &
PIDS+=($!)
sleep 1
CLIPSYNC_SECRET=$SECRET CLIPSYNC_SERVER=127.0.0.1:$FAKE "$PY" "$ROOT/pc/clipsync.py" status >"$T/fake.txt" 2>&1
if grep -qE "неверный секрет|чужой сервер" "$T/fake.txt"; then ok "сервер с другим ключом не принят"; else bad "сервер с другим ключом не принят"; fi
if grep -rqa "привет от A\|from phone\|офлайн" "$T/store"; then
    bad "сервер хранит данные в открытом виде"
else
    ok "на сервере нет открытых данных"
fi
if grep -rq "big.bin\|offline.txt\|usb.txt" "$T/store"; then bad "имена файлов видны серверу"; else ok "имена файлов скрыты от сервера"; fi

echo
echo "Итого: $pass прошло, $fail упало"
if [ "$fail" -ne 0 ]; then
    for f in relay A B C P Q; do echo "--- $f.log"; tail -n 15 "$T/$f.log" 2>/dev/null; done
fi
[ "$fail" -eq 0 ]
