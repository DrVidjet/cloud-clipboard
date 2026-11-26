#!/usr/bin/env bash
# Установка relay-сервера clipsync (cloud-clipboard) на Linux-сервер с systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/DrVidjet/cloud-clipboard/HEAD/install-server.sh | sudo bash
#   curl -fsSL …/install-server.sh | sudo bash -s -- --port 8765 --secret МОЙ_СЕКРЕТ
#   curl -fsSL …/install-server.sh | sudo bash -s -- --uninstall
#
# Ставит в /opt/clipsync relay.py и venv с пакетом cryptography, службу
# clipsync-relay.service (без root-прав: DynamicUser), открывает порт в ufw/firewalld.
# Сервер хранит только ключ авторизации — прочитать буфер обмена и файлы он не может.
set -euo pipefail

REPO=${CLIPSYNC_REPO:-DrVidjet/cloud-clipboard}
REF=${CLIPSYNC_REF:-HEAD}
PREFIX=/opt/clipsync
ETC=/etc/clipsync
UNIT=/etc/systemd/system/clipsync-relay.service
PORT=8765
SECRET=
UNINSTALL=0

say() { printf '\033[1m%s\033[0m\n' "$*" >&2; }
die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT=$2; shift 2 ;;
        --secret) SECRET=$2; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h | --help) sed -n '2,12p' "$0" 2>/dev/null || true; exit 0 ;;
        *) die "неизвестный параметр $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "запустите от root: … | sudo bash"
have systemctl || die "нужен systemd"
case "$PORT" in '' | *[!0-9]*) die "порт должен быть числом" ;; esac

if [ "$UNINSTALL" = 1 ]; then
    systemctl disable --now clipsync-relay.service 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    rm -rf "$PREFIX"
    say "Сервер удалён. Ключи остались в $ETC, файлы — в /var/lib/clipsync (удалите вручную, если не нужны)."
    exit 0
fi

install_pkgs() {
    if have apt-get; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif have dnf; then dnf install -y -q "$@"
    elif have pacman; then pacman -Sy --noconfirm --needed "$@"
    elif have zypper; then zypper -n -q install "$@"
    elif have apk; then apk add -q "$@"
    else die "не знаю, как поставить пакеты: установите $* вручную"; fi
}

# python3 с venv и curl
need=()
have curl || need+=(curl)
if ! have python3 || ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
    if have apt-get; then need+=(python3 python3-venv)
    elif have pacman; then need+=(python)
    else need+=(python3); fi
fi
[ ${#need[@]} -eq 0 ] || { say "Ставлю ${need[*]}…"; install_pkgs "${need[@]}"; }

say "Устанавливаю relay в $PREFIX…"
mkdir -p "$PREFIX"
src_dir=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)
if [ -n "$src_dir" ] && [ -f "$src_dir/server/relay.py" ]; then
    install -m644 "$src_dir/server/relay.py" "$PREFIX/relay.py"
else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/$REF/server/relay.py" -o "$PREFIX/relay.py.part"
    mv -f "$PREFIX/relay.py.part" "$PREFIX/relay.py"
fi
[ -x "$PREFIX/venv/bin/python" ] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --disable-pip-version-check --upgrade 'cryptography>=42'

# ключи авторизации: по одному на «комнату» (общий секрет)
mkdir -p "$ETC"
chmod 700 "$ETC"
touch "$ETC/auth.keys"
chmod 600 "$ETC/auth.keys"
NEW_SECRET=0
if [ -z "$SECRET" ] && ! grep -qE '^[0-9a-f]{64}' "$ETC/auth.keys"; then
    SECRET=$("$PREFIX/venv/bin/python" "$PREFIX/relay.py" gen-secret)
    NEW_SECRET=1
fi
if [ -n "$SECRET" ]; then
    key=$("$PREFIX/venv/bin/python" "$PREFIX/relay.py" auth-key "$SECRET")
    grep -q "^$key" "$ETC/auth.keys" || echo "$key  # добавлен $(date +%F)" >>"$ETC/auth.keys"
fi

cat >"$UNIT" <<EOF
[Unit]
Description=clipsync relay: общий буфер обмена и папка для телефонов и компьютеров
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$PREFIX/venv/bin/python $PREFIX/relay.py serve --port $PORT
LoadCredential=auth.keys:$ETC/auth.keys
StateDirectory=clipsync
DynamicUser=yes
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable clipsync-relay.service >/dev/null 2>&1
systemctl restart clipsync-relay.service

# порт в файрволе
if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$PORT/tcp" >/dev/null && say "ufw: открыт порт $PORT/tcp"
elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$PORT/tcp" && firewall-cmd -q --reload && say "firewalld: открыт порт $PORT/tcp"
fi

sleep 1
systemctl is-active -q clipsync-relay.service || {
    journalctl -u clipsync-relay.service -n 20 --no-pager >&2
    die "служба не запустилась"
}

ip=$(hostname -I 2>/dev/null | awk '{print $1}')
ip=${ip:-IP_СЕРВЕРА}
say ""
say "Сервер clipsync работает на порту $PORT (служба clipsync-relay)."
if [ -n "$SECRET" ]; then
    say ""
    if [ "$NEW_SECRET" = 1 ]; then
        say "Секрет (сохраните — сервер хранит только производный ключ и показать его снова не сможет):"
    else
        say "Секрет:"
    fi
    echo "  $SECRET"
    say ""
    say "На каждом компьютере, к которому подключаете телефон (адрес — внешний IP сервера):"
    echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/$REF/install.sh | bash -s -- --server $ip:$PORT --secret '$SECRET'"
else
    say "Ключи не менялись (уже есть в $ETC/auth.keys)."
fi
say ""
say "Журнал: journalctl -u clipsync-relay -f"
