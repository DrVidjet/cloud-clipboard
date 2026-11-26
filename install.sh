#!/usr/bin/env bash
# Установка clipsync (cloud-clipboard) на компьютер, к которому подключается телефон.
#
#   curl -fsSL https://raw.githubusercontent.com/DrVidjet/cloud-clipboard/HEAD/install.sh | bash
#   curl -fsSL …/install.sh | bash -s -- --server 203.0.113.10:8765 --secret СЕКРЕТ
#
# Без --server работает только по кабелю. Ставит недостающие системные пакеты
# (через sudo), скачивает проект в ~/.local/share/cloud-clipboard, готовит .venv,
# устанавливает пользовательскую службу systemd и команду ~/.local/bin/clipsync.
# Запускать от обычного пользователя, не от root.
set -euo pipefail

REPO=${CLIPSYNC_REPO:-DrVidjet/cloud-clipboard}
REF=${CLIPSYNC_REF:-HEAD}
DIR=${CLIPSYNC_DIR:-$HOME/.local/share/cloud-clipboard}
SERVER=
SECRET=
NO_PKGS=0
NO_SERVICE=0

say() { printf '\033[1m%s\033[0m\n' "$*" >&2; }
die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --server) SERVER=$2; shift 2 ;;
        --secret) SECRET=$2; shift 2 ;;
        --dir) DIR=$2; shift 2 ;;
        --no-packages) NO_PKGS=1; shift ;;
        --no-service) NO_SERVICE=1; shift ;;
        -h | --help) sed -n '2,11p' "$0" 2>/dev/null || true; exit 0 ;;
        *) die "неизвестный параметр $1" ;;
    esac
done

[ "$(id -u)" -ne 0 ] || die "запускайте от своего пользователя (sudo попросится сам, если понадобится)"
if [ -n "$SERVER" ] && [ -z "$SECRET" ]; then
    die "вместе с --server нужен --secret (его напечатал install-server.sh)"
fi

SUDO=
[ "$(id -u)" -eq 0 ] || SUDO=sudo

# ---------- системные пакеты ----------
missing() {
    local m=()
    have curl || m+=(curl)
    have python3 && python3 -c 'import venv, ensurepip' 2>/dev/null || m+=(python)
    have javac || m+=(jdk)
    have adb || m+=(adb)
    have wl-paste || have xclip || m+=(clipboard)
    printf '%s\n' "${m[@]}"
}

pkg_names() { # логические имена → пакеты дистрибутива
    local n out=()
    for n in "$@"; do
        if have apt-get; then
            case $n in python) out+=(python3 python3-venv) ;; jdk) out+=(default-jdk-headless) ;;
                adb) out+=(adb) ;; clipboard) out+=(wl-clipboard xclip) ;; *) out+=("$n") ;; esac
        elif have dnf; then
            case $n in python) out+=(python3) ;; jdk) out+=(java-latest-openjdk-devel) ;;
                adb) out+=(android-tools) ;; clipboard) out+=(wl-clipboard xclip) ;; *) out+=("$n") ;; esac
        elif have pacman; then
            case $n in python) out+=(python) ;; jdk) out+=(jdk-openjdk) ;;
                adb) out+=(android-tools) ;; clipboard) out+=(wl-clipboard xclip) ;; *) out+=("$n") ;; esac
        elif have zypper; then
            case $n in python) out+=(python3) ;; jdk) out+=(java-21-openjdk-devel) ;;
                adb) out+=(android-tools) ;; clipboard) out+=(wl-clipboard xclip) ;; *) out+=("$n") ;; esac
        else
            return 1
        fi
    done
    printf '%s\n' "${out[@]}"
}

mapfile -t need < <(missing)
if [ ${#need[@]} -gt 0 ] && [ "$NO_PKGS" = 0 ]; then
    mapfile -t pkgs < <(pkg_names "${need[@]}") || die "неизвестный дистрибутив: установите вручную ${need[*]} (см. README)"
    say "Ставлю системные пакеты: ${pkgs[*]}"
    if have apt-get; then $SUDO apt-get update -qq && $SUDO apt-get install -y -qq "${pkgs[@]}"
    elif have dnf; then $SUDO dnf install -y -q "${pkgs[@]}"
    elif have pacman; then $SUDO pacman -Sy --noconfirm --needed "${pkgs[@]}"
    elif have zypper; then $SUDO zypper -n -q install "${pkgs[@]}"
    fi
fi

# ---------- проект ----------
if [ -n "${CLIPSYNC_SRC:-}" ]; then
    # локальная копия исходников (для проверки установщика в CI)
    mkdir -p "$DIR"
    cp -a "$CLIPSYNC_SRC/." "$DIR/"
elif [ -d "$DIR/.git" ] && have git; then
    say "Обновляю $DIR…"
    git -C "$DIR" pull -q --ff-only
elif have git; then
    say "Скачиваю проект в $DIR…"
    mkdir -p "$(dirname "$DIR")"
    if [ -e "$DIR" ]; then
        # уже распакован из архива: заменяем файлы, сохраняя .venv и config.env
        tmp=$(mktemp -d)
        git clone -q --depth 1 "https://github.com/$REPO.git" "$tmp/src"
        cp -a "$tmp/src/." "$DIR/"
        rm -rf "$tmp"
    else
        git clone -q --depth 1 "https://github.com/$REPO.git" "$DIR"
    fi
else
    say "Скачиваю проект в $DIR…"
    mkdir -p "$DIR"
    curl -fsSL "https://github.com/$REPO/archive/$REF.tar.gz" | tar -xz -C "$DIR" --strip-components=1
fi

cd "$DIR"
./clipsync setup
[ -n "$SERVER" ] && ./clipsync config SERVER "$SERVER" >/dev/null
[ -n "$SECRET" ] && ./clipsync config SECRET "$SECRET" >/dev/null

mkdir -p "$HOME/.local/bin"
ln -sf "$DIR/clipsync" "$HOME/.local/bin/clipsync"

if [ "$NO_SERVICE" = 0 ]; then
    ./clipsync install
fi

say ""
say "Готово. Команда: clipsync (ссылка в ~/.local/bin), настройки: $DIR/config.env"
if [ -z "$SERVER" ]; then
    say "Сервер не задан — синхронизация только по кабелю. Добавить позже:"
    echo "  clipsync config SERVER адрес:порт && clipsync config SECRET секрет && clipsync restart"
fi
say ""
say "Подключите телефон кабелем с включённой «Отладкой по USB» и подтвердите запрос на экране."
say "Агент установится на телефон сам; дальше он работает и без кабеля (до перезагрузки телефона)."
say "Проверка: clipsync status"
