#!/bin/sh
# Move a Sigil install's config and state to the Lodeline paths after a package
# upgrade. Rerunnable, and it never overwrites or deletes data.
#
#   migrate-from-sigil <agent|sender|server|proxy> [--root DIR]
#
# Rules for each old directory:
#   - new path absent or empty: rename the old directory onto it, which is atomic.
#   - new path has entries: move each old entry that is not there yet, and report
#     the rest. A rerun picks up where an interrupted run stopped. A move across
#     filesystems never shows a partial file under the real name.
#   - old path is a symlink: leave it, and print the manual step.
# /etc/sigil and /var/log/sigil are shared between packages, so they wait until the
# package database shows no old Sigil package. Every run then repairs ownership
# over all the new directories, because each package configures before or after
# the account of another exists, and warns about old paths in config. Services
# stay stopped.
set -u

COMPONENT="${1:-}"
R=""
if [ "${2:-}" = "--root" ]; then R="${3:-}"; fi

case "$COMPONENT" in
    agent)  STATE="sigil:lodeline" ;;
    sender) STATE="sigil-sender:lodeline-sender" ;;
    server) STATE="sigil-server:lodeline-server" ;;
    proxy)  STATE="sigil-proxy:lodeline-proxy" ;;
    *) echo "usage: migrate-from-sigil <agent|sender|server|proxy> [--root DIR]" >&2; exit 2 ;;
esac

SAW_OLD=""
REPAIRS=""
NL='
'

note() { printf 'lodeline-migrate: %s\n' "$1" >&2; }

exists() { [ -e "$1" ] || [ -L "$1" ]; }

# True when the directory holds anything other than *.example files.
has_content() {
    for e in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        exists "$e" || continue
        case "$e" in *.example) ;; *) return 0 ;; esac
    done
    return 1
}

# <passwd|group> <name>. Outside --root, getent also sees LDAP and sssd accounts.
known() {
    if [ -n "$R" ]; then
        grep -q "^$2:" "$R/etc/$1" 2>/dev/null
    else
        getent "$1" "$2" >/dev/null 2>&1
    fi
}

plan_repairs() {
    for pair in "sigil lodeline" "sigil-proxy lodeline-proxy"; do
        # shellcheck disable=SC2086
        set -- $pair
        for db in passwd group; do
            if known "$db" "$1" && known "$db" "$2"; then
                REPAIRS="$REPAIRS $db $1 $2"
            elif known "$db" "$1" || { [ -n "$SAW_OLD" ] && known "$db" "$2"; }; then
                note "skipped repairing ownership from $1 to $2: one of them is not in $db, so those files keep their owner. Each package's run tries again. If this stays, check that the account resolves, then rerun $0 $COMPONENT."
            fi
        done
    done
}

fix_ownership() {
    DIR="$1"
    # shellcheck disable=SC2086
    set -- $REPAIRS
    while [ $# -gt 0 ]; do
        if [ "$1" = passwd ]; then
            find "$DIR" -user "$2" -exec chown -h "$3" {} + || note "could not chown $DIR from $2 to $3"
        else
            find "$DIR" -group "$2" -exec chgrp -h "$3" {} + || note "could not chgrp $DIR from $2 to $3"
        fi
        shift 3
    done
    if command -v restorecon >/dev/null 2>&1; then restorecon -R "$DIR" >/dev/null 2>&1 || :; fi
}

fs_of() { df -P "$1" 2>/dev/null | awk 'NR == 2 { print $1, $NF }'; }

# mv copies across filesystems, and a run killed mid-copy would leave a partial
# file under the real name. So a copy gets a temporary name, which a rerun removes,
# and only a complete copy is renamed into place.
# shortcut: df cannot see overlayfs copy-up, where mv still copies. Upgrade if a
# container image ever migrates in place.
move_entry() {
    tmp="$2.lodeline-migrate-tmp"
    rm -rf "$tmp"
    if [ "$(fs_of "${1%/*}")" = "$(fs_of "${2%/*}")" ]; then
        mv "$1" "$2"
    elif cp -a "$1" "$tmp" && mv "$tmp" "$2"; then
        rm -rf "$1"
    else
        rm -rf "$tmp"
        return 1
    fi
}

# Move one entry and its SQLite sidecars. The database goes last and only after
# its sidecars arrived, so an interrupted run leaves it at the old path with the
# rerun free to finish. A sidecar whose database is already at the new path is
# not from this script. It may belong to another database, and pairing a WAL with
# the wrong database corrupts it, so it stays for a person to judge.
move_family() {
    for s in "" -wal -shm -journal; do
        if exists "$1$s" && { exists "$2" || exists "$2$s"; }; then return 1; fi
    done
    for s in -wal -shm -journal ""; do
        if exists "$1$s"; then move_entry "$1$s" "$2$s" || return 1; fi
    done
}

merge_entries() {
    kept=""
    shown=""
    for e in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        exists "$e" || continue
        name=${e##*/}
        case "$name" in *.example) if exists "$2/$name"; then continue; fi ;; esac
        case "$name" in
            ?*-wal) base=${name%-wal} ;;
            ?*-shm) base=${name%-shm} ;;
            ?*-journal) base=${name%-journal} ;;
            *) base=$name ;;
        esac
        case "$kept$NL" in *"$NL$base$NL"*) continue ;; esac
        if ! move_family "$1/$base" "$2/$base"; then
            kept="$kept$NL$base"
            shown="${shown:+$shown, }$base"
        fi
    done
    rmdir "$1" 2>/dev/null || :
    [ -z "$kept" ]
}

# Works when the new directory is missing or holds only packaged examples, and
# stops before the mv when it holds anything else.
swap_command() {
    printf 'mkdir -p %s && rm -f %s/*.example && rmdir %s && mv %s %s' "$2" "$2" "$2" "$1" "$2"
}

move_dir() {
    old="$R$1"; new="$R$2"
    if [ -L "$old" ]; then
        SAW_OLD=1
        note "kept $1: it is a symlink to $(readlink "$old"), so nothing moved. $2 would start empty, and the agent would make a new host_id. Before starting the service, run: $(swap_command "$1" "$2"). Then rerun $0 $COMPONENT to repair ownership."
        return 0
    fi
    if [ ! -d "$old" ] || ! has_content "$old"; then return 0; fi
    SAW_OLD=1
    if [ -L "$new" ] || { [ -e "$new" ] && [ ! -d "$new" ]; }; then
        note "kept $1: $2 is not a plain directory. Nothing was moved, merge them by hand."
        return 0
    fi
    rmdir "$new" 2>/dev/null
    if [ ! -e "$new" ]; then
        # Same parent directory, so this is a rename or a failure, never a copy.
        if mv "$old" "$new"; then note "moved $1 to $2"; else note "could not move $1 to $2"; fi
    elif merge_entries "$old" "$new"; then
        note "moved $1 to $2"
    else
        note "kept in $1: $shown. Each could not move or is already in $2, so nothing was overwritten. Merge them by hand before starting the service. Keep a database with its -wal and -shm files."
    fi
}

warn_old_paths() {
    for dir in /etc/lodeline /etc/lodeline-server /etc/sigil /etc/sigil-server; do
        if [ ! -d "$R$dir" ]; then continue; fi
        grep -rlIE --exclude='*.example' '/(etc|var/lib|var/log|run|opt)/sigil' "$R$dir" 2>/dev/null | while IFS= read -r f; do
            note "${f#"$R"} still names an old /sigil path, update it by hand"
        done
    done
}

has_dpkg() { [ -f "$R/var/lib/dpkg/status" ] && command -v dpkg-query >/dev/null 2>&1; }
has_rpm() {
    { [ -d "$R/var/lib/rpm" ] || [ -d "$R/usr/lib/sysimage/rpm" ]; } && command -v rpm >/dev/null 2>&1
}

# Removed packages stay in dpkg's database, with their version, as config-files.
installed_versions() {
    if has_dpkg; then
        # shellcheck disable=SC2016
        dpkg-query --admindir="$R/var/lib/dpkg" -W -f='${db:Status-Status} ${Version}\n' "$1" 2>/dev/null |
            awk '$1 != "not-installed" && $1 != "config-files" { print $2 }'
    fi
    if has_rpm; then rpm --root "${R:-/}" -q --qf '%{VERSION}\n' "$1" 2>/dev/null; fi
}

# shortcut: the ebook editor at 0.x, on Debian ports and end-of-life Ubuntu where
# no Lodeline package ships, reads as ours. Upgrade if those become targets.
is_old_sigil_version() {
    case "$1" in 0.[0-9] | 0.1[01] | 0.[0-9][.~+-]* | 0.1[01][.~+-]*) return 0 ;; esac
    return 1
}

waiting=""
for p in sigil sigil-sender sigil-server sigil-proxy; do
    if has_dpkg || has_rpm; then
        for v in $(installed_versions "$p"); do
            if is_old_sigil_version "$v"; then waiting="$waiting $p"; break; fi
        done
    elif [ -e "$R/usr/bin/$p" ]; then
        waiting="$waiting $p"
    fi
done

olds=${STATE%%:*}; news=${STATE##*:}
move_dir "/var/lib/$olds" "/var/lib/$news"
if [ "$COMPONENT" != agent ]; then move_dir "/var/log/$olds" "/var/log/$news"; fi
if [ "$COMPONENT" = server ]; then move_dir /etc/sigil-server /etc/lodeline-server; fi

for shared in /etc /var/log; do
    if [ -z "$waiting" ]; then
        move_dir "$shared/sigil" "$shared/lodeline"
    elif [ -d "$R$shared/sigil" ] && has_content "$R$shared/sigil"; then
        SAW_OLD=1
        if has_dpkg || has_rpm; then
            note "kept $shared/sigil: still used by$waiting. Upgrade those packages to finish."
        else
            note "kept $shared/sigil: no package database here, and /usr/bin has$waiting, which may be an old Sigil binary still using it. If it is not, run: $(swap_command "$shared/sigil" "$shared/lodeline"). Then rerun $0 $COMPONENT."
        fi
    fi
done

plan_repairs
for dir in /etc/lodeline /etc/lodeline-server \
    /var/lib/lodeline /var/lib/lodeline-sender /var/lib/lodeline-server /var/lib/lodeline-proxy \
    /var/log/lodeline /var/log/lodeline-sender /var/log/lodeline-server /var/log/lodeline-proxy; do
    if [ -d "$R$dir" ]; then fix_ownership "$R$dir/"; fi
done

warn_old_paths
if [ -n "$SAW_OLD" ]; then
    note "$news stays stopped: packages never enable services. Finish any step above, then run: systemctl enable --now $news"
fi
exit 0
