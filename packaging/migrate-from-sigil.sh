#!/bin/sh
# Move a Sigil install's config and state to the Lodeline paths after a package
# upgrade. Rerunnable, and it never overwrites or deletes data.
#
#   migrate-from-sigil <agent|sender|server|proxy> [--root DIR]
#
# Rules for each old directory:
#   - new path absent or empty: rename the old directory onto it, which is atomic.
#   - new path has entries: move each old entry that is not there yet, and report
#     the rest. A rerun picks up where an interrupted run stopped.
#   - old path is a symlink: leave it, and print the manual step.
# /etc/sigil and /var/log/sigil are shared between packages, so they wait until no
# old binary is left. Every run then repairs ownership over all the new
# directories, because each package configures before or after the account of
# another exists, and warns about old paths in config. Services stay stopped.
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

note() { printf 'lodeline-migrate: %s\n' "$1" >&2; }

exists() { [ -e "$1" ] || [ -L "$1" ]; }

# True when the directory holds anything other than *.example files.
has_content() {
    for e in "$1"/* "$1"/.[!.]*; do
        exists "$e" || continue
        case "$e" in *.example) ;; *) return 0 ;; esac
    done
    return 1
}

known() { grep -q "^$1:" "$2" 2>/dev/null; }

fix_ownership() {
    DIR="$1"
    for pair in "sigil lodeline" "sigil-proxy lodeline-proxy"; do
        # shellcheck disable=SC2086
        set -- $pair
        if known "$1" "$R/etc/passwd" && known "$2" "$R/etc/passwd"; then
            find "$DIR" -user "$1" -exec chown -h "$2" {} + || note "could not chown $DIR from $1 to $2"
        fi
        if known "$1" "$R/etc/group" && known "$2" "$R/etc/group"; then
            find "$DIR" -group "$1" -exec chgrp -h "$2" {} + || note "could not chgrp $DIR from $1 to $2"
        fi
    done
    if command -v restorecon >/dev/null 2>&1; then restorecon -R "$DIR" >/dev/null 2>&1 || :; fi
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
        if exists "$1$s"; then mv "$1$s" "$2$s" || return 1; fi
    done
}

merge_entries() {
    kept=""
    for e in "$1"/* "$1"/.[!.]*; do
        exists "$e" || continue
        name=${e##*/}
        case "$name" in *.example) if exists "$2/$name"; then continue; fi ;; esac
        base=${name%-wal}; base=${base%-shm}; base=${base%-journal}
        case " $kept " in *" $base "*) continue ;; esac
        move_family "$1/$base" "$2/$base" || kept="$kept $base"
    done
    rmdir "$1" 2>/dev/null || :
    [ -z "$kept" ]
}

move_dir() {
    old="$R$1"; new="$R$2"
    if [ -L "$old" ]; then
        SAW_OLD=1
        note "kept $1: it is a symlink to $(readlink "$old"), so nothing moved. $2 would start empty, and the agent would make a new host_id. Before starting the service, run: rmdir $2 && mv $1 $2. Then rerun $0 $COMPONENT to repair ownership."
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
        if mv "$old" "$new"; then note "moved $1 to $2"; else note "could not move $1 to $2"; fi
    elif merge_entries "$old" "$new"; then
        note "moved $1 to $2"
    else
        note "kept in $1:$kept. Each could not move or is already in $2, so nothing was overwritten. Merge them by hand before starting the service. Keep a database with its -wal and -shm files."
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

old_binaries=""
for b in sigil sigil-sender sigil-server sigil-proxy; do
    if [ -e "$R/usr/bin/$b" ]; then old_binaries="$old_binaries $b"; fi
done

olds=${STATE%%:*}; news=${STATE##*:}
move_dir "/var/lib/$olds" "/var/lib/$news"
if [ "$COMPONENT" != agent ]; then move_dir "/var/log/$olds" "/var/log/$news"; fi
if [ "$COMPONENT" = server ]; then move_dir /etc/sigil-server /etc/lodeline-server; fi

for shared in /etc /var/log; do
    if [ -z "$old_binaries" ]; then
        move_dir "$shared/sigil" "$shared/lodeline"
    elif [ -d "$R$shared/sigil" ] && has_content "$R$shared/sigil"; then
        SAW_OLD=1
        note "kept $shared/sigil: still used by$old_binaries. Upgrade those packages to finish."
    fi
done

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
