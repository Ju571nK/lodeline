#!/bin/sh
# Move a Sigil install's config and state to the Lodeline paths after a package
# upgrade. Rerunnable, and it never overwrites or deletes data.
#
#   migrate-from-sigil <agent|sender|server|proxy> [--root DIR]
#
# Rules for each old directory:
#   - new path absent: rename the old directory onto it.
#   - new path holds nothing but packaged *.example files (or is empty, as
#     tmpfiles leaves it): move the old entries in, keeping what is there.
#   - new path has real content: leave both alone and say so.
# /etc/sigil is shared by every package, so it waits until no old binary is left.
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

note() { printf 'lodeline-migrate: %s\n' "$1" >&2; }

# True when the directory holds anything other than *.example files.
has_content() {
    for e in "$1"/* "$1"/.[!.]*; do
        [ -e "$e" ] || [ -L "$e" ] || continue
        case "$e" in *.example) ;; *) return 0 ;; esac
    done
    return 1
}

known() { grep -q "^$1:" "$2" 2>/dev/null; }

fix_ownership() {
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

move_dir() {
    old="$R$1"; new="$R$2"
    if [ ! -d "$old" ] || [ -L "$old" ] || ! has_content "$old"; then return 0; fi
    if [ -L "$new" ] || { [ -e "$new" ] && { [ ! -d "$new" ] || has_content "$new"; }; }; then
        note "kept $1: $2 already has content. Nothing was moved, merge them by hand."
        return 0
    fi
    if [ ! -e "$new" ]; then
        mv "$old" "$new" || { note "could not move $1 to $2"; return 0; }
    else
        for e in "$old"/* "$old"/.[!.]*; do
            [ -e "$e" ] || [ -L "$e" ] || continue
            target="$new/$(basename "$e")"
            if [ -e "$target" ] || [ -L "$target" ]; then continue; fi
            mv "$e" "$target" || note "could not move $e to $target"
        done
        rmdir "$old" 2>/dev/null || :
    fi
    note "moved $1 to $2"
    DIR="$new"
    fix_ownership
    grep -rlE '/(etc|var/lib|var/log|run)/sigil' --include='*.yaml' "$new" 2>/dev/null | while IFS= read -r f; do
        note "$f still names an old /sigil path, update it by hand"
    done
}

old_binaries=""
for b in sigil sigil-sender sigil-server sigil-proxy; do
    if [ -e "$R/usr/bin/$b" ]; then old_binaries="$old_binaries $b"; fi
done

olds=${STATE%%:*}; news=${STATE##*:}
move_dir "/var/lib/$olds" "/var/lib/$news"
move_dir "/var/log/$olds" "/var/log/$news"
if [ "$COMPONENT" = server ]; then move_dir /etc/sigil-server /etc/lodeline-server; fi

if [ -z "$old_binaries" ]; then
    move_dir /etc/sigil /etc/lodeline
elif [ -d "$R/etc/sigil" ]; then
    note "kept /etc/sigil: still used by$old_binaries. Upgrade those packages to finish."
fi
exit 0
