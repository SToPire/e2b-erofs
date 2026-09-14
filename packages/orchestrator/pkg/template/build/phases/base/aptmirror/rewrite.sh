# Only Debian itself: Ubuntu and ID_LIKE derivatives keep their own repositories.
if [ "$E2B_DISTRO_ID" = debian ]; then
    echo "[provision] Debian apt archive=$E2B_APT_ARCHIVE security=$E2B_APT_SECURITY"
    for e2b_source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$e2b_source" ] || continue
        e2b_tmp=$("$BUSYBOX" mktemp)
        if ! "$BUSYBOX" awk -v archive="$E2B_APT_ARCHIVE" -v security="$E2B_APT_SECURITY" '
        function replace_uri(uri, clean) {
            clean = uri
            sub(/\/$/, "", clean)
            if (clean ~ /^https?:\/\/deb\.debian\.org\/debian$/) return archive
            if (clean ~ /^https?:\/\/(deb\.debian\.org\/debian-security|security\.debian\.org\/(debian-security|debian))$/) return security
            return uri
        }
        function rewrite(s, out, token) {
            out = ""
            while (match(s, /[^ \t\r]+/)) {
                out = out substr(s, 1, RSTART-1)
                token = substr(s, RSTART, RLENGTH)
                out = out replace_uri(token)
                s = substr(s, RSTART+RLENGTH)
            }
            return out s
        }
        /^[ \t]*#/ { print; next }
        FILENAME ~ /\.sources$/ {
            if ($0 ~ /^[^ \t]/ || $0 ~ /^[ \t]*$/) in_uris = 0
            if (tolower($0) ~ /^uris:/) {
                in_uris = 1
                colon = index($0, ":")
                print substr($0, 1, colon) rewrite(substr($0, colon+1))
            } else if (in_uris) print rewrite($0)
            else print
            next
        }
        {
            if (match($0, /^[ \t]*deb(-src)?[ \t]+(\[[^]]*\][ \t]+)?/)) {
                prefix = substr($0, 1, RLENGTH)
                rest = substr($0, RLENGTH+1)
                if (match(rest, /^[^ \t\r#]+/)) {
                    print prefix replace_uri(substr(rest, 1, RLENGTH)) substr(rest, RLENGTH+1)
                    next
                }
            }
            print
        }
        ' "$e2b_source" > "$e2b_tmp"; then
            "$BUSYBOX" rm -f "$e2b_tmp"
            echo "[provision] ERROR: apt source rewrite failed: $e2b_source" >&2
            exit 1
        fi
        if ! "$BUSYBOX" cmp -s "$e2b_tmp" "$e2b_source"; then
            "$BUSYBOX" cat "$e2b_tmp" > "$e2b_source"
            echo "[provision] Rewrote Debian apt URIs in $e2b_source"
        fi
        "$BUSYBOX" rm -f "$e2b_tmp"
    done
fi
