#!/usr/bin/env bash
#
# Serve examples/nginx.conf.example under a real nginx and drive the module
# through njs, which is the only place it runs outside node.
#
# Usage:
#   ./test/nginx/check.sh                 dist/antibot.js, port 8443
#   ./test/nginx/check.sh dist/antibot.js 8443
#
# Needs nginx with ngx_http_js_module, openssl, python3 and node. The module,
# a certificate and a config are written under a temporary prefix and removed
# on exit; nothing outside it is touched.
set -euo pipefail

readonly MODULE=${1:-dist/antibot.js}
readonly PORT=${2:-8443}
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
readonly ROOT
readonly URL=https://localhost:$PORT

cd "$ROOT"
[ -f "$MODULE" ] || { echo "$MODULE not found; run ./build.sh first" >&2; exit 2; }
for tool in nginx openssl python3 node curl; do
    command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 2; }
done

TMP=$(mktemp -d)
readonly TMP
nginx_pid=""
backend_pid=""
cleanup() {
    if [ -n "$nginx_pid" ]; then
        nginx -c "$TMP/nginx.conf" -p "$TMP" -s quit 2>/dev/null || true
    fi
    if [ -n "$backend_pid" ]; then
        kill "$backend_pid" 2>/dev/null || true
    fi
    sleep 0.3
    rm -rf "$TMP"
}
trap cleanup EXIT

# The temporary prefix goes on exit, so anything worth reading afterwards is
# printed here.
fail() {
    echo "FAIL: $*" >&2
    if [ -s "$TMP/logs/error.log" ]; then
        echo "--- last 40 lines of the nginx error log ---" >&2
        tail -40 "$TMP/logs/error.log" >&2
    fi
    exit 1
}
ok()   { echo "  ok: $*"; }

# ---------------------------------------------------------------- the server

echo "== preparing a prefix under $TMP =="
mkdir -p "$TMP/njs" "$TMP/logs" "$TMP/backend/api"
install -m 644 "$MODULE" "$TMP/njs/antibot.js"
echo backend-ok   > "$TMP/backend/api/index.html"
echo backend-root > "$TMP/backend/index.html"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$TMP/localhost.key" -out "$TMP/localhost.crt" 2>"$TMP/openssl.log" \
    || { cat "$TMP/openssl.log" >&2; fail "could not make a certificate"; }

# Every path nginx writes to moves under the prefix, so the script needs no
# privilege: the compiled-in defaults are under /var and root owns them. The
# module path comes from the njs directory this run created, the listener
# from $PORT, and the policy from the example
# with its comment removed, so the header a deployment is told to set is the
# one every assertion below runs under. The challenge line is written at info,
# which nginx drops by default and this script grades.
# Searched rather than piped: find returns non-zero for a directory that is
# not there, and pipefail would turn that into a silent exit.
module_so=""
for dir in /usr/lib/nginx/modules /usr/lib64/nginx/modules \
           /usr/local/nginx/modules /usr/share/nginx/modules; do
    if [ -f "$dir/ngx_http_js_module.so" ]; then
        module_so=$dir/ngx_http_js_module.so
        break
    fi
done
[ -n "$module_so" ] || fail "ngx_http_js_module.so not found"
echo "  module: $module_so"

sed -e "s|^load_module .*|load_module $module_so;|" \
    -e "/^load_module/a error_log $TMP/logs/error.log info;" \
    -e "/^load_module/a pid $TMP/nginx.pid;" \
    -e "s|^            # add_header Content-Security-Policy|            add_header Content-Security-Policy|" \
    -e "/^http {/a \\    access_log            $TMP/logs/access.log;" \
    -e "/^http {/a \\    client_body_temp_path $TMP/body;" \
    -e "/^http {/a \\    proxy_temp_path       $TMP/proxy;" \
    -e "/^http {/a \\    fastcgi_temp_path     $TMP/fastcgi;" \
    -e "/^http {/a \\    uwsgi_temp_path       $TMP/uwsgi;" \
    -e "/^http {/a \\    scgi_temp_path        $TMP/scgi;" \
    -e "s|listen              443 ssl;|listen              $PORT ssl;|" \
    -e "s|/etc/letsencrypt/live/SERVER_NAME/fullchain.pem|$TMP/localhost.crt|" \
    -e "s|/etc/letsencrypt/live/SERVER_NAME/privkey.pem|$TMP/localhost.key|" \
    -e "s|/etc/nginx/njs/|$TMP/njs/|" \
    -e "s|SERVER_NAME|localhost|" \
    examples/nginx.conf.example > "$TMP/nginx.conf"

# http.server maps the URL onto the filesystem and nginx passes /api/ through
# unchanged, so the path has to exist.
python3 -m http.server 8080 --bind 127.0.0.1 --directory "$TMP/backend" \
    > "$TMP/backend.log" 2>&1 &
backend_pid=$!

secret() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

start_nginx() {
    env ANTIBOT_SECRET="$(secret)" "$@" nginx -c "$TMP/nginx.conf" -p "$TMP"
    nginx_pid=1
    local _
    for _ in $(seq 40); do
        curl -ksf "$URL/" -o /dev/null && return 0
        sleep 0.25
    done
    fail "nginx did not answer on $PORT"
}
stop_nginx() { nginx -c "$TMP/nginx.conf" -p "$TMP" -s quit 2>/dev/null || true; sleep 0.3; }

echo "== nginx -t =="
env ANTIBOT_SECRET="$(secret)" nginx -t -c "$TMP/nginx.conf" -p "$TMP"

echo "== serving $MODULE on $PORT =="
start_nginx

# ------------------------------------------------------------- the assertions

echo "== the gate =="

body=$(curl -ks "$URL/")
echo "$body" | grep -q 'Verifying you are not a bot' \
    || { echo "$body" | head -20; fail "a gated route did not return the challenge page"; }
ok "a gated route is answered with the challenge page"

code=$(curl -ks -o /dev/null -w '%{http_code}' "$URL/")
[ "$code" = "200" ] || fail "a challenged request answered $code, not 200"
ok "a challenged request answers 200"

headers=$(curl -ksI "$URL/")
echo "$headers" | grep -qi '^x-content-type-options: *nosniff' \
    || { echo "$headers"; fail "nosniff missing"; }
echo "$headers" | grep -qi '^cache-control: *no-store' || fail "no-store missing"
ok "nosniff and no-store present"

csp=$(echo "$headers" | tr -d '\r' | sed -n 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: //p')
[ -n "$csp" ] || { echo "$headers"; fail "no policy on the challenge response"; }
for token in "'unsafe-inline'" "'unsafe-eval'" "'wasm-unsafe-eval'" "worker-src blob:"; do
    case $csp in
        *"$token"*) ;;
        *) fail "the policy lacks $token: $csp" ;;
    esac
done
ok "the documented policy is served: $csp"

echo "== the page =="

echo "$body" | grep -q 'WebAssembly.compile' || fail "no wasm solver in the page"
echo "$body" | grep -q 'function jsSolver'   || fail "no JS solver in the page"
ok "the page carries both solvers"

wasm=$(dirname "$MODULE")/pow_solver.wasm
if [ -f "$wasm" ]; then
    b64=$(base64 < "$wasm" | tr -d '\n')
    echo "$body" | grep -qF "$b64" || fail "the page does not carry the built wasm"
    ok "the page carries the compiled solver"
fi

echo "== settings from the environment =="

# The artifact is not edited to deploy. Restarted with a difficulty no source
# constant carries, so the page can only be showing the environment.
stop_nginx
start_nginx ANTIBOT_POW_BITS=8 ANTIBOT_SITE_NAME='CI & Co'
page=$(curl -ks "$URL/")
echo "$page" | grep -q ',bits=8;' \
    || { echo "$page" | grep -o 'bits=[0-9]*' | head -1; fail "ANTIBOT_POW_BITS did not reach the page"; }
echo "$page" | grep -q '<h1>CI &amp; Co</h1>' \
    || { echo "$page" | grep -o '<h1>.*</h1>' | head -1; fail "ANTIBOT_SITE_NAME did not reach the page escaped"; }
ok "bits=8 and the escaped site name came from the environment"
stop_nginx
start_nginx

echo "== the error log =="

curl -ks "$URL/a%0Aantibot:%20forged" -o /dev/null
count=$(grep -c 'antibot: challenge served to' "$TMP/logs/error.log" || true)
if [ "$count" -eq 0 ]; then
    fail "no challenge line in the error log at info level"
fi
if grep -q '^antibot:' "$TMP/logs/error.log"; then
    grep -n '^antibot:' "$TMP/logs/error.log"
    fail "a line in the error log begins with antibot:, so one was forged"
fi
# serve_challenge runs after error_page 401, so r.uri is the internal location
# and carries nothing the client sent.
grep -o 'antibot: challenge served to .*' "$TMP/logs/error.log" | tail -1 || true
ok "$count challenge lines, none forged"

echo "== the accept path =="

# Everything above drives check() down its reject branch. Sec-Fetch-Dest keeps
# these out of the re-screen sample, which would answer with the challenge
# page 2% of the time.
ua='antibot-ci/1.0'
curl -ks -A "$ua" -H 'Sec-Fetch-Dest: empty' "$URL/" > "$TMP/page.html"
cookie=$(node test/solve-page.mjs < "$TMP/page.html")
echo "  solved $cookie"
body=$(curl -ks -A "$ua" -H 'Sec-Fetch-Dest: empty' -H "Cookie: $cookie" "$URL/")
[ "$body" = "backend-root" ] || { echo "$body" | head -20; fail "the solved cookie was not accepted"; }
ok "a solved cookie reaches the backend"

body=$(curl -ks -A 'a-different-agent/1.0' -H 'Sec-Fetch-Dest: empty' \
         -H "Cookie: $cookie" "$URL/")
echo "$body" | grep -q 'Verifying you are not a bot' \
    || { echo "$body" | head -20; fail "the cookie was accepted for another identity"; }
ok "the cookie does not travel to another identity"

echo "== cookie handling under njs =="

# Duplicates, an empty value and a malformed value are covered under node.
# This runs them through njs, including nginx's merging of repeated Cookie
# headers, which nothing else exercises.
with() { curl -ks -A "$ua" -H 'Sec-Fetch-Dest: empty' "$@" "$URL/"; }
name=${cookie%%=*}
body=$(with -H "Cookie: $name=0.0; $cookie")
[ "$body" = "backend-root" ] || fail "a junk duplicate masked the valid cookie"
body=$(with -H "Cookie: $name=0.0" -H "Cookie: $cookie")
[ "$body" = "backend-root" ] || fail "a second Cookie header masked the valid cookie"
for value in '' 'notaslot.notanonce' '0.0'; do
    body=$(with -H "Cookie: $name=$value")
    echo "$body" | grep -q 'Verifying you are not a bot' \
        || fail "cookie value '$value' was not challenged"
done
ok "duplicate, repeated header, empty and malformed all handled"

echo "== routes =="

# A POST without a cookie is answered with the challenge page and its body
# never reaches the backend. Asserted so the behaviour is recorded rather than
# discovered.
body=$(curl -ks -X POST -d 'field=value' "$URL/")
echo "$body" | grep -q 'Verifying you are not a bot' \
    || { echo "$body" | head -20; fail "a gated POST was not challenged"; }
if echo "$body" | grep -q 'backend-root'; then
    fail "a gated POST reached the backend"
fi
ok "a gated POST is challenged and loses its body"

body=$(curl -ks "$URL/api/")
[ "$body" = "backend-ok" ] || { echo "$body" | head -20; fail "/api/ did not reach the backend"; }
ok "a non-browser route is not gated"

echo "== counters =="

# Read after everything above, so the numbers are the ones this run caused.
# The zone is shared across workers, so which one answers does not matter.
counters=$(curl -ks "$URL/__antibot_status")
while IFS= read -r line; do echo "  $line"; done <<< "$counters"
get_count() { echo "$counters" | awk -v k="$1" '$1 == k { print $2 }'; }
for key in challenges accepted rejected rescreened; do
    value=$(get_count "$key")
    case $value in
        ''|*[!0-9]*) fail "the counter $key is not a number: '$value'" ;;
    esac
done
[ "$(get_count challenges)" -gt 0 ] || fail "no challenge was counted"
[ "$(get_count accepted)" -gt 0 ]   || fail "no acceptance was counted"
[ "$(get_count rejected)" -gt 0 ]   || fail "no rejection was counted"
[ "$(get_count misconfigured)" -eq 0 ] || fail "a request found no usable secret"
[ "$(get_count bits)" -eq 22 ] || fail "the counters report bits=$(get_count bits)"
case $counters in
    *"zone antibot"*) ;;
    *) fail "the shared zone is not in use: $counters" ;;
esac
ok "the counters match what this run caused"

echo
echo "all nginx checks passed"
