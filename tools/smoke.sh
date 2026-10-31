#!/usr/bin/env bash
# Create, update, no-op, rollback: a small stack state machine behind a real SigV4 check.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

log="$(mktemp)"; port=$((31000 + RANDOM % 900))
access="AKIDEXAMPLE"; secret="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
start() { python3 tools/fake_cf.py "$port" "$log" "$access" "$secret" "$@" & server=$!
  for _ in $(seq 1 40); do nc -z 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.1; done; }
stop() { kill $server 2>/dev/null; wait $server 2>/dev/null; }
start; trap 'stop' EXIT

ws="$(mktemp -d)"
write_secret() { printf '{"accessKey": "%s", "secretKey": "%s"}' "$1" "$2" >"$ws/.secrets.json"; }
write_input() { # write_input [key=value ...]
  python3 - "$ws/input.json" "$port" "$@" <<'PY'
import json, sys
path, port = sys.argv[1], sys.argv[2]
doc = {"region": "us-east-1", "stackName": "acme-net", "endpoint": "http://127.0.0.1:" + port,
       "templateBody": "Resources: {}\n", "parameters": "Env=prod,Size=2",
       "capabilities": "CAPABILITY_IAM,CAPABILITY_NAMED_IAM", "waitTimeoutSeconds": "60"}
for pair in sys.argv[3:]:
    key, _, value = pair.partition("=")
    doc[key] = value
json.dump(doc, open(path, "w"))
PY
}

# --- the stack does not exist yet: create it and wait for CREATE_COMPLETE
write_input
write_secret "$access" "$secret"
run "$ws" >"$ws/atom.log" 2>&1 || fail "create: $(cat "$ws/output.json") $(tail -3 "$ws/atom.log")"
[ "$(output "$ws" action)" = "create" ] || fail "action: $(cat "$ws/output.json")"
[ "$(output "$ws" status)" = "CREATE_COMPLETE" ] || fail "status: $(cat "$ws/output.json")"
[ -n "$(output "$ws" stackId)" ] || fail "stack id should come back: $(cat "$ws/output.json")"
grep -q "is CREATE_IN_PROGRESS" "$ws/atom.log" || fail "the poll should have seen the in-progress state"

# the request shape: numbered capabilities and parameters, template in the body
python3 - "$log" <<'PY' || fail "the CreateStack parameters were wrong"
import json, sys
entries = [json.loads(l) for l in open(sys.argv[1]).read().strip().splitlines()]
assert all(e["ok"] for e in entries), entries
create = [e for e in entries if e["action"] == "CreateStack"][0]["params"]
assert create["Capabilities.member.1"] == "CAPABILITY_IAM", create
assert create["Capabilities.member.2"] == "CAPABILITY_NAMED_IAM", create
assert create["Parameters.member.1.ParameterKey"] == "Env", create
assert create["Parameters.member.2.ParameterValue"] == "2", create
assert "templateBody" not in create and create["TemplateBody"] == "Resources: {}\n", create
PY

# --- the second run finds the stack and updates it
: >"$log"
write_input
write_secret "$access" "$secret"
run "$ws" >"$ws/atom.log" 2>&1 || fail "update: $(cat "$ws/output.json")"
[ "$(output "$ws" action)" = "update" ] || fail "action: $(cat "$ws/output.json")"
[ "$(output "$ws" status)" = "UPDATE_COMPLETE" ] || fail "status: $(cat "$ws/output.json")"
grep -q '"action": "UpdateStack"' "$log" || fail "the second run should call UpdateStack"

# --- a wrong secret is refused by the endpoint's own signature check
: >"$log"
write_secret "$access" "wrong-secret"
write_input
run "$ws" >"$ws/atom.log" 2>&1 && fail "a bad signature must fail"
grep -q "InvalidSignatureException" "$ws/output.json" || fail "AWS's error should surface: $(cat "$ws/output.json")"
grep -q '"errorType":1' "$ws/output.json" || fail "a refused request is a USER error"
write_secret "$access" "$secret"

# --- an update with no changes is a success, not a failure
stop; start --no-updates
write_input
write_secret "$access" "$secret"
run "$ws" >"$ws/atom.log" 2>&1 || fail "no-op update must not fail: $(cat "$ws/output.json")"
[ "$(output "$ws" action)" = "noop" ] || fail "action should be noop: $(cat "$ws/output.json")"
grep -q "already up to date" "$ws/atom.log" || fail "the log should say why"

# --- a rollback fails the step and quotes the reason
stop; start --rollback
write_input
write_secret "$access" "$secret"
run "$ws" >"$ws/atom.log" 2>&1 && fail "a rolled-back stack must fail the step"
grep -q "ROLLBACK_COMPLETE" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"
grep -q "the helper instance never came up" "$ws/output.json" || fail "the reason must be quoted: $(cat "$ws/output.json")"

# --- wait=false returns after the call
stop; start
write_input wait=false
write_secret "$access" "$secret"
run "$ws" >"$ws/atom.log" 2>&1 || fail "wait=false: $(cat "$ws/output.json")"
[ "$(output "$ws" status)" = "started" ] || fail "wait=false should report 'started': $(cat "$ws/output.json")"

# --- bad input
write_input templateBody=
write_secret "$access" "$secret"
run "$ws" >"$ws/atom.log" 2>&1 && fail "a stack without a template must be refused"
grep -q "templateBody or templateUrl is required" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

echo "smoke ok: real SigV4, create, update, rejected signature, no-op update, rollback fails, wait=false, bad input"
