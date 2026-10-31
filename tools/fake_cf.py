#!/usr/bin/env python3
"""A CloudFormation-shaped endpoint: verifies SigV4, keeps a little stack state machine.

    fake_cf.py <port> <log> <access-key> <secret-key> [--no-updates] [--rollback]
"""
import hashlib
import hmac
import http.server
import json
import sys
import urllib.parse

port, log_path, access_key, secret_key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
flags = sys.argv[5:]
no_updates = "--no-updates" in flags
rollback = "--rollback" in flags

state = {"exists": no_updates, "polls": 0, "mode": "update" if no_updates else "create"}


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def verify(headers, body, signed_headers, amz_date, scope):
    canonical_headers = ""
    for name in signed_headers.split(";"):
        canonical_headers += f"{name}:{headers.get(name, '').strip()}\n"
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_request = "\n".join(["POST", "/", "", canonical_headers, signed_headers, payload_hash])
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                 hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    date_stamp, region, service, _ = scope.split("/")
    key = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    key = sign(key, region)
    key = sign(key, service)
    return hmac.new(sign(key, "aws4_request"), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()


def error(message, code="ValidationError"):
    return ("<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code>"
            "<Message>%s</Message></Error></ErrorResponse>" % (code, message)).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = raw.decode("utf-8")
        params = {k: v[0] for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()}
        action = params.get("Action", "")

        auth = self.headers.get("Authorization", "")
        problem = "missing Authorization"
        if auth.startswith("AWS4-HMAC-SHA256 "):
            parts = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
            key_id, date_stamp, region, service, terminator = parts["Credential"].split("/")
            scope = "/".join([date_stamp, region, service, terminator])
            if key_id != access_key:
                problem = "unknown access key"
            else:
                wanted = verify(self.headers, raw, parts["SignedHeaders"], self.headers.get("X-Amz-Date", ""), scope)
                problem = None if hmac.compare_digest(wanted, parts["Signature"]) else "signature mismatch"

        with open(log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps({"action": action, "ok": problem is None, "problem": problem,
                                  "params": params}) + "\n")
        if problem is not None:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(error(problem, "InvalidSignatureException"))
            return

        def send(payload, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(payload if isinstance(payload, bytes) else payload.encode())

        if action == "DescribeStacks":
            if not state["exists"]:
                send(error("Stack with id %s does not exist" % params.get("StackName", "")), 400)
                return
            state["polls"] += 1
            creating = state.get("mode") == "create"
            if state["polls"] < 2:
                status = "CREATE_IN_PROGRESS" if creating else "UPDATE_IN_PROGRESS"
                reason = ""
            elif rollback:
                status = "ROLLBACK_COMPLETE" if creating else "UPDATE_ROLLBACK_COMPLETE"
                reason = "the helper instance never came up"
            else:
                status = "CREATE_COMPLETE" if creating else "UPDATE_COMPLETE"
                reason = ""
            send("<DescribeStacksResponse><DescribeStacksResult><Stacks><member>"
                 "<StackId>arn:aws:cloudformation:us-east-1:1:stack/%s/abc</StackId>"
                 "<StackName>%s</StackName><StackStatus>%s</StackStatus>"
                 "<StackStatusReason>%s</StackStatusReason>"
                 "</member></Stacks></DescribeStacksResult></DescribeStacksResponse>"
                 % (params.get("StackName", ""), params.get("StackName", ""), status, reason))
            return

        if action in ("CreateStack", "UpdateStack"):
            if action == "CreateStack":
                state.update(exists=True, mode="create", polls=0)
                stack_id = "arn:aws:cloudformation:us-east-1:1:stack/%s/abc" % params.get("StackName", "")
                send("<CreateStackResponse><CreateStackResult><StackId>%s</StackId>"
                     "</CreateStackResult></CreateStackResponse>" % stack_id)
                return
            if no_updates:
                send(error("No updates are to be performed."), 400)
                return
            state.update(mode="update", polls=0)
            send("<UpdateStackResponse><UpdateStackResult><StackId>arn:aws:cloudformation:us-east-1:1:stack/x/abc"
                 "</StackId></UpdateStackResult></UpdateStackResponse>")
            return

        send(error("unknown action %s" % action), 400)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
