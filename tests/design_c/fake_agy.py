"""Fake agy ACP server for conversation/facade tests: really calls the parked MCP endpoint over HTTP.

argv[1]: JSON behaviour {"script": [[step, ...] per prompt, ...], "log": path, "new_delay": seconds}
steps: {"call": {"name": str, "arguments": {...}}}  POST tools/call to the session's MCP server, wait for the answer
       {"text": str}                                 agent_message_chunk
       {"echo_last": true}                            agent_message_chunk with the last tool answer text
       {"silent": seconds}                            sleep without any output
       {"stderr": str}                                one line on stderr
       {"foreign": true}                              a tool_call update that is not ours (native tool running)
       {"refused_native": true}                       a native tool tried and refused (pending -> failed)
Prompts are numbered across fake processes (counted from the log), so a respawned child continues the script.
A prompt with no script entry answers "ok". session/cancel ends the in-flight prompt with stopReason cancelled.
The log file gets one JSON line per event: {"ev": "prompt"|"new"|"answer"|"cancel", ...}.
"""

import json
import sys
import threading
import time
import urllib.request

B = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
LOG = B.get("log")
lock = threading.Lock()
state = {"sessions": {}, "n_prompt": 0, "inflight": None, "next_sid": 0, "client_pending": {}}


def _call_client(method, params, *, cancel_after=None):
    rid = f"ag-{time.monotonic_ns()}"
    ev = threading.Event()
    slot = {"event": ev, "resp": None}
    with lock:
        state["client_pending"][rid] = slot
    emit({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    if cancel_after is not None:
        time.sleep(float(cancel_after))
        emit({"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": rid}})
    ev.wait(10.0)
    with lock:
        state["client_pending"].pop(rid, None)
    log(ev="client_resp", method=method, resp=slot["resp"])
    return slot["resp"]


def log(**kw):
    if LOG:
        with lock, open(LOG, "a") as fh:
            fh.write(json.dumps(kw) + "\n")


def emit(obj):
    with lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def update(sid, payload):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": payload}})


def mcp_call(server, name, arguments):
    headers = {h["name"]: h["value"] for h in server.get("headers", [])}
    headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}).encode()
    req = urllib.request.Request(server["url"], data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            data = json.loads(resp.read() or b"{}")
    except Exception as exc:  # noqa: BLE001 - dropped connection / refused
        return {"error": type(exc).__name__}
    res = data.get("result") or {}
    text = "".join(c.get("text", "") for c in res.get("content", []))
    imgs = [c.get("mimeType") for c in res.get("content", []) if c.get("type") == "image"]
    return {"text": text, "isError": bool(res.get("isError")), **({"images": imgs} if imgs else {})}


def run_prompt(rid, sid, text, steps, token):
    server = state["sessions"][sid]
    last = ""
    pending_result_usage = [None]
    for step in steps:
        if token["cancelled"]:
            return
        if "call" in step:
            tcid = f"tc{time.monotonic_ns()}"
            update(sid, {"sessionUpdate": "tool_call", "toolCallId": tcid, "status": "in_progress",
                         "title": server["name"] + "_" + step["call"]["name"],
                         "_meta": {"is_mcp_tool_call": True,
                                   "mcp": {"server": server["name"], "tool": step["call"]["name"]}}})
            ans = mcp_call(server, step["call"]["name"], step["call"].get("arguments", {}))
            log(ev="answer", sid=sid, name=step["call"]["name"], **ans)
            last = ans.get("text", "")
            if token["cancelled"]:
                return
            update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": tcid,
                         "status": "failed" if ans.get("isError") or ans.get("error") else "completed"})
        elif "text" in step:
            update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": step["text"]}})
        elif step.get("echo_last"):
            update(sid, {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": last}})
        elif "silent" in step:
            time.sleep(step["silent"])
        elif step.get("foreign"):
            update(sid, {"sessionUpdate": "tool_call", "toolCallId": "native1", "status": "in_progress",
                         "title": "view_file"})
        elif step.get("refused_native"):
            update(sid, {"sessionUpdate": "tool_call", "toolCallId": "native0", "status": "pending",
                         "title": "write_to_file"})
            update(sid, {"sessionUpdate": "tool_call_update", "toolCallId": "native0", "status": "failed"})
        elif "stderr" in step:
            sys.stderr.write(step["stderr"] + "\n")
            sys.stderr.flush()
        elif "usage" in step:
            update(sid, {"sessionUpdate": "usage_update", **step["usage"]})
        elif "result_usage" in step:
            pending_result_usage[0] = step["result_usage"]  # goes into the session/prompt RESULT, not a frame
        elif "client_req" in step:
            cr = step["client_req"]
            _call_client(cr["method"], cr.get("params") or {}, cancel_after=cr.get("cancel_after"))
    with lock:
        if token["done"]:
            return
        token["done"] = True
    result: dict = {"stopReason": "end_turn"}
    if pending_result_usage[0] is not None:
        result["usage"] = pending_result_usage[0]
    emit({"jsonrpc": "2.0", "id": rid, "result": result})


def main():
    for line in sys.stdin:
        msg = json.loads(line)
        method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method is None and rid is not None:
            with lock:
                slot = state["client_pending"].get(rid)
            if slot is not None:
                slot["resp"] = msg
                slot["event"].set()
            continue
        if method == "initialize":
            if B.get("log_init"):
                log(ev="init", client=params.get("clientInfo"), caps=params.get("clientCapabilities"))
            acaps = {"mcpCapabilities": {"http": True}, "promptCapabilities": {"image": True}}
            if B.get("session_close"):
                acaps["sessionCapabilities"] = {"close": {}}
            if B.get("load_session"):
                acaps["loadSession"] = True
            if B.get("session_resume"):
                acaps.setdefault("sessionCapabilities", {})["resume"] = {}
            emit({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": 1, "agentInfo": {"name": "antigravity-acp", "version": B.get("version", "1.5.2")},
                "agentCapabilities": acaps}})
        elif method == "session/close":
            log(ev="close_session", sid=params.get("sessionId"))
            err_code = B.get("session_close_error")
            if err_code is not None:
                emit({"jsonrpc": "2.0", "id": rid, "error": {"code": int(err_code), "message": "not found"}})
            else:
                emit({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "session/new":
            state["next_sid"] += 1
            sid = f"s{state['next_sid']}"
            state["sessions"][sid] = params["mcpServers"][0]
            log(ev="new", sid=sid, meta=params.get("_meta"))
            reply = {"jsonrpc": "2.0", "id": rid, "result": {"sessionId": sid}}
            if B.get("new_delay"):
                threading.Timer(float(B["new_delay"]), emit, args=(reply,)).start()
            else:
                emit(reply)
        elif method in ("session/set_model", "session/set_config_option"):
            emit({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "session/prompt":
            sid = params["sessionId"]
            text = "".join(b.get("text", "") for b in params["prompt"] if b.get("type") == "text")
            images = [b.get("mimeType") for b in params["prompt"] if b.get("type") == "image"]
            n = sum(1 for line in open(LOG) if '"ev": "prompt"' in line) if LOG and __import__("os").path.exists(LOG) else 0
            log(ev="prompt", sid=sid, n=n, text=text, images=images)
            script = B.get("script", [])
            steps = script[n] if n < len(script) else [{"text": "ok"}]
            token = {"cancelled": False, "done": False, "rid": rid}
            state["inflight"] = token
            threading.Thread(target=run_prompt, args=(rid, sid, text, steps, token), daemon=True).start()
        elif method == "session/cancel":
            token = state["inflight"]
            log(ev="cancel", sid=params.get("sessionId"))
            if token and not token["done"]:
                token["cancelled"] = True
                token["done"] = True
                emit({"jsonrpc": "2.0", "id": token["rid"], "result": {"stopReason": "cancelled"}})
        elif rid is not None and method:
            emit({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nf"}})


main()
