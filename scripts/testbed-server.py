#!/usr/bin/env python3
"""Serve the testbed cases over TLS and record what each client actually did.

One listener, three certificates: the permitted host, the forbidden host, and the bare IP.
A phone cannot be given an /etc/hosts entry, so the hostnames resolve through sslip.io to
this Mac's LAN address; the permitted and forbidden cases differ only in the name, which is
what makes a difference in outcome attributable to the name constraints alone.

Why this server keeps a log instead of leaving the verdict to the eye: Safari on iOS shows
no error code, so "the page did not open" is ambiguous — the constraint may have worked, or
DNS may have failed and nothing ever reached the Mac. Those two look identical on the phone
and completely different from here:

  handshake completed + request served -> the client trusted the chain
  connection arrived, handshake failed -> the client rejected the certificate
  no connection at all                 -> nothing was tested; DNS or routing

Only the middle line proves a rejection, so it is recorded rather than inferred.
"""

import argparse
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NO_SNI = "(no SNI)"


def current_lan_ip():
    for interface in ("en0", "en1"):
        try:
            out = subprocess.run(
                ["/usr/sbin/ipconfig", "getifaddr", interface],
                capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        ip = out.stdout.strip()
        if ip:
            return ip
    return None


def local_addresses():
    """Addresses that mean "this Mac", so its own probes are not mistaken for the phone."""
    addrs = {"127.0.0.1", "::1"}
    ip = current_lan_ip()
    if ip:
        addrs.add(ip)
    try:
        addrs.update(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None))
    except OSError:
        pass
    return addrs


class Observer:
    """Records one outcome per (client, server name) pair.

    The report is rewritten after every event rather than only on shutdown: the run takes
    as long as it takes to install a profile and open three URLs by hand, so the process
    may well be killed by a timeout or closed terminal before it can summarise anything.
    A report that only exists after a clean exit is a report you lose.
    """

    def __init__(self, locals_, on_change=None):
        self.locals = locals_
        self.events = []
        self.lock = threading.Lock()
        self.on_change = on_change

    def record(self, client, server_name, outcome, detail=""):
        with self.lock:
            self.events.append({
                "client": client,
                "remote": client not in self.locals,
                "serverName": server_name or NO_SNI,
                "outcome": outcome,
                "detail": detail,
            })
        origin = "phone/remote" if client not in self.locals else "local"
        print(f"  [{origin}] {client} {server_name or NO_SNI}: {outcome}"
              + (f" ({detail})" if detail else ""), flush=True)
        if self.on_change:
            self.on_change()

    def outcomes_for(self, server_name, remote_only=True):
        with self.lock:
            return [e["outcome"] for e in self.events
                    if e["serverName"] == (server_name or NO_SNI)
                    and (e["remote"] or not remote_only)]

    def behaviour_for(self, server_name, remote_only=True):
        """Classify what remote clients did with one server name.

        Safari offers "visit this website anyway", and a click-through reaches the server
        as an ordinary completed handshake — identical to genuine trust unless the earlier
        rejection from the same client is taken into account. Counting an override as trust
        turns a failed run into a false PASS, so the order of events per client decides:

          served with no prior rejection -> the client trusted the chain
          served after a rejection       -> the human overrode the warning
          rejection and nothing else     -> the client refused
        """
        name = server_name or NO_SNI
        per_client = {}
        with self.lock:
            for event in self.events:
                if event["serverName"] != name or (remote_only and not event["remote"]):
                    continue
                state = per_client.setdefault(
                    event["client"], {"trusted": False, "override": False, "rejected": False})
                if event["outcome"].startswith("handshake rejected"):
                    state["rejected"] = True
                elif event["outcome"] == "served":
                    if state["rejected"]:
                        state["override"] = True
                    else:
                        state["trusted"] = True
        return {
            "seen": bool(per_client),
            "trusted": any(s["trusted"] for s in per_client.values()),
            "override": any(s["override"] for s in per_client.values()),
            "rejected": any(s["rejected"] for s in per_client.values()),
        }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        name = getattr(self.connection, "testbed_sni", None) or NO_SNI
        self.server.observer.record(self.client_address[0], name, "served")
        body = f"served: {name}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass          # the observer is the log


class TestbedServer(ThreadingHTTPServer):
    """Wraps each accepted connection itself so a failed handshake can be recorded.

    Wrapping the listening socket instead would raise inside accept(), and socketserver
    silently swallows the error — which is exactly the evidence we need to keep.
    """

    daemon_threads = True

    def __init__(self, address, contexts, default_ctx, observer):
        self.contexts = contexts
        self.default_ctx = default_ctx
        self.observer = observer
        self._last_sni = None
        super().__init__(address, Handler)

    def sni_callback(self, sock, server_name, _ctx):
        self._last_sni = server_name
        sock.context = self.contexts.get(server_name, self.default_ctx)

    def get_request(self):
        conn, addr = self.socket.accept()
        self._last_sni = None
        try:
            tls = self.default_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as error:
            # The client received our certificate and refused it. This is what a phone
            # rejecting a name-constraint violation looks like from the server side.
            self.observer.record(addr[0], self._last_sni, "handshake rejected by client",
                                 type(error).__name__)
            conn.close()
            raise
        tls.testbed_sni = self._last_sni
        return tls, addr


def build_contexts(manifest):
    contexts, default = {}, None
    for case in manifest["cases"]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(case["certificateChainPEM"], case["privateKeyPEM"])
        if case["serverName"]:
            contexts[case["serverName"]] = ctx
        else:
            default = ctx          # bare-IP case: the client sends no SNI
    if default is None:
        default = next(iter(contexts.values()))
    return contexts, default


def verdicts(manifest, observer):
    """Turn recorded events into a per-case verdict for remote (phone) clients.

    The permitted case is the control. If the client does not trust the chain even there,
    the anchor is not trusted at all — usually full trust was never enabled — and every
    rejection elsewhere has that same cause. Reporting those as PASS would be the exact
    false positive this whole apparatus exists to prevent, so the run is marked invalid
    instead.
    """
    def control_for(case):
        """A control must build its path the same way as the case it vouches for.

        Judging a forbidden case that ships its whole chain against a permitted case that
        relies on the trust store compares two different failures: the first run to prove
        the constraint works was reported INVALID for exactly that reason.
        """
        return next((c for c in manifest["cases"]
                     if c["expectation"] == "valid"
                     and c.get("sendsFullChain") == case.get("sendsFullChain")), None)

    rows = []
    for case in manifest["cases"]:
        state = observer.behaviour_for(case["serverName"])
        expect = case["expectation"]

        if not state["seen"]:
            verdict, why = ("NOT TESTED",
                            "телефон не подключался — Wi-Fi, DNS или сменившийся LAN-адрес")
        elif expect == "valid":
            if state["trusted"]:
                verdict, why = "PASS", "страница открылась без предупреждения — корень доверен"
            elif state["override"]:
                verdict, why = ("FAIL", "телефон НЕ доверяет корню: было предупреждение, "
                                        "страница открылась только после «всё равно открыть». "
                                        "Включите полное доверие в Настройки → Основные → "
                                        "Об этом устройстве → Доверие сертификатам")
            else:
                verdict, why = ("FAIL", "телефон отверг сертификат для РАЗРЕШЁННОГО домена — "
                                        "корень не доверен")
        elif (control := control_for(case)) is None:
            verdict, why = ("INVALID", "нет сопоставимого контрольного кейса — "
                                       "отказ не с чем сравнить")
        elif not observer.behaviour_for(control["serverName"])["trusted"]:
            verdict, why = ("INVALID", f"сопоставимый контроль ({control['name']}) не прошёл, "
                                       "поэтому этот отказ ничего не доказывает")
        elif state["trusted"]:
            verdict, why = "FAIL", "iOS ПРИНЯЛ сертификат вне списка — ограничение не работает"
        elif state["rejected"]:
            why = "телефон отверг сертификат"
            if state["override"]:
                why += " (вы продавили предупреждение вручную — на вердикт не влияет)"
            verdict = "PASS"
        else:
            verdict, why = "NOT TESTED", "подключения не было"

        rows.append({"case": case["name"], "url": case["url"],
                     "expect": expect, "verdict": verdict, "why": why})
    return rows


def write_report(manifest, observer, path):
    """Persist the current verdicts. Atomic, so a reader never sees a half-written file."""
    if not path:
        return verdicts(manifest, observer)
    rows = verdicts(manifest, observer)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as handle:
        json.dump({"rows": rows, "events": observer.events}, handle,
                  ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return rows


def report(manifest, observer, path):
    rows = write_report(manifest, observer, path)
    width = max(len(r["case"]) for r in rows)
    print("\n=== Результат проверки с телефона ===")
    for r in rows:
        print(f"  {r['case']:<{width}}  {r['verdict']:<10} {r['why']}")
    if any(r["verdict"] == "NOT TESTED" for r in rows):
        print("\n  NOT TESTED means nothing was proven for that case — не считайте это успехом.")
    if path:
        print(f"\n  записано: {path}")
    return rows


def main():
    # Without this, running detached (`... &`) buffers stdout and the operator sees no URLs
    # and no confirmation the server came up — the run looks broken before it starts.
    sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--report", help="where to write the recorded phone verdicts (JSON)")
    args = parser.parse_args()

    with open(args.manifest) as handle:
        manifest = json.load(handle)

    live = current_lan_ip()
    if live and live != manifest["lanIP"]:
        sys.exit(
            f"LAN address changed ({manifest['lanIP']} -> {live}).\n"
            "Regenerate the testbed: the certificates are bound to the old names, so every\n"
            "case would fail for the wrong reason.")

    contexts, default = build_contexts(manifest)
    observer = Observer(local_addresses())
    observer.on_change = lambda: write_report(manifest, observer, args.report)
    write_report(manifest, observer, args.report)   # exists from the start, even if empty

    port = manifest["port"]
    try:
        httpd = TestbedServer(("", port), contexts, default, observer)
    except OSError as error:
        sys.exit(f"cannot bind port {port}: {error}")
    default.sni_callback = httpd.sni_callback
    for ctx in contexts.values():
        ctx.sni_callback = httpd.sni_callback

    print(f"listening on {manifest['lanIP']}:{port}")
    for cn in manifest.get("anchorCommonNames", []):
        print(f"\nВ «Доверие сертификатам» включите переключатель: {cn}")
    print("\nОткройте с iPhone (та же Wi-Fi), сначала установив "
          f"{manifest['mobileconfig']}\nи включив полное доверие в Настройки → Основные → "
          "Об этом устройстве → Доверие сертификатам:\n")
    # Order matters: the self-contained permitted case only needs a trusted anchor, so it
    # separates "trust is not enabled" from every other explanation. Opening the others
    # first produces rejections that cannot be attributed to anything.
    def rank(case):
        if case["expectation"] == "valid":
            return 0 if case.get("sendsFullChain") else 1
        return 2 if case.get("sendsFullChain") else 3

    purpose = {
        0: "СНАЧАЛА ЭТОТ — проверяет, что корень доверен",
        1: "затем этот — проверяет поиск промежуточного в хранилище",
        2: "решающий — ограничение при достижимом якоре",
        3: "справочный",
    }
    for case in sorted(manifest["cases"], key=rank):
        want = "должен" if case["expectation"] == "valid" else "НЕ должен"
        print(f"  {want:<9} {case['url']}")
        print(f"            ({purpose[rank(case)]})")
    if args.report:
        print(f"\nОтчёт обновляется после каждого события: {args.report}")
        print("Читать можно не останавливая сервер: "
              f"python3 -c \"import json;print(json.load(open('{args.report}'))['rows'])\"")
    print("\nCtrl-C или kill — напечатаю итог.")
    if not current_lan_ip():
        print("\nWARNING: LAN-адрес не определяется, телефон до этой машины не дойдёт.")
    print()

    # Explicit handlers rather than relying on KeyboardInterrupt: serve_forever() blocks in
    # select() and does not reliably surface SIGINT when the server is not attached to a
    # terminal, which would swallow the whole report. shutdown() must run off the serving
    # thread or it deadlocks, hence the helper thread. SIGTERM is handled too, so `kill`
    # also produces the verdict instead of losing it.
    stopping = threading.Event()

    def on_signal(_signum, _frame):
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # The address is checked at startup, but this process outlives DHCP leases and Wi-Fi
    # reconnects. When it moves, the sslip.io names still point at the old address, the
    # phone reaches nothing, and every case reports NOT TESTED with a misleading "check
    # Wi-Fi" — pointing away from the actual cause. Re-check while serving.
    def watch_address():
        while not stopping.wait(15):
            live = current_lan_ip()
            if live and live != manifest["lanIP"]:
                print(f"\n!! LAN-адрес сменился: {manifest['lanIP']} -> {live}", flush=True)
                print("!! Имена стенда указывают на старый адрес — телефон сюда не попадёт.",
                      flush=True)
                print("!! Перегенерируйте стенд: swift run obcert-testbed --out <dir> --tag <new>",
                      flush=True)
                observer.record("-", "-", f"testbed stale: lanIP {manifest['lanIP']} -> {live}")
                on_signal(None, None)
                return

    threading.Thread(target=watch_address, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    rows = report(manifest, observer, args.report)
    failed = [r for r in rows if r["verdict"] == "FAIL"]
    untested = [r for r in rows if r["verdict"] == "NOT TESTED"]
    sys.exit(1 if failed else (2 if untested else 0))


if __name__ == "__main__":
    main()
