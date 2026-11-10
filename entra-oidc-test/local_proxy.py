"""本地 HTTP 反向代理: http://localhost:5000 -> 远程服务器上的 app.py

用途: 服务器 sshd 禁止 TCP 转发时, 让浏览器地址栏保持 localhost:5000,
从而与 Entra 注册的 redirect_uri 完全一致。

用法:
    pip install requests
    python local_proxy.py http://服务器IP:5000
然后浏览器打开 http://localhost:5000

注意: 远程 app.py 需监听 0.0.0.0(或用 Nginx 反代), 且仅建议在内网使用。
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

TARGET = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

# 逐跳头, 不能原样转发
DROP_REQUEST_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
}
DROP_RESPONSE_HEADERS = {
    "transfer-encoding",
    "connection",
    "keep-alive",
    "content-encoding",
    "content-length",
}


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in DROP_REQUEST_HEADERS
        }

        try:
            resp = requests.request(
                self.command,
                TARGET + self.path,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=60,
            )
        except requests.RequestException as exc:
            self.send_error(502, f"upstream unreachable: {exc}")
            return

        self.send_response(resp.status_code)
        for key, value in resp.raw.headers.items():
            if key.lower() in DROP_RESPONSE_HEADERS:
                continue
            self.send_header(key, value)

        payload = resp.content
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = _handle

    def log_message(self, fmt, *args):
        sys.stderr.write("[proxy] " + (fmt % args) + "\n")


def main():
    print(f"[*] http://localhost:{PORT}  ->  {TARGET}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Proxy).serve_forever()


if __name__ == "__main__":
    main()
