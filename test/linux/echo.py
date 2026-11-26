# Answers with the caller's address in Cloudflare trace format: the
# "Internet" host the Moley box reaches directly.
from http.server import BaseHTTPRequestHandler, HTTPServer

class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"ip={self.client_address[0]}\nloc=XX\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8080), Echo).serve_forever()
