import os
import json
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from agent import PhishingAgent

cfg = json.load(open("best_weights.json"))
agent = PhishingAgent(cfg["weights"], cfg["threshold"])

NICE = {
    "long_url": "Long domain name",
    "many_dots": "Many dots in the domain",
    "has_at": "Contains an @ sign",
    "ip_address": "Uses an IP address instead of a name",
    "many_hyphens": "Many hyphens in the domain",
    "not_https": "Not using HTTPS",
    "bad_words": "Suspicious words (login, verify, bank...)",
    "many_subdomains": "Many subdomains",
    "many_digits": "Many digits",
    "bad_tld": "Suspicious domain ending (.xyz, .top...)",
}

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Detector</title>
<style>
  body { font-family: Arial, sans-serif; margin: 0; padding: 30px 16px;
         background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh;
         color: #fff; text-align: center; }
  h1 { margin: 0 0 6px; }
  .sub { opacity: 0.85; margin-bottom: 24px; font-size: 14px; }
  .card { background: #fff; color: #222; max-width: 640px; margin: 0 auto;
          padding: 22px; border-radius: 14px; text-align: left; }
  .card h3 { margin: 0 0 10px; }
  input[type=text] { width: 100%; box-sizing: border-box; padding: 14px;
          font-size: 16px; border-radius: 8px; border: 1px solid #ccc; }
  button { margin-top: 14px; padding: 12px 26px; font-size: 16px; border: none;
           border-radius: 8px; background: #667eea; color: white; cursor: pointer; }
  .result { margin-top: 20px; padding: 16px; border-radius: 10px; }
  .safe { background: #e8f5e9; border: 1px solid #2e7d32; }
  .phish { background: #fdecea; border: 1px solid #c62828; }
  .verdict { font-size: 24px; font-weight: bold; }
  .small { color: #555; font-size: 14px; margin-top: 6px; }
  ul { margin: 6px 0 0; padding-left: 20px; }
  .examples { margin-top: 16px; font-size: 13px; color: #666; }
  .examples a { color: #4a5fd0; cursor: pointer; text-decoration: underline;
                display: block; margin-top: 4px; }
  .note { margin-top: 22px; font-size: 12px; opacity: 0.8; }
</style>
</head>
<body>
  <h1>&#128737; Phishing Detector</h1>
  <div class="sub">Paste a link to scan it with an agent whose weights were tuned using PSO</div>
  <div class="card">
    <h3>Check URL</h3>
    <form method="POST" action="/">
      <input type="text" name="url" id="url" placeholder="https://example.com"
             value="%%URL%%" autofocus>
      <button type="submit">Scan URL</button>
    </form>
    %%RESULT%%
    <div class="examples">Try an example:
      <a onclick="fill('https://www.google.com')">https://www.google.com</a>
      <a onclick="fill('http://bank-verify-login.xyz/@secure')">http://bank-verify-login.xyz/@secure</a>
    </div>
  </div>
  <div class="note">The agent looks at the shape of the link only, not at the page content.</div>
<script>
  function fill(v) { document.getElementById('url').value = v; }
</script>
</body>
</html>"""


def render(url="", result_html=""):
    return (PAGE.replace("%%URL%%", html.escape(url, quote=True))
                .replace("%%RESULT%%", result_html))


def build_result(url):
    try:
        verdict, score, reasons = agent.decide(url)
    except Exception:
        return '<div class="result phish">Could not analyze this link.</div>'

    items = "".join("<li>%s</li>" % NICE.get(r, r) for r in reasons)
    if verdict == "PHISHING":
        return ('<div class="result phish"><div class="verdict">Phishing suspected</div>'
                '<div class="small">Risk score: %.2f (threshold %.2f)</div>'
                '<div class="small">Why:</div><ul>%s</ul></div>'
                % (score, agent.threshold, items))
    extra = ('<div class="small">Minor signs:</div><ul>%s</ul>' % items) if items else ""
    return ('<div class="result safe"><div class="verdict">Looks safe</div>'
            '<div class="small">Risk score: %.2f (threshold %.2f)</div>%s</div>'
            % (score, agent.threshold, extra))


class Handler(BaseHTTPRequestHandler):
    def _send(self, body):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(render())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        url = form.get("url", [""])[0].strip()
        if url:
            self._send(render(url, build_result(url)))
        else:
            self._send(render())

    def log_message(self, *args):
        pass   # نخفي رسايل السيرفر عشان الشاشة تفضل نضيفة


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))   # الاستضافة بتحدد الرقم ده
    server = HTTPServer(("0.0.0.0", port), Handler)
    print("Server running on port", port)
    print("Locally open:  http://127.0.0.1:%d" % port)
    server.serve_forever()