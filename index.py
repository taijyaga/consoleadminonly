import os
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request

# データの保持用
attack_logs = []
account_ranks = {}
country_ranks = {}

def get_country_info(ip):
    """MaxMindなどの外部DBの代わりに、外部APIを叩いて国名を取得"""
    try:
        if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168."):
            return "Local Network", "jp"
        # Render環境等で安全に叩ける標準ライブラリのurllibを使用
        url = f"https://ipapi.co{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            res = json.loads(response.read().decode())
            return res.get("country_name", "Unknown"), res.get("country_code", "").lower()
    except:
        return "Unknown", ""

class CloudAttackReceiver(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
        
        try:
            data = json.loads(post_data)
            account = data.get("account", "unknown")
            is_breach = data.get("breach", False)
            
            # Render（プロキシ）経由の本当のIPを取得
            x_forwarded = self.headers.get("X-Forwarded-For")
            ip = x_forwarded.split(",")[0].strip() if x_forwarded else self.client_address[0]
            
            country, code = get_country_info(ip)
            
            if account not in account_ranks:
                account_ranks[account] = {"attacks": 0, "breaches": 0}
            if country not in country_ranks:
                country_ranks[country] = {"code": code, "count": 0}
                
            country_ranks[country]["count"] += 1
            if is_breach:
                account_ranks[account]["breaches"] += 1
            else:
                account_ranks[account]["attacks"] += 1
                
            log_entry = {
                "ip": ip, "account": account, "is_breach": is_breach,
                "country": country, "code": code
            }
            attack_logs.insert(0, log_entry)
            if len(attack_logs) > 100:
                attack_logs.pop()
                
            print(f"[SUCCESS] Recorded attack from {country}")
        except Exception as e:
            print("解析エラー:", e)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):
        """確認用ページにデータを返す"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        response_data = {
            "logs": attack_logs,
            "accounts": account_ranks,
            "countries": country_ranks
        }
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    # '0.0.0.0' でRenderの外部ポート割当を正常に待ち受ける
    server = HTTPServer(('0.0.0.0', port), CloudAttackReceiver)
    print(f"Cloud Server running on port {port}...")
    server.serve_forever()
