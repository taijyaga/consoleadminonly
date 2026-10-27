import os
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

# 簡易的なインメモリ・データベース（サーバーのメモリ上にランキングを保存）
attack_logs = []
account_ranks = {}
country_ranks = {}

def get_country_info(ip):
    """IPアドレスから国名と国旗コードを判定"""
    try:
        if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168."):
            return "Local Network", "jp"
        res = requests.get(f"https://ipapi.co{ip}/json/", timeout=3).json()
        return res.get("country_name", "Unknown"), res.get("country_code", "").lower()
    except:
        return "Unknown", ""

class CloudAttackReceiver(BaseHTTPRequestHandler):
    def do_POST(self):
        """罠サイトからの攻撃ログを受け取る"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(post_data)
            account = data.get("account", "unknown")
            is_breach = data.get("breach", False)
            
            # 経由されたプロキシIPではなく、本当の送信元IPを取得
            x_forwarded = self.headers.get("X-Forwarded-For")
            ip = x_forwarded.split(",")[0].strip() if x_forwarded else self.client_address[0]
            
            country, code = get_country_info(ip)
            
            # データの集計
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
            if len(attack_logs) > 100:  # メモリ節約のため直近100件のみ保持
                attack_logs.pop()
                
            print(f"[SUCCESS] Recorded attack from {country} ({ip}) targeting '{account}'")
        except Exception as e:
            print("データ解析エラー:", e)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_GET(self):
        """集計されたランキングデータをダッシュボード（手元のアプリ）に返す"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # 画面に送るデータをまとめる
        response_data = {
            "logs": attack_logs,
            "accounts": account_ranks,
            "countries": country_ranks
        }
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    def do_OPTIONS(self):
        """ブラウザのセキュリティ（CORS）対策"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        return  # 余計なアクセスログをRenderの画面に出さない

if __name__ == "__main__":
    # Renderが指定するポート番号（環境変数）を取得、なければ10000番を使用
    port = int(os.environ.get("PORT", 10000))
    server = HTTPServer(('0.0.0.0', port), CloudAttackReceiver)
    print(f"Cloud Server running on port {port}...")
    server.serve_forever()
