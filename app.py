import streamlit as st
import google.generativeai as genai
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import re
import time
import os

# ==========================================
# 1. Configuration & Constants
# ==========================================

# NOTE: 本番環境では st.secrets を使用して管理することを推奨します
# ローカル実行用に、ここに直接キーを記述するか、st.secrets["GOOGLE_API_KEY"] を使用してください
if "GOOGLE_API_KEY" in st.secrets:
    GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
else:
    # ここにあなたのAPIキーを貼り付けてください
    GOOGLE_API_KEY = "YOUR_GEMINI_API_KEY_HERE" 

# Cisco DevNet Always-On Sandbox Connection Details
# 検証結果に基づき、混雑の少ないNX-OS(Nexus 9000)を採用
SANDBOX_DEVICE = {
    'device_type': 'cisco_nxos',    # Nexus OS設定
    'host': 'sandbox-nxos-1.cisco.com',
    'username': 'admin',
    'password': 'Admin_1234!',      # NX-OS用パスワード
    'port': 22,
    # 公衆回線越しのSandbox接続用チューニング
    'global_delay_factor': 2,       
    'banner_timeout': 30,           
    'conn_timeout': 30,             
}

# AI Model Configuration
# 最新の高速モデルを指定
MODEL_NAME = 'gemini-2.0-flash'

# ==========================================
# 2. Functional Logic (Backend)
# ==========================================

def configure_genai():
    """Gemini APIの初期設定"""
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        return True
    except Exception as e:
        return str(e)

def sanitize_output(text: str) -> str:
    """
    機密情報をマスク処理します。
    プライベートIPは残し、グローバルIPのみを隠すロジックを実装しています。
    """
    rules = [
        # 1. Passwords / Secrets / Community Strings
        (r'(password|secret) \d+ \S+', r'\1 <HIDDEN_PASSWORD>'),
        (r'(encrypted password) \S+', r'\1 <HIDDEN_PASSWORD>'),
        (r'(snmp-server community) \S+', r'\1 <HIDDEN_COMMUNITY>'),
        (r'(username \S+ privilege \d+ secret \d+) \S+', r'\1 <HIDDEN_SECRET>'),
        
        # 2. Public IP Masking
        # 10.x, 172.16-31.x, 192.168.x (プライベートIP) 以外をマスク対象とする正規表現
        (r'\b(?!(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.)\d{1,3}\.(?:\d{1,3}\.){2}\d{1,3}\b', '<MASKED_PUBLIC_IP>'),
        
        # 3. MAC Address
        (r'([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}', '<MASKED_MAC>'),
    ]
    
    sanitized_text = text
    for pattern, replacement in rules:
        sanitized_text = re.sub(pattern, replacement, sanitized_text)
        
    return sanitized_text

def connect_and_fetch() -> dict:
    """
    実機(NX-OS)にSSH接続し、コマンドを実行して結果を返します。
    """
    # NX-OS用にコマンドを調整
    commands = [
        "terminal length 0",            # ページネーション無効化
        "show version",                 # システム情報
        "show interface brief",         # インターフェース状態一覧
        "show ip route",                # ルーティング情報
    ]
    
    raw_output = ""
    
    try:
        with ConnectHandler(**SANDBOX_DEVICE) as ssh:
            # プロンプト取得
            prompt = ssh.find_prompt()
            raw_output += f"Connected to: {prompt}\n"

            for cmd in commands:
                # コマンド送信
                output = ssh.send_command(cmd)
                raw_output += f"\n{'='*30}\n[Command] {cmd}\n{output}\n"
                # 連続実行エラー防止のため少し待機
                time.sleep(0.5)

        # 成功時: サニタイズ処理を実行
        sanitized = sanitize_output(raw_output)
        return {
            "success": True, 
            "raw": raw_output, 
            "sanitized": sanitized
        }
            
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        return {"success": False, "error": f"Network Error: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"System Error: {str(e)}"}

def ask_gemini_agent(sanitized_log: str) -> str:
    """
    サニタイズされたログをGeminiに送信し、解析結果を取得します。
    """
    # APIキー未設定チェック
    if "YOUR_GEMINI_API_KEY" in GOOGLE_API_KEY:
        return "⚠️ エラー: ソースコード内の `GOOGLE_API_KEY` に正しいAPIキーを設定してください。"

    prompt = f"""
    あなたはデータセンターネットワークのスペシャリストAIです。
    以下はCisco Nexus (NX-OS) スイッチから取得・サニタイズされたステータスログです。
    これを分析し、以下のフォーマットでレポートを作成してください。

    ### 🛡️ Nexus 自動診断レポート
    **判定**: [ 正常 / 注意 / 異常 ] から選択
    
    **1. デバイス概要**
    *   NX-OSバージョン、稼働時間(Uptime)、プラットフォーム(Chassis)を簡潔に。
    
    **2. インターフェース状態**
    *   接続されている主要なインターフェース(Eth1/1など)のステータス(up/down)を確認。
    *   VLANや管理ポート(mgmt0)の状態について言及。
    
    **3. ルーティング状況**
    *   認識されているルート数や、デフォルトゲートウェイの有無。
    
    **4. 考察と推奨アクション**
    *   ログから読み取れるネットワークの健全性と、もしあれば追加確認すべきコマンド。

    --- Log Data Start ---
    {sanitized_log}
    --- Log Data End ---
    """
    
    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"🤖 AI Agent Error: {str(e)}"

# ==========================================
# 3. UI / Workflow (Streamlit)
# ==========================================

def main():
    st.set_page_config(page_title="AI NetOps Agent (NX-OS)", layout="wide", page_icon="🛡️")
    
    # Header
    st.title("🛡️ Autonomous Network Operations Agent")
    st.markdown("""
    **Cisco NX-OS 自律診断モジュール**  
    Nexus 9000 Sandbox (Data Center) に自律接続し、Gemini 2.0 Flash が診断を行います。
    """)
    
    # API設定チェック
    api_check = configure_genai()
    if api_check is not True:
        st.error(f"Gemini API Config Error: {api_check}")

    # Sidebar
    with st.sidebar:
        st.header("Agent Status")
        st.success("● System Online")
        st.info(f"Target: {SANDBOX_DEVICE['host']}\nOS: Cisco NX-OS\nModel: {MODEL_NAME}")
        st.markdown("---")
        st.caption("Disclaimer: Connecting to Cisco DevNet Always-On Sandbox.")

    # Main Layout
    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("📡 Operation Console")
        st.write("ボタンを押すと、エージェントがバックグラウンドで診断ワークフローを開始します。")
        
        execute_btn = st.button("🚀 自動診断を実行 (Start Diagnostics)", type="primary")
        
        if execute_btn:
            # ステータス表示コンテナ
            with st.status("Agent Workflow Running...", expanded=True) as status:
                
                # Step 1: Network Connection
                st.write("🔌 Establishing SSH Connection to Nexus Sandbox...")
                result = connect_and_fetch()
                
                if not result["success"]:
                    status.update(label="Connection Failed", state="error")
                    st.error(result['error'])
                    # エラー詳細の表示（トラブルシュート用）
                    st.json(SANDBOX_DEVICE)
                    return # 処理中断

                st.write("✅ Data Acquired.")
                st.write("🧹 Sanitizing Sensitive Information...")
                
                # Step 2: AI Analysis
                st.write(f"🧠 Requesting AI Analysis ({MODEL_NAME})...")
                ai_response = ask_gemini_agent(result["sanitized"])
                
                status.update(label="All Tasks Completed!", state="complete", expanded=False)
                
                # 結果をセッションステートに保存（再描画対策）
                st.session_state['diag_result'] = result
                st.session_state['ai_response'] = ai_response

    # 結果表示エリア（セッションステートがあれば表示）
    if 'diag_result' in st.session_state:
        result = st.session_state['diag_result']
        ai_response = st.session_state['ai_response']
        
        with col2:
            st.subheader("📋 Agent Report")
            
            # タブで表示切り替え
            tab1, tab2, tab3 = st.tabs(["🤖 AI Analysis", "🔒 Sanitized Log", "🔍 Raw Log (Debug)"])
            
            with tab1:
                st.markdown(ai_response)
                
            with tab2:
                st.caption("AIに送信されたデータ（機密情報マスク済み）")
                st.code(result["sanitized"], language="text")
                
            with tab3:
                st.warning("注意: ここには生データが表示されます（管理者用）")
                with st.expander("生ログを表示"):
                    st.code(result["raw"], language="text")

if __name__ == "__main__":
    main()
