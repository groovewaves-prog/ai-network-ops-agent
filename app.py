import streamlit as st
import google.generativeai as genai
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import re
import time

# ==========================================
# 1. Configuration & Constants
# ==========================================

#  st.secrets にGOOGLE API KEYを設定しています。
# 今回はデモ用にコード内に記載しますが、実際のキーを設定してください
import os
# ローカル環境などで環境変数がなければ st.secrets を見に行く、あるいは直接 st.secrets を使う
if "GOOGLE_API_KEY" in st.secrets:
    GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
else:
    # ローカル実行用など（必要なければ空文字やエラー処理へ）
    GOOGLE_API_KEY = "YOUR_LOCAL_KEY_OR_EMPTY"

# Cisco DevNet Always-On Sandbox (Nexus 9000)
# IOS-XEより空いていることが多いです
SANDBOX_DEVICE = {
    'device_type': 'cisco_nxos',    # <--- デバイスタイプ変更
    'host': 'sandbox-nxos-1.cisco.com',
    'username': 'admin',            # <--- ユーザー名変更
    'password': 'Admin_1234!',      # <--- パスワード変更
    'port': 22,
    'global_delay_factor': 2,
    'banner_timeout': 30,
    'conn_timeout': 30,
}

# AI Model Configuration
MODEL_NAME = 'gemini-2.0-flash' # 高速応答なFlashモデルを採用

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
    機密情報をマスク処理します。（同僚案のリスト形式を採用し、拡張）
    """
    rules = [
        # 1. Passwords / Secrets / Community Strings
        (r'(password|secret) \d+ \S+', r'\1 <HIDDEN_PASSWORD>'),
        (r'(encrypted password) \S+', r'\1 <HIDDEN_PASSWORD>'),
        (r'(snmp-server community) \S+', r'\1 <HIDDEN_COMMUNITY>'),
        (r'(username \S+ privilege \d+ secret \d+) \S+', r'\1 <HIDDEN_SECRET>'),
        
        # 2. Public IP Masking (同僚案採用: プライベートIPは残し、グローバルIPのみ隠す)
        # 10.x, 172.16-31.x, 192.168.x 以外をマスク対象とする高度なRegex
        (r'\b(?!(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.)\d{1,3}\.(?:\d{1,3}\.){2}\d{1,3}\b', '<MASKED_PUBLIC_IP>'),
        
        # 3. MAC Address (念のため)
        (r'([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}', '<MASKED_MAC>'),
    ]
    
    sanitized_text = text
    for pattern, replacement in rules:
        sanitized_text = re.sub(pattern, replacement, sanitized_text)
        
    return sanitized_text

def connect_and_fetch() -> dict:
    """
    実機にSSH接続し、コマンドを実行して結果を返します。
    """
    commands = [
        "terminal length 0",
        "show version",              # NX-OSは "| include Cisco IOS" が不要
        "show interface brief",      # NX-OSは "ip" が付かないことが多い
        "show ip route",             # NX-OSは "summary" が無い場合がある
    ]
    
    raw_output = ""
    
    try:
        with ConnectHandler(**SANDBOX_DEVICE) as ssh:
            # 特権モード確認
            if not ssh.check_enable_mode():
                ssh.enable()
            
            prompt = ssh.find_prompt()
            raw_output += f"Connected to: {prompt}\n"

            for cmd in commands:
                output = ssh.send_command(cmd)
                raw_output += f"\n{'='*30}\n[Command] {cmd}\n{output}\n"
                time.sleep(0.5) # 連続実行エラー防止

        # 成功時
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
    if GOOGLE_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        return "⚠️ エラー: ソースコード内の `GOOGLE_API_KEY` に正しいAPIキーを設定してください。"

    prompt = f"""
    あなたは熟練のネットワークオペレーションセンター(NOC)エンジニアAIです。
    以下はCisco機器から自動取得・サニタイズされたステータスログです。
    これを分析し、以下のフォーマットでレポートを作成してください。

    ### 🛡️ 自動診断レポート
    **判定**: [ 正常 / 注意 / 異常 ] から選択
    
    **1. デバイス概要**
    *   OSバージョンや稼働時間を簡潔に。
    
    **2. インターフェース状態 (注目すべき点のみ)**
    *   Up/Upしている主要I/Fや、逆にDownしている異常I/Fがあれば指摘。
    *   IPアドレスは一部マスクされていますが、ネットワーク構成を推測してください。
    
    **3. ルーティング状況**
    *   ルート数やプロトコルの有無。
    
    **4. 推奨アクション**
    *   追加で実行すべきコマンドや確認事項があれば提案。

    --- Log Data ---
    {sanitized_log}
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
    st.set_page_config(page_title="AI NetOps Agent", layout="wide", page_icon="🛡️")
    
    # Header
    st.title("🛡️ Autonomous Network Operations Agent")
    st.markdown("""
    **Cisco DevNet Sandbox 自律診断モジュール**  
    自律エージェントが実機にSSH接続し、健全性を診断してGeminiによる解説を行います。
    """)
    
    # API設定チェック
    api_check = configure_genai()
    if api_check is not True:
        st.error(f"Gemini API Config Error: {api_check}")

    # Sidebar
    with st.sidebar:
        st.header("Agent Status")
        st.success("● System Online")
        st.info(f"Target: {SANDBOX_DEVICE['host']}\nModel: {MODEL_NAME}")
        st.markdown("---")
        st.caption("Disclaimer: This is a demo connecting to a public sandbox.")

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
                st.write("🔌 Establishing SSH Connection to Sandbox...")
                result = connect_and_fetch()
                
                if not result["success"]:
                    status.update(label="Connection Failed", state="error")
                    st.error(result['error'])
                    return # 処理中断

                st.write("✅ Data Acquired.")
                st.write("🧹 Sanitizing Sensitive Information...")
                
                # Step 2: AI Analysis
                st.write("🧠 Requesting AI Analysis (Gemini)...")
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
            
            # タブで表示切り替え（同僚案を採用）
            tab1, tab2, tab3 = st.tabs(["🤖 AI Analysis", "🔒 Sanitized Log", "🔍 Raw Log (Debug)"])
            
            with tab1:
                st.markdown(ai_response)
                st.button("レポートをコピー (Copy)", disabled=True, help="Demo feature")
            
            with tab2:
                st.caption("AIに送信されたデータ（機密情報マスク済み）")
                st.code(result["sanitized"], language="text")
                
            with tab3:
                st.warning("注意: ここには生データが表示されます（管理者用）")
                with st.expander("生ログを表示"):
                    st.code(result["raw"], language="text")

if __name__ == "__main__":
    main()
