import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from sqlalchemy import create_engine, text

app = Flask(__name__)

# Get DB URL from Render Environment Variables
DB_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DB_URL)

def init_db():
    """Creates the keys table if it doesn't exist"""
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS access_keys (
                key_code TEXT PRIMARY KEY,
                status TEXT DEFAULT 'pending', -- 'pending' or 'active'
                user_email TEXT,
                expires_at TIMESTAMP
            );
        """))
        conn.commit()

# Initialize DB on startup
init_db()

# --- 1. ADMIN PANEL (Generate Keys) ---
@app.route('/admin')
def admin_panel():
    # Simple HTML UI to generate a key
    html = """
    <html>
    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>🔑 Admin Key Generator</h1>
        <button onclick="generateKey()" style="padding: 15px 30px; font-size: 18px; cursor: pointer;">Generate 5-min Key</button>
        <div id="result" style="margin-top: 20px; font-size: 24px; font-weight: bold; color: green;"></div>
        <script>
            async function generateKey() {
                let res = await fetch('/admin/create', {method: 'POST'});
                let data = await res.json();
                document.getElementById('result').innerText = data.key;
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/admin/create', methods=['POST'])
def create_key():
    # Create a random 16-character key
    new_key = secrets.token_hex(8) 
    
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO access_keys (key_code, status) VALUES (:k, 'pending')"),
            {"k": new_key}
        )
        conn.commit()
    
    return jsonify({"key": new_key})

# --- 2. USER ENDPOINT (Colab connects here) ---
@app.route('/api/check_key', methods=['POST'])
def check_key():
    data = request.json
    key_input = data.get('key')
    email_input = data.get('email')

    if not key_input or not email_input:
        return jsonify({"valid": False, "message": "Missing key or email"}), 400

    with engine.connect() as conn:
        # Fetch key details
        result = conn.execute(
            text("SELECT status, expires_at, user_email FROM access_keys WHERE key_code = :k"),
            {"k": key_input}
        ).fetchone()

        # 1. Key does not exist
        if not result:
            return jsonify({"valid": False, "message": "❌ Invalid Key"}), 403

        status, expires_at, owner_email = result

        # 2. Key is Pending (First Activation)
        if status == 'pending':
            # Activate it now: Set email and expiration (Now + 5 mins)
            expiration_time = datetime.now() + timedelta(minutes=5)
            conn.execute(
                text("""
                    UPDATE access_keys 
                    SET status = 'active', user_email = :e, expires_at = :t 
                    WHERE key_code = :k
                """),
                {"e": email_input, "t": expiration_time, "k": key_input}
            )
            conn.commit()
            return jsonify({"valid": True, "message": "✅ Key Activated! Hello World."})

        # 3. Key is Active (Subsequent Checks)
        elif status == 'active':
            # Check if User matches (Optional security check)
            if owner_email != email_input:
                return jsonify({"valid": False, "message": "❌ This key belongs to another user."}), 403

            # Check if Expired
            if datetime.now() > expires_at:
                # DELETE the key from DB
                conn.execute(text("DELETE FROM access_keys WHERE key_code = :k"), {"k": key_input})
                conn.commit()
                return jsonify({"valid": False, "message": "⛔ Key Expired and Deleted."}), 403
            
            # Still Valid
            else:
                return jsonify({"valid": True, "message": "👋 Hello World (Time remaining)"})

    return jsonify({"valid": False, "message": "Unknown Error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
