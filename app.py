import os
import secrets
import base64
import json
import sqlite3
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
import jwt
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from db import get_db_connection, init_db

def format_name_title_case(s):
    if not s:
        return ""
    words = s.strip().split()
    formatted = []
    for w in words:
        if len(w) > 0:
            formatted.append(w[0].upper() + w[1:].lower())
    return " ".join(formatted)

# Initialize database
init_db()

app = Flask(__name__, static_folder='public', static_url_path='')

# Flask secret key for JWT session signing
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)

# Load/Generate AES Key for database encryption (AES-256-GCM)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aes_key_env = os.environ.get("VAULT_AES_KEY")
if aes_key_env:
    aes_key = base64.b64decode(aes_key_env.encode('utf-8'))
else:
    KEY_FILE = os.path.join(os.path.dirname(__file__), 'secret.key')
    if not os.path.exists(KEY_FILE):
        aes_key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, 'wb') as f:
            f.write(aes_key)
    else:
        with open(KEY_FILE, 'rb') as f:
            aes_key = f.read()

aesgcm = AESGCM(aes_key)

# Cryptographic Helpers
def encrypt_data(text: str) -> str:
    if not text:
        return ""
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    return base64.b64encode(nonce + encrypted).decode('utf-8')

def decrypt_data(encrypted_base64: str) -> str:
    if not encrypted_base64:
        return ""
    try:
        data = base64.b64decode(encrypted_base64.encode('utf-8'))
        nonce = data[:12]
        ciphertext = data[12:]
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"[Error al descifrar: {str(e)}]"

# Password hashing helpers
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "La contraseña maestra debe tener al menos 8 caracteres."
    if not re.search(r"[a-z]", password):
        return False, "La contraseña maestra debe contener al menos una letra minúscula."
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña maestra debe contener al menos una letra mayúscula."
    if not re.search(r"\d", password):
        return False, "La contraseña maestra debe contener al menos un número."
    if not re.search(r"[!@#\$%\^&\*\(\),\.\?\":\{\}\|<>\_\+\-\=\[\]/\\\s]", password):
        return False, "La contraseña maestra debe contener al menos un carácter especial (ej. !, @, #, $, %, etc.)."
    return True, ""


# Audit log helper
def add_audit_log(user_id, action, details):
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)', (user_id, action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Audit logging error:", e)

# Decorator to secure endpoints with JWT & enforce single active session
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token no proporcionado.'}), 401
        
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (data['user_id'],)).fetchone()
            conn.close()
            
            if not user:
                return jsonify({'message': 'Usuario no encontrado.'}), 401
            
            if user['status'] != 'active':
                return jsonify({'message': 'Usuario inhabilitado por la administración.'}), 403
            
            # --- SINGLE SESSION ENFORCEMENT ---
            token_session_id = data.get('session_id')
            db_session_id = user['current_session_id']
            if token_session_id != db_session_id:
                return jsonify({
                    'message': 'Su sesión ha sido cerrada debido a que se inició sesión en otro dispositivo.',
                    'session_terminated': True
                }), 401
            
            token_scope = data.get('scope', 'full_access')
            
            # Flow: 2FA required
            if token_scope == '2fa_pending':
                if request.path != '/api/auth/login/2fa':
                    return jsonify({'message': 'Validación de 2FA requerida.'}), 403
                    
            # Flow: 2FA Setup required (mandatory for all users)
            if token_scope == '2fa_setup_pending':
                allowed_paths = ['/api/auth/login/2fa-setup', '/api/auth/login/2fa-enable']
                if request.path not in allowed_paths:
                    return jsonify({'message': 'Configuración de doble factor (2FA) requerida.'}), 403
            
            # Flow: Force password change after admin reset
            if user['force_password_change'] == 1 and token_scope == 'full_access':
                allowed_paths = ['/api/auth/change-password', '/api/auth/user-info']
                if request.path not in allowed_paths:
                    return jsonify({'message': 'Cambio obligatorio de contraseña maestra requerido.', 'force_password_change': True}), 403

            current_user = dict(user)
            current_user.pop('password_hash', None)
            current_user.pop('totp_secret', None)
            current_user['token_scope'] = token_scope
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Sesión expirada.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Sesión inválida.'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Decorator to restrict endpoints to administrators
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['is_admin'] != 1:
            return jsonify({'message': 'Acceso denegado. Permisos de administrador requeridos.'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# ==========================================
# SMTP EMAIL SENDER HELPER
# ==========================================

def send_invitation_email(email_to, invite_url):
    conn = get_db_connection()
    smtp_host_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_host'").fetchone()
    smtp_port_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_port'").fetchone()
    smtp_user_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_user'").fetchone()
    smtp_pass_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_pass'").fetchone()
    smtp_from_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_from'").fetchone()
    conn.close()

    smtp_host = smtp_host_row['value'] if smtp_host_row else 'smtp.gmail.com'
    smtp_port = int(smtp_port_row['value']) if smtp_port_row else 587
    smtp_user = smtp_user_row['value'] if smtp_user_row else ''
    smtp_pass = smtp_pass_row['value'] if smtp_pass_row else ''
    smtp_from = smtp_from_row['value'] if smtp_from_row else 'operaciones@fiscalia.gob.bo'

    if not smtp_user or not smtp_pass:
        return False, "Servidor de correo (SMTP) no configurado en el sistema."

    logo_path = os.path.join(os.path.dirname(__file__), 'public', 'logo_fiscalia.png')
    has_local_logo = os.path.exists(logo_path)

    # HTML Email Template
    logo_html = '<img src="cid:logo_fiscalia" class="logo" alt="Fiscalía de Santa Cruz">' if has_local_logo else """
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b3/Escudo_de_Bolivia.svg/250px-Escudo_de_Bolivia.svg.png" class="logo" alt="Escudo de Bolivia">
    <div class="brand-name">MINISTERIO PÚBLICO</div>
    <div class="brand-sub">FISCALÍA GENERAL DEL ESTADO - BOLIVIA</div>
    """

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                background-color: #f4f5f7;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                max-width: 600px;
                margin: 40px auto;
                background: #ffffff;
                border: 1px solid #e1e4e8;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                overflow: hidden;
            }}
            .email-header {{
                background-color: #ffffff;
                padding: 25px;
                border-bottom: 1px solid #e1e4e8;
                text-align: center;
            }}
            .logo {{
                max-height: 80px;
                margin-bottom: 15px;
            }}
            .brand-name {{
                font-size: 15px;
                font-weight: bold;
                color: #008000;
                letter-spacing: 0.05em;
                margin: 0;
            }}
            .brand-sub {{
                font-size: 11px;
                color: #6a737d;
                margin: 4px 0 0 0;
                font-weight: 500;
            }}
            .email-body {{
                padding: 40px 30px;
                text-align: center;
            }}
            .invitation-text {{
                font-size: 16px;
                color: #24292e;
                line-height: 1.6;
                margin-bottom: 30px;
            }}
            .btn-join {{
                display: inline-block;
                background-color: #008000;
                color: #ffffff !important;
                text-decoration: none;
                padding: 12px 30px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 15px;
                box-shadow: 0 4px 6px rgba(0, 128, 0, 0.25);
            }}
            .footer-text {{
                font-size: 13px;
                color: #586069;
                margin-top: 30px;
            }}
            .email-footer {{
                background-color: #f8f9fa;
                padding: 20px;
                font-size: 11px;
                color: #6a737d;
                text-align: center;
                border-top: 1px solid #e1e4e8;
                line-height: 1.6;
            }}
            .email-footer a {{
                color: #008000;
                text-decoration: none;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-header">
                {logo_html}
            </div>
            
            <div class="email-body">
                <p class="invitation-text">
                    Ha sido invitado a unirse a la organización <strong>Fiscalía Departamental de Santa Cruz</strong>.
                </p>
                
                <a href="{invite_url}" class="btn-join">Unirse a la Organización</a>
                
                <p class="footer-text" style="margin-top: 25px; font-size: 13px; color: #b03a2e; font-weight: 500; background-color: #fdf2f2; padding: 12px; border-radius: 6px; border: 1px solid #f5c6cb; text-align: left; line-height: 1.5;">
                    <strong>Políticas de Seguridad:</strong> Al registrarse, deberá establecer una contraseña maestra segura de <strong>mínimo 8 caracteres</strong>, que cuente con letras mayúsculas, minúsculas, números y caracteres especiales (como !, @, #, $, etc.).
                </p>
                
                <p class="footer-text">
                    Si no desea unirse a esta organización, puede ignorar este correo de forma segura.
                </p>
            </div>
            
            <div class="email-footer">
                Este correo fue enviado por el sistema de gestión de credenciales del <strong>Ministerio Público de Bolivia</strong>.<br>
                Si no solicitó esta acción, puede ignorar este mensaje de forma segura.<br>
                <a href="https://www.fiscalia.gob.bo" target="_blank">www.fiscalia.gob.bo</a>
            </div>
        </div>
    </body>
    </html>
    """

    try:
        msg = MIMEMultipart('related')
        msg['Subject'] = 'Unirse a Fiscalía Departamental de Santa Cruz'
        msg['From'] = f"Fiscalía de Santa Cruz <{smtp_from}>"
        msg['To'] = email_to
        
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)
        
        part = MIMEText(html_body, 'html', 'utf-8')
        msg_alternative.attach(part)
        
        if has_local_logo:
            with open(logo_path, 'rb') as f:
                msg_image = MIMEImage(f.read())
                msg_image.add_header('Content-ID', '<logo_fiscalia>')
                msg_image.add_header('Content-Disposition', 'inline', filename='logo_fiscalia.png')
                msg.attach(msg_image)

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=8)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, email_to, msg.as_string())
        server.quit()
        return True, "Enlace de invitación enviado al correo del funcionario."
    except Exception as e:
        return False, f"Error SMTP: {str(e)}"




def send_reset_password_email(email_to, reset_url):
    conn = get_db_connection()
    smtp_host_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_host'").fetchone()
    smtp_port_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_port'").fetchone()
    smtp_user_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_user'").fetchone()
    smtp_pass_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_pass'").fetchone()
    smtp_from_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_from'").fetchone()
    conn.close()

    smtp_host = smtp_host_row['value'] if smtp_host_row else 'smtp.gmail.com'
    smtp_port = int(smtp_port_row['value']) if smtp_port_row else 587
    smtp_user = smtp_user_row['value'] if smtp_user_row else ''
    smtp_pass = smtp_pass_row['value'] if smtp_pass_row else ''
    smtp_from = smtp_from_row['value'] if smtp_from_row else 'operaciones@fiscalia.gob.bo'

    if not smtp_user or not smtp_pass:
        return False, "Servidor de correo (SMTP) no configurado en el sistema."

    logo_path = os.path.join(os.path.dirname(__file__), 'public', 'logo_fiscalia.png')
    has_local_logo = os.path.exists(logo_path)

    logo_html = '<img src="cid:logo_fiscalia" class="logo" alt="Fiscalía de Santa Cruz">' if has_local_logo else """
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b3/Escudo_de_Bolivia.svg/250px-Escudo_de_Bolivia.svg.png" class="logo" alt="Escudo de Bolivia">
    <div class="brand-name">MINISTERIO PÚBLICO</div>
    <div class="brand-sub">FISCALÍA GENERAL DEL ESTADO - BOLIVIA</div>
    """

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                background-color: #f4f5f7;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                max-width: 600px;
                margin: 40px auto;
                background: #ffffff;
                border: 1px solid #e1e4e8;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                overflow: hidden;
            }}
            .email-header {{
                background-color: #ffffff;
                padding: 25px;
                border-bottom: 1px solid #e1e4e8;
                text-align: center;
            }}
            .logo {{
                max-height: 80px;
                margin-bottom: 15px;
            }}
            .brand-name {{
                font-size: 15px;
                font-weight: bold;
                color: #008000;
                letter-spacing: 0.05em;
                margin: 0;
            }}
            .brand-sub {{
                font-size: 11px;
                color: #6a737d;
                margin: 4px 0 0 0;
                font-weight: 500;
            }}
            .email-body {{
                padding: 30px;
                line-height: 1.6;
                color: #24292e;
            }}
            .invitation-text {{
                font-size: 16px;
                margin-bottom: 25px;
                color: #24292e;
                font-weight: 500;
            }}
            .btn-join {{
                display: inline-block;
                background-color: #f59e0b;
                color: #ffffff !important;
                padding: 12px 30px;
                font-size: 14px;
                font-weight: bold;
                text-decoration: none;
                border-radius: 6px;
                box-shadow: 0 4px 6px rgba(245, 158, 11, 0.25);
                margin: 15px 0;
            }}
            .footer-text {{
                font-size: 13px;
                color: #586069;
                margin-top: 30px;
            }}
            .email-footer {{
                background-color: #f8f9fa;
                padding: 20px;
                font-size: 11px;
                color: #6a737d;
                text-align: center;
                border-top: 1px solid #e1e4e8;
                line-height: 1.6;
            }}
            .email-footer a {{
                color: #008000;
                text-decoration: none;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-header">
                {logo_html}
            </div>
            
            <div class="email-body">
                <p class="invitation-text">
                    Se ha solicitado el restablecimiento de la contraseña maestra para su cuenta de <strong>VaultFiscalia</strong>.
                </p>
                
                <a href="{reset_url}" class="btn-join">Restablecer Contraseña Maestra</a>
                
                <p class="footer-text" style="margin-top: 25px; font-size: 13px; color: #b03a2e; font-weight: 500; background-color: #fdf2f2; padding: 12px; border-radius: 6px; border: 1px solid #f5c6cb; text-align: left; line-height: 1.5;">
                    <strong>Políticas de Seguridad:</strong> Deberá establecer una contraseña maestra segura de <strong>mínimo 8 caracteres</strong>, que cuente con letras mayúsculas, minúsculas, números y caracteres especiales (como !, @, #, $, etc.).
                </p>
                
                <p class="footer-text">
                    Las credenciales guardadas en su bóveda permanecerán intactas. Si usted no solicitó este restablecimiento, notifíquelo al administrador de inmediato.
                </p>
            </div>
            
            <div class="email-footer">
                Este correo fue enviado por el sistema de gestión de credenciales del <strong>Ministerio Público de Bolivia</strong>.<br>
                Si no solicitó esta acción, puede ignorar este mensaje de forma segura.<br>
                <a href="https://www.fiscalia.gob.bo" target="_blank">www.fiscalia.gob.bo</a>
            </div>
        </div>
    </body>
    </html>
    """

    try:
        from email.mime.image import MIMEImage
        msg = MIMEMultipart('related')
        msg['Subject'] = 'Restablecimiento de Contraseña Maestra - VaultFiscalia'
        msg['From'] = f"Fiscalía de Santa Cruz <{smtp_from}>"
        msg['To'] = email_to
        
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)
        
        part = MIMEText(html_body, 'html', 'utf-8')
        msg_alternative.attach(part)
        
        if has_local_logo:
            with open(logo_path, 'rb') as f:
                msg_image = MIMEImage(f.read())
                msg_image.add_header('Content-ID', '<logo_fiscalia>')
                msg_image.add_header('Content-Disposition', 'inline', filename='logo_fiscalia.png')
                msg.attach(msg_image)

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=8)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, email_to, msg.as_string())
        server.quit()
        return True, "Enlace de restablecimiento enviado al correo del funcionario."
    except Exception as e:
        return False, f"Error SMTP: {str(e)}"



def send_password_hint_email(email_to, hint):
    conn = get_db_connection()
    smtp_host_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_host'").fetchone()
    smtp_port_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_port'").fetchone()
    smtp_user_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_user'").fetchone()
    smtp_pass_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_pass'").fetchone()
    smtp_from_row = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_from'").fetchone()
    conn.close()

    smtp_host = smtp_host_row['value'] if smtp_host_row else 'smtp.gmail.com'
    smtp_port = int(smtp_port_row['value']) if smtp_port_row else 587
    smtp_user = smtp_user_row['value'] if smtp_user_row else ''
    smtp_pass = smtp_pass_row['value'] if smtp_pass_row else ''
    smtp_from = smtp_from_row['value'] if smtp_from_row else 'operaciones@fiscalia.gob.bo'

    if not smtp_user or not smtp_pass:
        return False, "Servidor de correo (SMTP) no configurado en el sistema."

    logo_path = os.path.join(os.path.dirname(__file__), 'public', 'logo_fiscalia.png')
    has_local_logo = os.path.exists(logo_path)

    # HTML Email Template
    logo_html = '<img src="cid:logo_fiscalia" class="logo" alt="Fiscalía de Santa Cruz">' if has_local_logo else """
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b3/Escudo_de_Bolivia.svg/250px-Escudo_de_Bolivia.svg.png" class="logo" alt="Escudo de Bolivia">
    <div class="brand-name">MINISTERIO PÚBLICO</div>
    <div class="brand-sub">FISCALÍA GENERAL DEL ESTADO - BOLIVIA</div>
    """

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                background-color: #f4f5f7;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                max-width: 600px;
                margin: 40px auto;
                background: #ffffff;
                border: 1px solid #e1e4e8;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                overflow: hidden;
            }}
            .email-header {{
                background-color: #ffffff;
                padding: 25px;
                border-bottom: 1px solid #e1e4e8;
                text-align: center;
            }}
            .logo {{
                max-height: 80px;
                margin-bottom: 15px;
            }}
            .brand-name {{
                font-size: 15px;
                font-weight: bold;
                color: #008000;
                letter-spacing: 0.05em;
                margin: 0;
            }}
            .brand-sub {{
                font-size: 11px;
                color: #6a737d;
                margin: 4px 0 0 0;
                font-weight: 500;
            }}
            .email-body {{
                padding: 40px 30px;
                text-align: center;
            }}
            .hint-title {{
                font-size: 18px;
                color: #008000;
                font-weight: bold;
                margin-bottom: 15px;
            }}
            .hint-box {{
                display: inline-block;
                background-color: #f1f3f5;
                border: 1px dashed #ab87d2;
                color: #24292e;
                padding: 15px 30px;
                border-radius: 6px;
                font-size: 16px;
                font-weight: bold;
                margin-top: 10px;
                margin-bottom: 20px;
            }}
            .footer-text {{
                font-size: 12px;
                color: #586069;
                margin-top: 25px;
                line-height: 1.4;
            }}
            .email-footer {{
                background-color: #f8f9fa;
                padding: 20px;
                font-size: 11px;
                color: #6a737d;
                text-align: center;
                border-top: 1px solid #e1e4e8;
                line-height: 1.6;
            }}
            .email-footer a {{
                color: #008000;
                text-decoration: none;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-header">
                {logo_html}
            </div>
            
            <div class="email-body">
                <div class="hint-title">Pista de Contraseña Maestra</div>
                <p>Ha solicitado recordar la pista de contraseña maestra asociada a su cuenta en <strong>VaultFiscalia</strong>.</p>
                
                <div class="hint-box">
                    "{hint}"
                </div>
                
                <p class="footer-text">
                    Si no solicitó recordar su pista, le recomendamos revisar la seguridad de su cuenta institucional.
                </p>
            </div>
            
            <div class="email-footer">
                Este correo fue enviado por el sistema de gestión de credenciales del <strong>Ministerio Público de Bolivia</strong>.<br>
                Si no solicitó esta acción, puede ignorar este mensaje de forma segura.<br>
                <a href="https://www.fiscalia.gob.bo" target="_blank">www.fiscalia.gob.bo</a>
            </div>
        </div>
    </body>
    </html>
    """

    try:
        msg = MIMEMultipart('related')
        msg['Subject'] = 'Pista de Contraseña Maestra - VaultFiscalia'
        msg['From'] = f"Fiscalía de Santa Cruz <{smtp_from}>"
        msg['To'] = email_to
        
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)
        
        part = MIMEText(html_body, 'html', 'utf-8')
        msg_alternative.attach(part)
        
        if has_local_logo:
            with open(logo_path, 'rb') as f:
                msg_image = MIMEImage(f.read())
                msg_image.add_header('Content-ID', '<logo_fiscalia>')
                msg_image.add_header('Content-Disposition', 'inline', filename='logo_fiscalia.png')
                msg.attach(msg_image)

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=8)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, email_to, msg.as_string())
        server.quit()
        return True, "Pista de contraseña enviada a su correo institucional."
    except Exception as e:
        return False, f"Error SMTP: {str(e)}"


@app.route('/api/auth/password-hint', methods=['POST'])
def request_password_hint():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'message': 'El correo electrónico es requerido.'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT password_hint FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    
    if user:
        hint = user['password_hint']
        if hint:
            sent, status = send_password_hint_email(email, hint)
            if not sent:
                return jsonify({'message': f'No se pudo enviar el correo: {status}'}), 500
        else:
            return jsonify({'message': 'Su cuenta de usuario no tiene configurada ninguna pista de contraseña.'}), 400
    else:
        return jsonify({'message': 'No se encontró ningún usuario registrado con ese correo institucional.'}), 404
        
    return jsonify({'message': 'Se ha enviado la pista de su contraseña maestra a su casilla de correo institucional.'})


# ==========================================
# AUTHENTICATION & INVITATIONS
# ==========================================

@app.route('/api/auth/invite/verify', methods=['GET'])
def verify_invitation():
    token = request.args.get('token', '').strip()
    if not token:
        return jsonify({'valid': False, 'message': 'Token no proporcionado.'}), 400
        
    conn = get_db_connection()
    invite = conn.execute('SELECT * FROM invitations WHERE token = ? AND used = 0', (token,)).fetchone()
    conn.close()
    
    if not invite:
        return jsonify({'valid': False, 'message': 'Invitación inválida, expirada o ya utilizada.'})
        
    return jsonify({
        'valid': True,
        'email': invite['email'],
        'nombres': invite['nombres'],
        'apellido_paterno': invite['apellido_paterno'],
        'apellido_materno': invite['apellido_materno'],
        'ci': invite['ci'],
        'message': 'Invitación válida.'
    })


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    invite_token = data.get('invite_token', '').strip()
    password_hint = data.get('password_hint', '').strip()
    
    if not email or not password:
        return jsonify({'message': 'Faltan campos obligatorios.'}), 400
        
    # Strictly check email domain
    if not email.endswith('@fiscalia.gob.bo'):
        return jsonify({'message': 'Correo inválido. Solo se admiten correos institucionales @fiscalia.gob.bo.'}), 400
        
    # Check password strength and complexity
    is_strong, strength_err = validate_password_strength(password)
    if not is_strong:
        return jsonify({'message': strength_err}), 400
    
    conn = get_db_connection()
    
    # Check if this is the first user (system bootstrap)
    user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    
    if user_count > 0:
        # Require a valid invitation token
        if not invite_token:
            conn.close()
            return jsonify({'message': 'El registro libre está deshabilitado. Se requiere un enlace de invitación oficial.'}), 400
            
        invite = conn.execute(
            'SELECT * FROM invitations WHERE email = ? AND token = ? AND used = 0',
            (email, invite_token)
        ).fetchone()
        
        if not invite:
            conn.close()
            return jsonify({'message': 'Enlace de invitación inválido o no coincide con el correo ingresado.'}), 400
            
    # Check duplicate user
    existing = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'message': 'Esta cuenta de correo electrónico ya está registrada.'}), 400
    
    # First user registered in the database is automatically administrator + superuser
    is_admin = 1 if user_count == 0 else 0
    is_superuser = 1 if user_count == 0 else 0
    hashed = hash_password(password)
    
    if user_count == 0:
        nombres = 'Administrador'
        apellido_paterno = ''
        apellido_materno = 'Principal'
        ci = '0000000'
    else:
        nombres = invite['nombres']
        apellido_paterno = invite['apellido_paterno']
        apellido_materno = invite['apellido_materno']
        ci = invite['ci']
        
    cursor = conn.cursor()
    
    # Create the user
    cursor.execute(
        'INSERT INTO users (email, password_hash, is_admin, is_superuser, status, force_password_change, password_hint, nombres, apellido_paterno, apellido_materno, ci) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)',
        (email, hashed, is_admin, is_superuser, 'active', password_hint, nombres, apellido_paterno, apellido_materno, ci)
    )
    user_id = cursor.lastrowid
    
    # Mark invitation as used
    if user_count > 0:
        cursor.execute('UPDATE invitations SET used = 1 WHERE email = ?', (email,))
        
    # Insert initial password hash to password history
    cursor.execute('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)', (user_id, hashed))
        
    conn.commit()
    conn.close()
    
    role_str = 'Superusuario' if is_superuser else ('Administrador' if is_admin else 'Funcionario')
    add_audit_log(user_id, 'USER_REGISTER', f"Usuario registrado exitosamente con rol: {role_str}")
    
    return jsonify({'message': f"Registro de {role_str} completado exitosamente. Ahora inicie sesión para configurar su doble factor (2FA)."}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'message': 'Faltan credenciales.'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user or not verify_password(password, user['password_hash']):
        conn.close()
        return jsonify({'message': 'Credenciales incorrectas.'}), 401
        
    if user['status'] != 'active':
        conn.close()
        return jsonify({'message': 'Su cuenta está inhabilitada. Contacte al administrador de la Fiscalía.'}), 403
        
    # Enforce Single Session
    session_id = secrets.token_hex(16)
    conn.execute('UPDATE users SET current_session_id = ? WHERE id = ?', (session_id, user['id']))
    conn.commit()
    conn.close()
    
    # MANDATORY 2FA CHECK
    if user['totp_enabled'] == 0:
        # Issue temporary token
        token = jwt.encode({
            'user_id': user['id'],
            'session_id': session_id,
            'scope': '2fa_setup_pending',
            'exp': datetime.now(timezone.utc) + timedelta(minutes=10)
        }, JWT_SECRET, algorithm='HS256')
        return jsonify({
            'totp_setup_required': True,
            'token': token,
            'message': 'Es obligatorio configurar Google Authenticator (2FA) para acceder a su bóveda.'
        })
        
    # Standard Login with 2FA enabled -> Issue temporary 2FA token
    token = jwt.encode({
        'user_id': user['id'],
        'session_id': session_id,
        'scope': '2fa_pending',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=5)
    }, JWT_SECRET, algorithm='HS256')
    
    return jsonify({
        'totp_required': True,
        'token': token,
        'message': 'Se requiere validación de Google Authenticator.'
    })


@app.route('/api/auth/login/2fa', methods=['POST'])
def login_2fa():
    token = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
    if not token:
        return jsonify({'message': 'Token de verificación faltante.'}), 401
        
    data = request.json or {}
    code = data.get('code', '').strip()
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if payload.get('scope') != '2fa_pending':
            return jsonify({'message': 'Token no válido para 2FA.'}), 400
            
        user_id = payload['user_id']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if not user or user['status'] != 'active':
            return jsonify({'message': 'Usuario no válido.'}), 403
            
        # Verify Single Session
        if payload.get('session_id') != user['current_session_id']:
            return jsonify({'message': 'La sesión fue revocada debido a un nuevo login.'}), 401
            
        # Verify 2FA
        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(code, valid_window=2):
            return jsonify({'message': 'Código 2FA incorrecto o expirado.'}), 400
            
        # Successful validation - Issue full token
        full_token = jwt.encode({
            'user_id': user['id'],
            'session_id': user['current_session_id'],
            'scope': 'full_access',
            'exp': datetime.now(timezone.utc) + timedelta(minutes=15)
        }, JWT_SECRET, algorithm='HS256')
        
        role_str = 'Superusuario' if user['is_superuser'] else ('Administrador' if user['is_admin'] else 'Funcionario')
        add_audit_log(user['id'], 'USER_LOGIN_2FA', f"Inicio de sesión exitoso como {role_str} validado con Google Authenticator")
        
        return jsonify({
            'token': full_token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'is_admin': user['is_admin'],
                'is_superuser': user['is_superuser'],
                'force_password_change': user['force_password_change'],
                'totp_enabled': user['totp_enabled']
            }
        })
        
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'La sesión de inicio de sesión expiró.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Sesión inválida.'}), 401


@app.route('/api/auth/verify-totp', methods=['POST'])
@token_required
def auth_verify_totp(current_user):
    data = request.json or {}
    code = data.get('code', '').strip()
    if not code:
        return jsonify({'message': 'Código no proporcionado.'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT totp_enabled, totp_secret FROM users WHERE id = ?', (current_user['id'],)).fetchone()
    conn.close()
    
    if not user or user['totp_enabled'] == 0:
        return jsonify({'valid': True, 'message': 'TOTP no está activo.'})
        
    import pyotp
    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=2):
        return jsonify({'valid': False, 'message': 'Código de doble factor incorrecto.'}), 400
        
    return jsonify({'valid': True, 'message': 'Código verificado con éxito.'})


# ==========================================
# MANDATORY 2FA SETUP ENDPOINTS (ON LOGIN)
# ==========================================

@app.route('/api/auth/login/2fa-setup', methods=['GET'])
@token_required
def login_2fa_setup(current_user):
    if current_user.get('token_scope') != '2fa_setup_pending':
        return jsonify({'message': 'Acción no permitida.'}), 403
        
    conn = get_db_connection()
    user = conn.execute('SELECT totp_secret FROM users WHERE id = ?', (current_user['id'],)).fetchone()
    
    secret = user['totp_secret']
    if not secret:
        secret = pyotp.random_base32()
        conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, current_user['id']))
        conn.commit()
        
    conn.close()
    
    # Provisioning URI
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user['email'],
        issuer_name="VaultFiscalia"
    )
    
    # Create QR code image
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return jsonify({
        'secret': secret,
        'qr_code': f"data:image/png;base64,{img_str}"
    })


@app.route('/api/auth/login/2fa-enable', methods=['POST'])
@token_required
def login_2fa_enable(current_user):
    if current_user.get('token_scope') != '2fa_setup_pending':
        return jsonify({'message': 'Acción no permitida.'}), 403
        
    data = request.json or {}
    code = data.get('code', '').strip()
    
    conn = get_db_connection()
    user = conn.execute('SELECT totp_secret, current_session_id FROM users WHERE id = ?', (current_user['id'],)).fetchone()
    
    if not user or not user['totp_secret']:
        conn.close()
        return jsonify({'message': 'Debe inicializar la configuración de 2FA primero.'}), 400
        
    totp = pyotp.TOTP(user['totp_secret'])
    if totp.verify(code, valid_window=2):
        # Enable TOTP
        conn.execute('UPDATE users SET totp_enabled = 1 WHERE id = ?', (current_user['id'],))
        conn.commit()
        conn.close()
        
        # Successful activation - issue full access token
        full_token = jwt.encode({
            'user_id': current_user['id'],
            'session_id': user['current_session_id'],
            'scope': 'full_access',
            'exp': datetime.now(timezone.utc) + timedelta(minutes=15)
        }, JWT_SECRET, algorithm='HS256')
        
        add_audit_log(current_user['id'], '2FA_MANDATORY_SETUP', 'Activación obligatoria de Google 2FA completada en inicio de sesión')
        
        return jsonify({
            'token': full_token,
            'user': {
                'id': current_user['id'],
                'email': current_user['email'],
                'is_admin': current_user['is_admin'],
                'is_superuser': current_user['is_superuser'],
                'force_password_change': current_user['force_password_change']
            }
        })
    else:
        conn.close()
        return jsonify({'message': 'Código 2FA incorrecto o expirado.'}), 400


# ==========================================
# GLOBAL SYSTEM SETTINGS (TIMEOUT & SMTP)
# ==========================================

@app.route('/api/settings/timeout', methods=['GET'])
@token_required
def get_idle_timeout(current_user):
    conn = get_db_connection()
    row = conn.execute('SELECT value FROM system_settings WHERE key = ?', ('idle_timeout_minutes',)).fetchone()
    conn.close()
    
    minutes = int(row['value']) if row else 15
    return jsonify({'idle_timeout_minutes': minutes})


@app.route('/api/admin/settings/timeout', methods=['PUT'])
@token_required
@admin_required
def update_idle_timeout(current_user):
    data = request.json or {}
    minutes = data.get('idle_timeout_minutes')
    
    try:
        minutes = int(minutes)
        if minutes < 1:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({'message': 'El tiempo de inactividad debe ser un número entero mayor o igual a 1.'}), 400
        
    conn = get_db_connection()
    conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('idle_timeout_minutes', ?)", (str(minutes),))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_SETTINGS_TIMEOUT_UPDATE', f"El administrador cambió el tiempo de inactividad global a {minutes} minutos")
    
    return jsonify({
        'idle_timeout_minutes': minutes,
        'message': f"Tiempo de inactividad global actualizado a {minutes} minutos con éxito."
    })


@app.route('/api/admin/settings/smtp', methods=['GET'])
@token_required
@admin_required
def admin_get_smtp_settings(current_user):
    conn = get_db_connection()
    smtp_host = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_host'").fetchone()
    smtp_port = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_port'").fetchone()
    smtp_user = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_user'").fetchone()
    smtp_from = conn.execute("SELECT value FROM system_settings WHERE key = 'smtp_from'").fetchone()
    conn.close()
    
    return jsonify({
        'smtp_host': smtp_host['value'] if smtp_host else '',
        'smtp_port': smtp_port['value'] if smtp_port else '',
        'smtp_user': smtp_user['value'] if smtp_user else '',
        'smtp_from': smtp_from['value'] if smtp_from else ''
    })


@app.route('/api/admin/settings/smtp', methods=['PUT'])
@token_required
@admin_required
def admin_update_smtp_settings(current_user):
    data = request.json or {}
    smtp_host = data.get('smtp_host', '').strip()
    smtp_port = data.get('smtp_port', '').strip()
    smtp_user = data.get('smtp_user', '').strip()
    smtp_pass = data.get('smtp_pass', '')
    smtp_from = data.get('smtp_from', '').strip()
    
    if not smtp_host or not smtp_port or not smtp_from:
        return jsonify({'message': 'El servidor, puerto y remitente son campos obligatorios.'}), 400
        
    conn = get_db_connection()
    conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('smtp_host', ?)", (smtp_host,))
    conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('smtp_port', ?)", (smtp_port,))
    conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('smtp_user', ?)", (smtp_user,))
    conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('smtp_from', ?)", (smtp_from,))
    if smtp_pass:
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('smtp_pass', ?)", (smtp_pass,))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_SETTINGS_SMTP_UPDATE', 'El administrador actualizó la configuración SMTP para envíos de correo')
    return jsonify({'message': 'Configuración del servidor de correo (SMTP) actualizada con éxito.'})


# ==========================================
# USER PROFILE & SETTINGS (AUTHENTICATED)
# ==========================================

@app.route('/api/auth/user-info', methods=['GET'])
@token_required
def get_user_info(current_user):
    return jsonify(current_user)


@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    data = request.json or {}
    new_password = data.get('new_password', '')
    old_password = data.get('old_password', '')
    
    is_strong, strength_err = validate_password_strength(new_password)
    if not is_strong:
        return jsonify({'message': strength_err}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT password_hash, force_password_change FROM users WHERE id = ?', (current_user['id'],)).fetchone()
    
    # Verify old password if not forced
    if user['force_password_change'] == 0:
        if not old_password or not verify_password(old_password, user['password_hash']):
            conn.close()
            return jsonify({'message': 'Contraseña maestra actual incorrecta.'}), 400
            
    # Check Password History
    history = conn.execute('SELECT password_hash FROM password_history WHERE user_id = ?', (current_user['id'],)).fetchall()
    for row in history:
        if verify_password(new_password, row['password_hash']):
            conn.close()
            return jsonify({'message': 'Seguridad: La nueva contraseña maestra no puede ser igual a ninguna de sus contraseñas anteriores.'}), 400
            
    hashed = hash_password(new_password)
    
    # Invalidate session
    new_session_id = secrets.token_hex(16)
    
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET password_hash = ?, force_password_change = 0, current_session_id = ? WHERE id = ?',
        (hashed, new_session_id, current_user['id'])
    )
    cursor.execute(
        'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
        (current_user['id'], hashed)
    )
    
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'USER_PASSWORD_CHANGE', 'Contraseña maestra cambiada por el usuario (validada con anterior y comprobado historial)')
    
    return jsonify({'message': 'Contraseña maestra actualizada. Por seguridad, inicie sesión nuevamente.'})


@app.route('/api/auth/2fa/disable', methods=['POST'])
@token_required
def disable_2fa(current_user):
    data = request.json or {}
    password = data.get('password', '')
    
    conn = get_db_connection()
    user = conn.execute('SELECT password_hash FROM users WHERE id = ?', (current_user['id'],)).fetchone()
    
    if not user or not verify_password(password, user['password_hash']):
        conn.close()
        return jsonify({'message': 'Contraseña maestra incorrecta.'}), 401
        
    # Unlink QR/Secret
    conn.execute('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', (current_user['id'],))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], '2FA_DISABLE', 'El usuario desvinculó su Google Authenticator (2FA)')
    return jsonify({'message': 'Autenticación de doble factor desvinculada. En su próximo login se le exigirá configurar uno nuevo.'})


@app.route('/api/auth/delete-account', methods=['POST'])
@token_required
def delete_account(current_user):
    data = request.json or {}
    password = data.get('password', '')
    
    if current_user['is_admin'] == 1:
        conn = get_db_connection()
        admins = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = 1 AND status = \'active\'').fetchone()['count']
        conn.close()
        if admins <= 1:
            return jsonify({'message': 'Usted es el único administrador activo. Promueva a otro antes de dar de baja su cuenta.'}), 400
            
    conn = get_db_connection()
    user = conn.execute('SELECT password_hash FROM users WHERE id = ?', (current_user['id'],)).fetchone()
    
    if not user or not verify_password(password, user['password_hash']):
        conn.close()
        return jsonify({'message': 'Contraseña maestra incorrecta.'}), 401
        
    add_audit_log(current_user['id'], 'USER_SELF_DELETE', f"El usuario {current_user['email']} dio de baja su propia cuenta")
    
    conn.execute('DELETE FROM users WHERE id = ?', (current_user['id'],))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Su cuenta ha sido eliminada permanentemente.'})


# ==========================================
# VAULT MANAGEMENT ENDPOINTS (CRUD)
# ==========================================

@app.route('/api/vault', methods=['GET'])
@token_required
def get_vault_items(current_user):
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM vault_items WHERE user_id = ?', (current_user['id'],)).fetchall()
    conn.close()
    
    decrypted_list = []
    for item in items:
        decrypted_list.append({
            'id': item['id'],
            'name': decrypt_data(item['name']),
            'username': decrypt_data(item['username']),
            'password': decrypt_data(item['password']),
            'url': decrypt_data(item['url']),
            'notes': decrypt_data(item['notes']),
            'is_favorite': item['is_favorite']
        })
        
    return jsonify(decrypted_list)


@app.route('/api/vault', methods=['POST'])
@token_required
def add_vault_item(current_user):
    data = request.json or {}
    name = data.get('name', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    url = data.get('url', '').strip()
    notes = data.get('notes', '').strip()
    is_favorite = 1 if data.get('is_favorite') else 0
    
    if not name or not username or not password:
        return jsonify({'message': 'Nombre, usuario y contraseña son campos obligatorios.'}), 400
        
    enc_name = encrypt_data(name)
    enc_username = encrypt_data(username)
    enc_password = encrypt_data(password)
    enc_url = encrypt_data(url)
    enc_notes = encrypt_data(notes)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO vault_items (user_id, name, username, password, url, notes, is_favorite) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (current_user['id'], enc_name, enc_username, enc_password, enc_url, enc_notes, is_favorite)
    )
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'VAULT_ITEM_CREATE', f"Credencial creada: '{name}'")
    
    return jsonify({'message': 'Credencial agregada exitosamente.'}), 201


@app.route('/api/vault/<int:item_id>', methods=['PUT'])
@token_required
def update_vault_item(current_user, item_id):
    data = request.json or {}
    name = data.get('name', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    url = data.get('url', '').strip()
    notes = data.get('notes', '').strip()
    is_favorite = 1 if data.get('is_favorite') else 0
    
    if not name or not username or not password:
        return jsonify({'message': 'Nombre, usuario y contraseña son campos obligatorios.'}), 400
        
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM vault_items WHERE id = ? AND user_id = ?', (item_id, current_user['id'])).fetchone()
    
    if not existing:
        conn.close()
        return jsonify({'message': 'Credencial no encontrada.'}), 404
        
    old_password = decrypt_data(existing['password'])
    if password != old_password:
        add_audit_log(current_user['id'], 'VAULT_ITEM_PASSWORD_UPDATE', f"Contraseña actualizada para credencial: '{name}'")
    else:
        add_audit_log(current_user['id'], 'VAULT_ITEM_UPDATE', f"Credencial modificada: '{name}'")
        
    enc_name = encrypt_data(name)
    enc_username = encrypt_data(username)
    enc_password = encrypt_data(password)
    enc_url = encrypt_data(url)
    enc_notes = encrypt_data(notes)
    
    conn.execute(
        'UPDATE vault_items SET name = ?, username = ?, password = ?, url = ?, notes = ?, is_favorite = ? WHERE id = ? AND user_id = ?',
        (enc_name, enc_username, enc_password, enc_url, enc_notes, is_favorite, item_id, current_user['id'])
    )
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Credencial actualizada exitosamente.'})


@app.route('/api/vault/<int:item_id>', methods=['DELETE'])
@token_required
def delete_vault_item(current_user, item_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM vault_items WHERE id = ? AND user_id = ?', (item_id, current_user['id'])).fetchone()
    
    if not existing:
        conn.close()
        return jsonify({'message': 'Credencial no encontrada.'}), 404
        
    name = decrypt_data(existing['name'])
    conn.execute('DELETE FROM vault_items WHERE id = ? AND user_id = ?', (item_id, current_user['id']))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'VAULT_ITEM_DELETE', f"Credencial eliminada: '{name}'")
    
    return jsonify({'message': 'Credencial eliminada exitosamente.'})


# ==========================================
# ADMINISTRATIVE ENDPOINTS (ADMIN-ONLY)
# ==========================================

# Helper to check if caller has permission to modify target user
def check_administrative_permission(caller_user, target_user_id):
    conn = get_db_connection()
    target = conn.execute('SELECT is_admin, is_superuser FROM users WHERE id = ?', (target_user_id,)).fetchone()
    conn.close()
    
    if not target:
        return False, 'Usuario no encontrado.'
        
    # Standard Admin tries to modify Admin or Superuser -> Blocked!
    if (target['is_admin'] == 1 or target['is_superuser'] == 1) and caller_user['is_superuser'] != 1:
        return False, 'Acceso denegado. Un Administrador estándar no puede modificar cuentas de otros Administradores ni del Superusuario.'
        
    return True, ''


@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def admin_list_users(current_user):
    conn = get_db_connection()
    users = conn.execute('SELECT id, email, is_admin, is_superuser, status, totp_enabled, force_password_change, nombres, apellido_paterno, apellido_materno, ci FROM users').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route('/api/admin/users/<int:target_id>/status', methods=['PUT'])
@token_required
@admin_required
def admin_toggle_user_status(current_user, target_id):
    if target_id == current_user['id']:
        return jsonify({'message': 'No puede deshabilitar su propia cuenta.'}), 400
        
    permitted, err_msg = check_administrative_permission(current_user, target_id)
    if not permitted:
        return jsonify({'message': err_msg}), 403
        
    data = request.json or {}
    status = data.get('status')
    if status not in ['active', 'suspended']:
        return jsonify({'message': 'Estado inválido.'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE id = ?', (target_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Usuario no encontrado.'}), 404
        
    new_session_id = secrets.token_hex(16) if status == 'suspended' else None
    
    conn.execute('UPDATE users SET status = ?, current_session_id = ? WHERE id = ?', (status, new_session_id, target_id))
    conn.commit()
    conn.close()
    
    action = 'ADMIN_USER_DISABLE' if status == 'suspended' else 'ADMIN_USER_ENABLE'
    status_label = 'deshabilitado' if status == 'suspended' else 'habilitado'
    add_audit_log(current_user['id'], action, f"El administrador cambió el estado del usuario '{user['email']}' a '{status_label}'")
    
    return jsonify({'message': f"Usuario {status_label} exitosamente."})


@app.route('/api/admin/users/<int:target_id>/email', methods=['PUT'])
@token_required
@admin_required
def admin_edit_user_email(current_user, target_id):
    permitted, err_msg = check_administrative_permission(current_user, target_id)
    if not permitted:
        return jsonify({'message': err_msg}), 403
        
    data = request.json or {}
    new_email = data.get('email', '').strip().lower()
    
    if not new_email:
        return jsonify({'message': 'El correo electrónico es obligatorio.'}), 400
        
    if not new_email.endswith('@fiscalia.gob.bo'):
        return jsonify({'message': 'Correo inválido. Debe pertenecer al dominio @fiscalia.gob.bo.'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE id = ?', (target_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Usuario no encontrado.'}), 404
        
    conflict = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', (new_email, target_id)).fetchone()
    if conflict:
        conn.close()
        return jsonify({'message': 'El correo electrónico ya se encuentra registrado por otro usuario.'}), 400
        
    old_email = user['email']
    
    new_session_id = secrets.token_hex(16)
    conn.execute('UPDATE users SET email = ?, current_session_id = ? WHERE id = ?', (new_email, new_session_id, target_id))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_USER_EMAIL_UPDATE', f"El administrador cambió el correo de '{old_email}' a '{new_email}'")
    
    return jsonify({'message': 'Correo del usuario actualizado exitosamente.'})


@app.route('/api/admin/users/<int:target_id>/reset-2fa', methods=['PUT'])
@token_required
@admin_required
def admin_reset_user_2fa(current_user, target_id):
    permitted, err_msg = check_administrative_permission(current_user, target_id)
    if not permitted:
        return jsonify({'message': err_msg}), 403
        
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE id = ?', (target_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Usuario no encontrado.'}), 404
        
    new_session_id = secrets.token_hex(16)
    conn.execute('UPDATE users SET totp_enabled = 0, totp_secret = NULL, current_session_id = ? WHERE id = ?', (new_session_id, target_id))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_USER_2FA_RESET', f"El administrador desvinculó Google 2FA para el usuario: {user['email']}")
    
    return jsonify({'message': 'Google Authenticator desvinculado con éxito. Se cerró su sesión activa.'})


@app.route('/api/admin/users/<int:target_id>/role', methods=['PUT'])
@token_required
@admin_required
def admin_toggle_user_role(current_user, target_id):
    if current_user['is_superuser'] != 1:
        return jsonify({'message': 'Acceso denegado. Se requieren permisos de Superusuario para promover o degradar administradores.'}), 403
        
    if target_id == current_user['id']:
        return jsonify({'message': 'No puede alterar su propio rol.'}), 400
        
    data = request.json or {}
    role = data.get('role', 'funcionario').lower()
    
    if role == 'superuser':
        is_admin = 1
        is_superuser = 1
        role_name = 'Superusuario'
    elif role == 'admin':
        is_admin = 1
        is_superuser = 0
        role_name = 'Administrador'
    else:
        is_admin = 0
        is_superuser = 0
        role_name = 'Funcionario'
        
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE id = ?', (target_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Usuario no encontrado.'}), 404
        
    if target_id == 1:
        conn.close()
        return jsonify({'message': 'No se puede degradar al Superusuario principal.'}), 400
        
    conn.execute('UPDATE users SET is_admin = ?, is_superuser = ? WHERE id = ?', (is_admin, is_superuser, target_id))
    conn.commit()
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_USER_ROLE_CHANGE', f"El Superusuario cambió el rol de '{user['email']}' a '{role_name}'")
    
    return jsonify({'message': f"El rol del usuario ha sido cambiado a {role_name}."})


@app.route('/api/admin/users/<int:target_id>/reset-password', methods=['POST'])
@token_required
@admin_required
def admin_reset_user_password(current_user, target_id):
    permitted, err_msg = check_administrative_permission(current_user, target_id)
    if not permitted:
        return jsonify({'message': err_msg}), 403
        
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (target_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Usuario no encontrado.'}), 404
        
    token = secrets.token_urlsafe(16)
    conn.execute("UPDATE users SET password_reset_token = ?, status = 'pending_activation' WHERE id = ?", (token, target_id))
    conn.commit()
    conn.close()
    
    host = request.headers.get('Host', '127.0.0.1:5000')
    protocol = 'https' if request.is_secure else 'http'
    reset_url = f"{protocol}://{host}/?reset={token}"
    
    email = user['email']
    email_sent, email_msg = send_reset_password_email(email, reset_url)
    
    add_audit_log(current_user['id'], 'ADMIN_RESET_USER_PW', f"El administrador solicitó restablecimiento de contraseña para: {email}")
    
    return jsonify({
        'message': 'Enlace de restablecimiento generado y enviado con éxito.',
        'email_sent': email_sent,
        'email_status': email_msg,
        'reset_url': reset_url
    })


@app.route('/api/admin/users/<int:target_id>', methods=['DELETE'])
@token_required
@admin_required
def admin_delete_user(current_user, target_id):
    if target_id == current_user['id']:
        return jsonify({'message': 'No puede eliminar su propia cuenta.'}), 400
        
    permitted, err_msg = check_administrative_permission(current_user, target_id)
    if not permitted:
        return jsonify({'message': err_msg}), 403
        
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE id = ?', (target_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'Usuario no encontrado.'}), 404
        
    add_audit_log(current_user['id'], 'ADMIN_USER_DELETE', f"El administrador eliminó la cuenta del funcionario: '{user['email']}'")
    
    conn.execute('DELETE FROM users WHERE id = ?', (target_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Cuenta de funcionario y credenciales asociadas eliminadas de forma definitiva.'})


# --- INVITATIONS MANAGEMENT ---

@app.route('/api/admin/invitations', methods=['GET'])
@token_required
@admin_required
def admin_list_invitations(current_user):
    conn = get_db_connection()
    
    # 1. Unused invitations
    invites = conn.execute('SELECT * FROM invitations WHERE used = 0 ORDER BY created_at DESC').fetchall()
    
    # 2. Suspended or pending users
    users = conn.execute("SELECT id, email, nombres, apellido_paterno, apellido_materno, ci, status, password_reset_token FROM users WHERE status IN ('suspended', 'pending_activation')").fetchall()
    
    conn.close()
    
    res = []
    
    # Add invitations
    for i in invites:
        res.append({
            'id': i['id'],
            'email': i['email'],
            'nombres': i['nombres'],
            'apellido_paterno': i['apellido_paterno'],
            'apellido_materno': i['apellido_materno'],
            'ci': i['ci'],
            'used': i['used'],
            'token': i['token'],
            'type': 'invitation',
            'status': 'pending',
            'created_at': i['created_at'],
            'last_sent_at': i['last_sent_at']
        })
        
    # Add users
    for u in users:
        res.append({
            'id': u['id'],
            'email': u['email'],
            'nombres': u['nombres'],
            'apellido_paterno': u['apellido_paterno'],
            'apellido_materno': u['apellido_materno'],
            'ci': u['ci'],
            'used': 0,
            'token': u['password_reset_token'],
            'type': 'user',
            'status': 'inhabilitado' if u['status'] == 'suspended' else 'pending',
            'created_at': None,
            'last_sent_at': None
        })
        
    return jsonify(res)


@app.route('/api/admin/invite', methods=['POST'])
@token_required
@admin_required
def admin_create_invitation(current_user):
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    nombres = format_name_title_case(data.get('nombres', ''))
    apellido_paterno = format_name_title_case(data.get('apellido_paterno', ''))
    apellido_materno = format_name_title_case(data.get('apellido_materno', ''))
    ci = data.get('ci', '').strip()
    
    if not email:
        return jsonify({'message': 'El correo electrónico es requerido.'}), 400
    if not nombres:
        return jsonify({'message': 'El campo Nombres es requerido.'}), 400
    if not apellido_materno:
        return jsonify({'message': 'El campo Apellido Materno es requerido.'}), 400
    if not ci:
        return jsonify({'message': 'El número de CI es requerido.'}), 400
        
    if not email.endswith('@fiscalia.gob.bo'):
        return jsonify({'message': 'Solo se pueden invitar correos del dominio @fiscalia.gob.bo.'}), 400
        
    conn = get_db_connection()
    # Check duplicate user
    existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing_user:
        conn.close()
        return jsonify({'message': 'Este correo ya tiene una cuenta registrada en la bóveda.'}), 400
        
    token = secrets.token_urlsafe(16)
    existing_invite = conn.execute('SELECT token FROM invitations WHERE email = ?', (email,)).fetchone()
    if existing_invite:
        conn.execute('''
            UPDATE invitations 
            SET token = ?, used = 0, last_sent_at = datetime("now"), nombres = ?, apellido_paterno = ?, apellido_materno = ?, ci = ?
            WHERE email = ?
        ''', (token, nombres, apellido_paterno, apellido_materno, ci, email))
        conn.commit()
    else:
        try:
            conn.execute('''
                INSERT INTO invitations (email, token, last_sent_at, nombres, apellido_paterno, apellido_materno, ci)
                VALUES (?, ?, datetime("now"), ?, ?, ?, ?)
            ''', (email, token, nombres, apellido_paterno, apellido_materno, ci))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.execute('''
                UPDATE invitations 
                SET token = ?, used = 0, last_sent_at = datetime("now"), nombres = ?, apellido_paterno = ?, apellido_materno = ?, ci = ?
                WHERE email = ?
            ''', (token, nombres, apellido_paterno, apellido_materno, ci, email))
            conn.commit()
            
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_INVITE_USER', f"El administrador generó invitación para la cuenta: {email}")
    
    host = request.headers.get('Host', '127.0.0.1:5000')
    protocol = 'https' if request.is_secure else 'http'
    invite_url = f"{protocol}://{host}/?invite={token}"
    
    # Try sending HTML email via SMTP
    email_sent, email_msg = send_invitation_email(email, invite_url)
    
    return jsonify({
        'message': 'Enlace de invitación generado con éxito.',
        'email': email,
        'token': token,
        'invite_url': invite_url,
        'email_sent': email_sent,
        'email_status': email_msg
    })



@app.route('/api/admin/invite/bulk', methods=['POST'])
@token_required
@admin_required
def admin_bulk_invite(current_user):
    if 'file' not in request.files:
        return jsonify({'message': 'No se proporcionó ningún archivo.'}), 400
        
    uploaded_file = request.files['file']
    filename = uploaded_file.filename
    if not filename.endswith(('.csv', '.xlsx')):
        return jsonify({'message': 'Formato de archivo no soportado. Debe ser .csv o .xlsx.'}), 400
        
    content = uploaded_file.read()
    if not content:
        return jsonify({'message': 'El archivo está vacío.'}), 400
        
    rows = []
    if filename.endswith('.csv'):
        import io
        import csv
        try:
            first_line = content.split(b'\n')[0].decode('utf-8-sig', errors='ignore')
            delimiter = ';' if ';' in first_line else ','
            stream = io.StringIO(content.decode('utf-8-sig', errors='ignore'), newline=None)
            reader = csv.reader(stream, delimiter=delimiter)
            rows = [row for row in reader if any(row)]
        except Exception as e:
            return jsonify({'message': f'Error al decodificar el archivo CSV: {str(e)}'}), 400
    else:
        import openpyxl
        from io import BytesIO
        try:
            wb = openpyxl.load_workbook(BytesIO(content), data_only=True, read_only=True)
            sheet = wb.active
            for row in sheet.iter_rows(values_only=True):
                row_str = []
                for cell in row:
                    row_str.append(str(cell).strip() if cell is not None else "")
                if any(row_str):
                    rows.append(row_str)
        except Exception as e:
            return jsonify({'message': f'Error al leer la planilla Excel: {str(e)}'}), 400

    if len(rows) < 2:
        return jsonify({'message': 'El archivo debe contener una fila de cabecera y al menos una fila de datos.'}), 400
        
    header = [h.strip().lower() for h in rows[0]]
    
    nombres_idx = -1
    paterno_idx = -1
    materno_idx = -1
    ci_idx = -1
    email_idx = -1
    
    for idx, h in enumerate(header):
        if 'nombre' in h:
            nombres_idx = idx
        elif 'paterno' in h:
            paterno_idx = idx
        elif 'materno' in h:
            materno_idx = idx
        elif 'ci' in h or 'cedula' in h or 'documento' in h:
            ci_idx = idx
        elif 'correo' in h or 'email' in h:
            email_idx = idx
            
    if nombres_idx == -1: nombres_idx = 0
    if paterno_idx == -1: paterno_idx = 1
    if materno_idx == -1: materno_idx = 2
    if ci_idx == -1: ci_idx = 3
    if email_idx == -1: email_idx = 4
    
    max_idx = max(nombres_idx, paterno_idx, materno_idx, ci_idx, email_idx)
    
    conn = get_db_connection()
    success_count = 0
    skipped_count = 0
    errors = []
    
    host = request.headers.get('Host', '127.0.0.1:5000')
    protocol = 'https' if request.is_secure else 'http'
    
    for r_idx, row in enumerate(rows[1:], start=2):
        if len(row) <= max_idx:
            errors.append(f"Fila {r_idx}: Columnas insuficientes.")
            continue
            
        nombres = format_name_title_case(row[nombres_idx])
        apellido_paterno = format_name_title_case(row[paterno_idx])
        apellido_materno = format_name_title_case(row[materno_idx])
        ci = row[ci_idx].strip()
        email = row[email_idx].strip().lower()
        
        if not nombres or not apellido_materno or not ci or not email:
            errors.append(f"Fila {r_idx}: Faltan datos obligatorios (Nombres, Apellido Materno, CI y Correo son obligatorios).")
            continue
            
        if not email.endswith('@fiscalia.gob.bo'):
            errors.append(f"Fila {r_idx}: Correo institucional '{email}' inválido (debe terminar en @fiscalia.gob.bo).")
            continue
            
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            skipped_count += 1
            continue
            
        token = secrets.token_urlsafe(16)
        existing_invite = conn.execute('SELECT token FROM invitations WHERE email = ?', (email,)).fetchone()
        if existing_invite:
            conn.execute('''
                UPDATE invitations 
                SET token = ?, used = 0, last_sent_at = datetime("now"), nombres = ?, apellido_paterno = ?, apellido_materno = ?, ci = ?
                WHERE email = ?
            ''', (token, nombres, apellido_paterno, apellido_materno, ci, email))
        else:
            conn.execute('''
                INSERT INTO invitations (email, token, last_sent_at, nombres, apellido_paterno, apellido_materno, ci)
                VALUES (?, ?, datetime("now"), ?, ?, ?, ?)
            ''', (email, token, nombres, apellido_paterno, apellido_materno, ci))
            
        conn.commit()
        
        invite_url = f"{protocol}://{host}/?invite={token}"
        email_sent, email_msg = send_invitation_email(email, invite_url)
        
        if email_sent:
            success_count += 1
        else:
            errors.append(f"Fila {r_idx} ({email}): Enlace generado pero no se pudo enviar el correo: {email_msg}")
            success_count += 1
            
    conn.close()
    
    add_audit_log(current_user['id'], 'ADMIN_BULK_INVITE', f"El administrador procesó importación masiva. Éxitos: {success_count}, Omitidos: {skipped_count}, Errores: {len(errors)}")
    
    return jsonify({
        'message': 'Carga masiva finalizada.',
        'success_count': success_count,
        'skipped_count': skipped_count,
        'errors': errors
    })


@app.route('/api/admin/invite/<int:invite_id>/resend', methods=['POST'])
@token_required
@admin_required
def admin_resend_invitation(current_user, invite_id):
    conn = get_db_connection()
    invite = conn.execute('SELECT * FROM invitations WHERE id = ?', (invite_id,)).fetchone()
    
    if not invite:
        conn.close()
        return jsonify({'message': 'Invitación no encontrada.'}), 404
        
    if invite['used'] == 1:
        conn.close()
        return jsonify({'message': 'Esta invitación ya fue utilizada para registrar una cuenta.'}), 400
        
    email = invite['email']
    token = invite['token']
    
    # Update last_sent_at time
    conn.execute('UPDATE invitations SET last_sent_at = datetime("now") WHERE id = ?', (invite_id,))
    conn.commit()
    conn.close()
    
    host = request.headers.get('Host', '127.0.0.1:5000')
    protocol = 'https' if request.is_secure else 'http'
    invite_url = f"{protocol}://{host}/?invite={token}"
    
    # Send email
    email_sent, email_msg = send_invitation_email(email, invite_url)
    
    add_audit_log(current_user['id'], 'ADMIN_RESEND_INVITE', f"El administrador reenvió invitación para la cuenta: {email}")
    
    return jsonify({
        'message': 'Reenvío de invitación procesado.',
        'email_sent': email_sent,
        'email_status': email_msg,
        'invite_url': invite_url
    })





@app.route('/api/auth/reset/verify', methods=['GET'])
def auth_verify_reset_token():
    token = request.args.get('token', '').strip()
    if not token:
        return jsonify({'message': 'Token no proporcionado.'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE password_reset_token = ?', (token,)).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'message': 'El token de restablecimiento es inválido o ya expiró.'}), 400
        
    return jsonify({'email': user['email']})


@app.route('/api/auth/reset/confirm', methods=['POST'])
def auth_confirm_reset_password():
    data = request.json or {}
    token = data.get('token', '').strip()
    password = data.get('password', '')
    
    if not token:
        return jsonify({'message': 'Token no proporcionado.'}), 400
        
    is_valid, pw_err = validate_password_strength(password)
    if not is_valid:
        return jsonify({'message': pw_err}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT id, email FROM users WHERE password_reset_token = ?', (token,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'message': 'El token de restablecimiento es inválido o ya expiró.'}), 400
        
    # Update password and clear token
    new_hash = hash_password(password)
    conn.execute('''
        UPDATE users 
        SET password_hash = ?, password_reset_token = NULL, current_session_id = NULL, status = 'active' 
        WHERE id = ?
    ''', (new_hash, user['id']))
    conn.commit()
    conn.close()
    
    # Audit log
    add_audit_log(user['id'], 'USER_PW_RESET_CONFIRM', f"El funcionario restableció con éxito su contraseña maestra vía token.")
    
    return jsonify({'message': 'Su contraseña maestra ha sido restablecida con éxito. Ya puede iniciar sesión.'})


@app.route('/api/admin/logs', methods=['GET'])
@token_required
@admin_required
def admin_get_logs(current_user):
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT l.id, l.action, l.details, l.timestamp, u.email as user_email
        FROM audit_logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.timestamp DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])


# ==========================================
# STATIC FILES SERVING & PAGE ROUTES
# ==========================================

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory('public', path)


if __name__ == '__main__':
    os.makedirs(os.path.join(os.path.dirname(__file__), 'public'), exist_ok=True)
    
    print("--------------------------------------------------")
    print("VaultFiscalia - Iniciando Servidor")
    print("URL Local: http://127.0.0.1:5000")
    print("--------------------------------------------------")
    app.run(host='127.0.0.1', port=5000, debug=True)
