import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import os

def test_send():
    smtp_host = 'smtp.gmail.com'
    smtp_port = 587
    smtp_user = 'rolo.gareca.2014@gmail.com'
    smtp_pass = 'Boc@.2018'
    smtp_from = 'operaciones@fiscalia.gob.bo'
    email_to = 'rolando.gareca@fiscalia.gob.bo'
    
    invite_url = 'http://127.0.0.1:5000/?invite=TEST_TOKEN_12345'
    
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
                <img src="cid:logo_fiscalia" class="logo" alt="Fiscalía Departamental de Santa Cruz">
            </div>
            
            <div class="email-body">
                <p class="invitation-text">
                    Ha sido invitado a unirse a la organización <strong>Fiscalía Departamental de Santa Cruz</strong>.
                </p>
                
                <a href="{invite_url}" class="btn-join">Unirse a la Organización</a>
                
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
    
    msg = MIMEMultipart('related')
    msg['Subject'] = 'Unirse a Fiscalía Departamental de Santa Cruz'
    msg['From'] = f"Fiscalía de Santa Cruz <{smtp_from}>"
    msg['To'] = email_to
    
    msg_alternative = MIMEMultipart('alternative')
    msg.attach(msg_alternative)
    
    part = MIMEText(html_body, 'html', 'utf-8')
    msg_alternative.attach(part)
    
    # Attach CID image
    logo_path = 'public/logo_fiscalia.png'
    if os.path.exists(logo_path):
        with open(logo_path, 'rb') as f:
            msg_image = MIMEImage(f.read())
            msg_image.add_header('Content-ID', '<logo_fiscalia>')
            msg_image.add_header('Content-Disposition', 'inline', filename='logo_fiscalia.png')
            msg.attach(msg_image)
            print("CID logo attached.")
            
    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, email_to, msg.as_string())
        server.quit()
        print("SUCCESS: Email sent successfully!")
    except Exception as e:
        print("FAILED to send email:", e)

if __name__ == '__main__':
    test_send()
