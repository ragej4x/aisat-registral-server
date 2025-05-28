""""
    EMAIL HANDLER FOR SENDING EMAILS / CODES

    This file contains the code for sending emails and codes to the user.
    It uses the smtplib library to send emails and the random library to generate codes.
    
    Functions:
    - Generatecode: Class to generate and send verification codes via email
    - send_password_reset_confirmation: Sends a confirmation email after password reset
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import sys
from datetime import datetime
from email.utils import formataddr

# Email configuration
sender_email = "aisatregistral@gmail.com"
sender_name = "AISAT Registration System"
formatted_sender = formataddr((sender_name, sender_email))
app_password = "jgyx jdge vtui zjgy"

class Generatecode():
    def __init__(self, email, attempt=0, skip_dev_email=False):
        self.code = f"{random.randint(0, 9999):04d}"
        self.email = email
        self.skip_dev_email = skip_dev_email

    def get_code(self):
        """Generate and send a verification code to the user's email"""
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = "AISAT Password Recovery"
            message["From"] = formatted_sender
            message["To"] = self.email

            # Plain text version
            text = f"""
AISAT Password Recovery

Your verification code is: {self.code}

Please enter this code in the app to reset your password.
This code will expire in 10 minutes.

If you did not request a password reset, please ignore this email.

AISAT Registration System
"""

            # Enhanced HTML version with improved design
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AISAT Password Recovery</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
        
        body, html {{
            font-family: 'Roboto', Arial, sans-serif;
            line-height: 1.6;
            color: #444;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        
        .email-container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .header {{
            text-align: center;
            padding: 0;
        }}
        
        .header img {{
            max-width: 100%;
            height: auto;
            display: block;
            border-radius: 12px 12px 0 0;
        }}
        
        .content {{
            padding: 30px;
            color: #333;
            background-color: #ffffff;
        }}
        
        .content h2 {{
            color: #001489;
            margin-top: 0;
            font-size: 24px;
            text-align: center;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        
        .content p {{
            margin-bottom: 20px;
            font-size: 16px;
            line-height: 1.6;
        }}
        
        .code-container {{
            background-color: #f7f9ff;
            border: 1px solid #e0e7ff;
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            text-align: center;
        }}
        
        .code {{
            font-size: 42px;
            font-weight: 700;
            color: #001489;
            letter-spacing: 8px;
            margin: 15px 0;
        }}
        
        .note {{
            background-color: #fffde7;
            border-left: 4px solid #ffd54f;
            padding: 15px 20px;
            margin: 20px 0;
            font-size: 15px;
            border-radius: 4px;
        }}
        
        .button {{
            display: inline-block;
            background-color: #001489;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 4px;
            margin: 20px 0;
            font-weight: 500;
        }}
        
        .footer {{
            background-color: #f7f9ff;
            padding: 20px 30px;
            font-size: 13px;
            color: #777;
            text-align: center;
            border-top: 1px solid #e0e7ff;
        }}

        .signature {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px dashed #e0e7ff;
        }}

        .signature p {{
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <img src="https://i.ibb.co/PZvm3X7f/aisat.png" alt="AISAT Logo" style="max-width:100%; height:auto; display:block; border-radius:12px 12px 0 0;">
        </div>
        
        <div class="content">
            <h2>Password Recovery</h2>
            
            <p>Dear Student,</p>
            
            <p>We received a request to reset your password for the AISAT Registration System. To continue with the password reset process, please use the verification code below:</p>
            
            <div class="code-container">
                <p><strong>Your verification code is:</strong></p>
                <div class="code">{self.code}</div>
                <p>This code will expire in 10 minutes</p>
            </div>
            
            <p>If you didn't request a password reset, you can safely ignore this email and your password will remain unchanged.</p>
            
            <div class="note">
                <strong>Security Tip:</strong> Never share this code with anyone. AISAT staff will never ask for your verification code.
            </div>
            
            <p>If you need assistance, please contact our support team.</p>
            
            <div class="signature">
                <p>Thank you,<br>
                <strong>AISAT Registration Team</strong></p>
            </div>
        </div>
        
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2023 Asian International School of Aeronautics and Technology. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""

            part1 = MIMEText(text, "plain")
            part2 = MIMEText(html, "html")
            message.attach(part1)
            message.attach(part2)
            
            try:
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                    server.login(sender_email, app_password)
                    
                    # If skip_dev_email is True and the recipient is not devtestragejax@gmail.com,
                    # only send to the user. Otherwise, follow the original behavior.
                    recipients = [self.email]
                    if not self.skip_dev_email and self.email != sender_email:
                        recipients.append(sender_email)
                        
                    server.sendmail(formatted_sender, recipients, message.as_string())
            except Exception:
                # Still return the code regardless of email success for development
                pass
                
            return self.code
            
        except Exception as e:
            # Still return the code to allow for testing
            return self.code

def send_password_reset_confirmation(email, skip_dev_email=False):
    """Send a confirmation email after password reset"""
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = "AISAT Password Reset Successful"
        message["From"] = formatted_sender
        message["To"] = email

        # Current time for the email
        current_time = datetime.now().strftime("%B %d, %Y at %I:%M %p")

        # Plain text version
        text = f"""
AISAT Password Reset Successful

Your password has been successfully reset on {current_time}.

If you did not make this change, please contact our support team immediately.

Thank you,
AISAT Registration Team
"""

        # HTML version with improved design
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AISAT Password Reset Successful</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
        
        body, html {{
            font-family: 'Roboto', Arial, sans-serif;
            line-height: 1.6;
            color: #444;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        
        .email-container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .header {{
            text-align: center;
            padding: 0;
        }}
        
        .header img {{
            max-width: 100%;
            height: auto;
            display: block;
            border-radius: 12px 12px 0 0;
        }}
        
        .content {{
            padding: 30px;
            color: #333;
            background-color: #ffffff;
        }}
        
        .content h2 {{
            color: #001489;
            margin-top: 0;
            font-size: 24px;
            text-align: center;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        
        .content p {{
            margin-bottom: 20px;
            font-size: 16px;
            line-height: 1.6;
        }}
        
        .success-box {{
            background-color: #f0fff0;
            border: 1px solid #d0e9d0;
            border-radius: 8px;
            padding: 25px;
            margin: 25px 0;
            text-align: center;
        }}
        
        .success-icon {{
            color: #4caf50;
            font-size: 52px;
            margin-bottom: 15px;
        }}
        
        .success-box h3 {{
            color: #2e7d32;
            margin: 10px 0;
        }}
        
        .alert {{
            background-color: #fff5e6;
            border-left: 4px solid #ff9800;
            padding: 15px 20px;
            margin: 20px 0;
            font-size: 15px;
            border-radius: 4px;
        }}
        
        .details {{
            background-color: #f7f9ff;
            border-radius: 8px;
            padding: 15px 20px;
            margin: 20px 0;
            border: 1px solid #e0e7ff;
        }}
        
        .details p {{
            margin: 8px 0;
            font-size: 15px;
        }}
        
        .footer {{
            background-color: #f7f9ff;
            padding: 20px 30px;
            font-size: 13px;
            color: #777;
            text-align: center;
            border-top: 1px solid #e0e7ff;
        }}

        .signature {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px dashed #e0e7ff;
        }}

        .signature p {{
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <img src="https://i.ibb.co/PZvm3X7f/aisat.png" alt="AISAT Logo" style="max-width:100%; height:auto; display:block; border-radius:12px 12px 0 0;">
        </div>
        
        <div class="content">
            <h2>Password Reset Successful</h2>
            
            <p>Dear Student,</p>
            
            <div class="success-box">
                <div class="success-icon" style="color:#4caf50; font-size:52px; margin-bottom:15px;">✅</div>
                <h3>Your password has been reset successfully</h3>
                <p>You can now log in with your new password</p>
            </div>
            
            <div class="details">
                <p><strong>Email:</strong> {email}</p>
                <p><strong>Time:</strong> {current_time}</p>
                <p><strong>Action:</strong> Password Reset</p>
            </div>
            
            <div class="alert">
                <strong>Important:</strong> If you did not request this password change, please contact our support team immediately as your account may be at risk.
            </div>
            
            <p>Thank you for using the AISAT Registration System.</p>
            
            <div class="signature">
                <p>Thank you,<br>
                <strong>AISAT Registration Team</strong></p>
            </div>
        </div>
        
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2023 Asian International School of Aeronautics and Technology. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""

        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)
        
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, app_password)
                
                # If skip_dev_email is True and the recipient is not devtestragejax@gmail.com,
                # only send to the user. Otherwise, follow the original behavior.
                recipients = [email]
                if not skip_dev_email and email != sender_email:
                    recipients.append(sender_email)
                    
                server.sendmail(formatted_sender, recipients, message.as_string())
            return True
        except Exception:
            return False
            
    except Exception:
        return False
