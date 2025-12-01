import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import sys

def run_subpro_py():
    """Run subPro.py and capture its output"""
    try:
        result = subprocess.run(
            [sys.executable, 'subPro.py'],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = f"""Return code: {result.returncode}

STDOUT:
{result.stdout if result.stdout else '(empty)'}

STDERR:
{result.stderr if result.stderr else '(empty)'}
"""
        return output
    except subprocess.TimeoutExpired:
        return "Error: Script execution timed out"
    except Exception as e:
        return f"Error running script: {str(e)}"

def send_email(subject, body, to_email):
    """Send email using Gmail SMTP"""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    from_email = "ecem117.project@gmail.com"
    
    # Try to get password from environment or file
    password = os.environ.get('GMAIL_APP_PASSWORD', '')
    
    if not password:
        try:
            with open('gmail_password.txt', 'r') as f:
                password = f.read().strip()
        except FileNotFoundError:
            pass
    
    if not password:
        print("\n" + "="*60)
        print("Gmail App Password Required")
        print("="*60)
        print("\nTo send emails, you need a Gmail App Password.")
        print("\nSteps to create an App Password:")
        print("1. Go to: https://myaccount.google.com/security")
        print("2. Enable 2-Step Verification (if not already enabled)")
        print("3. Go to: https://myaccount.google.com/apppasswords")
        print("4. Select 'Mail' and 'Other (Custom name)'")
        print("5. Enter 'Python Script' as the name")
        print("6. Copy the 16-character password")
        print("\nThen either:")
        print("  Option A: Set environment variable:")
        print("    Windows: set GMAIL_APP_PASSWORD=your_password")
        print("    Linux/Mac: export GMAIL_APP_PASSWORD=your_password")
        print("\n  Option B: Create a file named 'gmail_password.txt' with the password")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to server and send
        print(f"\nConnecting to Gmail SMTP server...")
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        print("Logging in...")
        server.login(from_email, password)
        print("Sending email...")
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        
        print(f"\n✓ Email sent successfully to {to_email}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("\n✗ Authentication failed. Please check your app password.")
        return False
    except Exception as e:
        print(f"\n✗ Error sending email: {e}")
        return False

def main():
    print("Running subPro.py...")
    output = run_subpro_py()
    print(f"\nCaptured output:\n{output}")
    
    # Prepare email content
    subject = "Output from subPro.py"
    body = f"""The output from running subPro.py:

{output}

Script execution completed.
"""
    
    # Send email
    to_email = "ecem117.project@gmail.com"
    print(f"\nPreparing to send email to {to_email}...")
    send_email(subject, body, to_email)

if __name__ == "__main__":
    main()

