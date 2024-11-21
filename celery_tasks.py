#назвал файл celery, пока без celery
from mail import mail, create_message
from utils import create_url_safe_token
async def send_email(recipients: list[str], subject: str, body: str):

    message = create_message(recipients=recipients, subject=subject, body=body)
    await mail.send_message(message)
    #print("Email sent")

async def send_email_to_confirm(email):
    token = create_url_safe_token({"email": email})
    link = f"http://127.0.0.1:8000/auth/email-confirm?token={token}"
    html_message = f'Инструкция для подтверждения почты: <p>{link}</p>'
    subject = "Email Confirm Instructions"
    await send_email([email], subject, html_message)
