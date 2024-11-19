#назвал файл celery, пока без celery
from mail import mail, create_message
async def send_email(recipients: list[str], subject: str, body: str):

    message = create_message(recipients=recipients, subject=subject, body=body)
    await mail.send_message(message)
    print("Email sent")