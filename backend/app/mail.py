from email.message import EmailMessage
from email.utils import formataddr

import aiosmtplib

from app.config import get_settings

settings = get_settings()


def build_temporary_password_email(*, username: str, temporary_password: str) -> tuple[str, str]:
    subject = "PCF: временный пароль"
    body = (
        f"Здравствуйте, {username}!\n\n"
        "Для вашей учетной записи был создан или сброшен пароль.\n"
        f"Временный пароль: {temporary_password}\n\n"
        "При первом входе система попросит вас задать новый пароль.\n"
        "Если вы не ожидали это письмо, свяжитесь с администратором."
    )
    return subject, body


async def send_plain_text_email(*, recipient_email: str, subject: str, body: str) -> None:
    message = EmailMessage()
    # formataddr корректно кодирует кириллицу и спец-символы в display name
    # (RFC 2047/5322). Прямая f-string «{name} <{email}>» ломалась бы на запятых.
    message["From"] = formataddr((settings.smtp_from_name, settings.smtp_from_email))
    message["To"] = recipient_email
    message["Subject"] = subject
    message.set_content(body, charset="utf-8")
    # Порт 465 → implicit TLS (use_tls=True). Порт 587 → STARTTLS (start_tls=True).
    use_tls = bool(settings.smtp_use_ssl)
    start_tls = bool(settings.smtp_use_tls) and not use_tls
    await aiosmtplib.send(
        message,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username or None,
        password=settings.smtp_password or None,
        use_tls=use_tls,
        start_tls=start_tls,
        timeout=settings.smtp_timeout_seconds,
    )
