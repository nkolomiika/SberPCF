import asyncio
import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import aio_pika
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.mail import send_plain_text_email
from app.models import MailJob

settings = get_settings()
DEBUG_LOG_PATH = Path("/workspace/debug-755228.log")


def _debug_log(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    payload = {
        "sessionId": "755228",
        "runId": "mail-worker-connect",
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(datetime.now(UTC).timestamp() * 1000),
    }
    try:
        with DEBUG_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


async def relay_pending_jobs(channel: aio_pika.abc.AbstractChannel, queue_name: str) -> None:
    while True:
        async with SessionLocal() as db:
            jobs = list(
                (
                    await db.scalars(
                        select(MailJob).where(MailJob.status == "pending").order_by(MailJob.created_at.asc()).limit(50)
                    )
                ).all()
            )
            for job in jobs:
                await channel.default_exchange.publish(
                    aio_pika.Message(
                        body=str(job.id).encode("utf-8"),
                        content_type="text/plain",
                        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    ),
                    routing_key=queue_name,
                )
                job.status = "queued"
                job.published_at = datetime.now(UTC)
                job.last_error = None
            if jobs:
                await db.commit()
        await asyncio.sleep(5)


async def process_mail_job(job_id: UUID) -> None:
    async with SessionLocal() as db:
        job = await db.scalar(select(MailJob).where(MailJob.id == job_id))
        if not job or job.status == "sent":
            return
        job.status = "processing"
        job.attempts += 1
        await db.commit()
        try:
            await send_plain_text_email(
                recipient_email=job.recipient_email,
                subject=job.subject,
                body=str(job.payload.get("body", "")),
            )
        except Exception as exc:
            job.status = "failed"
            job.last_error = str(exc)
            await db.commit()
            return
        job.status = "sent"
        job.sent_at = datetime.now(UTC)
        job.last_error = None
        await db.commit()


async def consume_mail_jobs(queue: aio_pika.abc.AbstractQueue) -> None:
    async with queue.iterator() as iterator:
        async for message in iterator:
            async with message.process(requeue=False):
                await process_mail_job(UUID(message.body.decode("utf-8")))


async def main() -> None:
    if not settings.mail_enabled:
        while True:
            await asyncio.sleep(60)
    parsed_rabbitmq_url = urlsplit(settings.rabbitmq_url)
    attempt = 0
    # region agent log
    _debug_log(
        "H2",
        "backend/app/worker/mail_worker.py:main:init",
        "Mail worker startup settings",
        {
            "mail_enabled": settings.mail_enabled,
            "queue_name": settings.mail_queue_name,
            "rabbitmq_scheme": parsed_rabbitmq_url.scheme,
            "rabbitmq_host": parsed_rabbitmq_url.hostname,
            "rabbitmq_port": parsed_rabbitmq_url.port or 5672,
            "rabbitmq_vhost": parsed_rabbitmq_url.path or "/",
        },
    )
    # endregion
    while True:
        try:
            attempt += 1
            resolved_addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        parsed_rabbitmq_url.hostname or "rabbitmq",
                        parsed_rabbitmq_url.port or 5672,
                        type=socket.SOCK_STREAM,
                    )
                }
            )
            # region agent log
            _debug_log(
                "H1",
                "backend/app/worker/mail_worker.py:main:before_connect",
                "Attempting RabbitMQ connection",
                {
                    "attempt": attempt,
                    "rabbitmq_host": parsed_rabbitmq_url.hostname,
                    "rabbitmq_port": parsed_rabbitmq_url.port or 5672,
                    "resolved_addresses": resolved_addresses,
                },
            )
            # endregion
            connection = await aio_pika.connect_robust(settings.rabbitmq_url)
            async with connection:
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=10)
                queue = await channel.declare_queue(settings.mail_queue_name, durable=True)
                # region agent log
                _debug_log(
                    "H1",
                    "backend/app/worker/mail_worker.py:main:connected",
                    "RabbitMQ connection established",
                    {
                        "attempt": attempt,
                        "queue_name": queue.name,
                    },
                )
                # endregion
                relay_task = asyncio.create_task(relay_pending_jobs(channel, queue.name))
                consumer_task = asyncio.create_task(consume_mail_jobs(queue))
                await asyncio.gather(relay_task, consumer_task)
        except Exception as exc:
            # region agent log
            _debug_log(
                "H3",
                "backend/app/worker/mail_worker.py:main:connect_error",
                "RabbitMQ connection failed",
                {
                    "attempt": attempt,
                    "exception_type": type(exc).__name__,
                    "exception": str(exc),
                    "rabbitmq_host": parsed_rabbitmq_url.hostname,
                    "rabbitmq_port": parsed_rabbitmq_url.port or 5672,
                },
            )
            # endregion
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
