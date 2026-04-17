import asyncio
import json
from datetime import UTC, datetime
from urllib import request as urllib_request
from uuid import UUID

import aio_pika
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.mail import send_plain_text_email
from app.models import MailJob

settings = get_settings()


def _debug_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: dict) -> None:
    payload = {
        "sessionId": "a74592",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(datetime.now(UTC).timestamp() * 1000),
    }
    req = urllib_request.Request(
        "http://127.0.0.1:7847/ingest/092a8b93-589d-44d5-a2a5-67f255084dee",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Debug-Session-Id": "a74592"},
        method="POST",
    )
    try:
        urllib_request.urlopen(req, timeout=2).read()
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
    while True:
        try:
            # #region agent log
            _debug_log(
                run_id="mail-worker-broker",
                hypothesis_id="H2",
                location="mail_worker.py:main:connect_start",
                message="Mail worker attempting broker connection",
                data={
                    "mail_enabled": settings.mail_enabled,
                    "rabbitmq_url": settings.rabbitmq_url,
                    "mail_queue_name": settings.mail_queue_name,
                },
            )
            # #endregion
            connection = await aio_pika.connect_robust(settings.rabbitmq_url)
            async with connection:
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=10)
                queue = await channel.declare_queue(settings.mail_queue_name, durable=True)
                # #region agent log
                _debug_log(
                    run_id="mail-worker-broker",
                    hypothesis_id="H3",
                    location="mail_worker.py:main:connect_success",
                    message="Mail worker connected to broker",
                    data={"mail_queue_name": queue.name},
                )
                # #endregion
                relay_task = asyncio.create_task(relay_pending_jobs(channel, queue.name))
                consumer_task = asyncio.create_task(consume_mail_jobs(queue))
                await asyncio.gather(relay_task, consumer_task)
        except Exception as exc:
            # #region agent log
            _debug_log(
                run_id="mail-worker-broker",
                hypothesis_id="H3",
                location="mail_worker.py:main:connect_error",
                message="Mail worker broker connection failed",
                data={"error_type": type(exc).__name__, "error_message": str(exc)},
            )
            # #endregion
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
