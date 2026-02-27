import os

from celery import Celery
from dotenv import load_dotenv

load_dotenv()

broker_url = os.getenv("broker_url")
result_backend = os.getenv("result_backend")

celery = Celery(
    "static_analysis",
    broker = broker_url,
    backend = result_backend,
    include=["tasks"],   
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
