# app.py
import hashlib
import hmac
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI()

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")  # xoxb token if you want to reply
FORWARD_WEBHOOK_URL = os.environ.get(
    "FORWARD_WEBHOOK_URL"
)  # your n8n or Notion ingest URL


def verify_signature(raw_body: bytes, ts: str, sig: str) -> bool:
    # Slack recommends rejecting if timestamp is older than 5 minutes
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    base = f"v0:{ts}:{raw_body.decode('utf-8')}".encode()
    mac = hmac.new(
        SLACK_SIGNING_SECRET.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    expected = "v0=" + mac
    return hmac.compare_digest(expected, sig)


@app.post("/webhook/slack-events")
async def slack_events(request: Request):
    raw = await request.body()
    ts = request.headers.get("X-Slack-Request-Timestamp")
    sig = request.headers.get("X-Slack-Signature")

    if not ts or not sig or not verify_signature(raw, ts, sig):
        raise HTTPException(status_code=401, detail="invalid signature")

    data = await request.json()

    # URL verification
    if data.get("type") == "url_verification":
        return PlainTextResponse(data.get("challenge", ""))

    # Event callbacks
    if data.get("type") == "event_callback":
        event = data.get("event", {})
        is_message = event.get("type") == "message"
        ch = event.get("channel", "")
        ch_type = event.get("channel_type")  # "im" or "mpim" for DMs
        if is_message and (ch.startswith("D") or ch_type in {"im", "mpim"}):
            payload = {
                "team_id": data.get("team_id"),
                "channel": ch,
                "channel_type": ch_type,
                "user": event.get("user"),
                "text": event.get("text"),
                "ts": event.get("ts"),
            }

            # Forward to Notion or n8n if configured
            if FORWARD_WEBHOOK_URL:
                try:
                    async with httpx.AsyncClient(timeout=5) as client:
                        await client.post(FORWARD_WEBHOOK_URL, json=payload)
                except Exception:
                    # Do not fail the Slack ack
                    pass

            # Optional reply back in the DM
            if SLACK_BOT_TOKEN:
                try:
                    async with httpx.AsyncClient(timeout=5) as client:
                        await client.post(
                            "https://slack.com/api/chat.postMessage",
                            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
                            json={"channel": ch, "text": "Got it"},
                        )
                except Exception:
                    pass

    # Always ack quickly
    return JSONResponse({"ok": True})
