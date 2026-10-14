"""SIEM triage service: a shared queue of fictional signals, each decided by a typed-decision model.

Endpoints:
  GET  /api/feed?after=<seq>   signals triaged since `seq` (the page polls this)
  POST /api/feedback           {"signal_id", "action": "allowlist_source" | "confirm_malicious"}
                               applies analyst feedback and re-triages that signal (before/after)
  GET  /status

The triage loop is shared by every viewer and pauses when nobody has polled recently, so the GPU
cost does not grow with traffic. Analyst feedback expires after 15 minutes.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal

import laya
import torch
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from signals import TITLES, Draft, draw
from triage import StreamState, triage

MODEL_ID = os.environ.get("TRIAGE_MODEL", "michaelfeil/laya-typed-decisions")
MODEL_REVISION = os.environ.get("TRIAGE_MODEL_REVISION") or None
PORT = int(os.environ.get("PORT", "8080"))
ALLOWED_ORIGIN_REGEX = os.environ.get(
    "TRIAGE_ALLOWED_ORIGIN_REGEX",
    r"https://([a-z0-9-]+\.)*chalk\.(ai|dev)|http://localhost(:\d+)?",
)
FEED_INTERVAL_S = float(os.environ.get("TRIAGE_FEED_INTERVAL_S", "6"))
# The loop runs only while someone has polled within this many seconds.
IDLE_AFTER_S = 120.0
FEED_SIZE = 60
SEED_SIGNALS = 8
FEEDBACK_PER_MINUTE = 10
FEED_POLLS_PER_MINUTE = 90

log = logging.getLogger("siem-triage")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


class RateLimiter:
    """Sliding one-minute window per client address."""

    def __init__(self, per_minute: int) -> None:
        super().__init__()
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window = self.hits[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.per_minute:
            return False
        window.append(now)
        return True


def client_key(request: Request) -> str:
    # Behind the scaling group's gateway, the client address is the first X-Forwarded-For hop.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (
        request.client.host if request.client else "unknown"
    )


class TriageService:
    def __init__(self) -> None:
        super().__init__()
        t0 = time.monotonic()
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.agent = laya.load(MODEL_ID, device=self.device, revision=MODEL_REVISION)
        self.stream = StreamState()
        self.rng = random.Random()
        # One device runs one batch at a time; the lock also guards the stream state.
        self.lock = threading.Lock()
        self.feed: deque[dict[str, Any]] = deque(maxlen=FEED_SIZE)
        self.drafts: OrderedDict[str, Draft] = OrderedDict()
        self.seq = 0
        self.last_poll = 0.0
        log.info(
            "loaded %s on %s in %.1fs", MODEL_ID, self.device, time.monotonic() - t0
        )

    def _run(
        self, draft: Draft, now: float
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], float]:
        record, decision, contributions, infer_ms = triage(
            self.agent, draft, self.stream, now
        )
        if self.device == "cuda":
            torch.cuda.synchronize()
        return record, decision, contributions, infer_ms

    def ingest(self, now: float) -> dict[str, Any]:
        draft = draw(self.rng)
        with self.lock:
            self.stream.observe(draft, now)
            record, decision, contributions, infer_ms = self._run(draft, now)
            self.seq += 1
            signal_id = uuid.uuid4().hex[:12]
            item = {
                "id": signal_id,
                "seq": self.seq,
                "ts": now,
                "rule": draft.rule,
                "title": TITLES[draft.rule],
                "principal": draft.principal,
                "asset": draft.asset,
                "source": draft.source,
                "expected": draft.expected,
                "record": record,
                "decision": decision,
                "contributions": contributions,
                "infer_ms": round(infer_ms, 1),
            }
            self.feed.append(item)
            self.drafts[signal_id] = draft
            while len(self.drafts) > FEED_SIZE:
                self.drafts.popitem(last=False)
        return item

    def feedback(self, signal_id: str, action: str, now: float) -> dict[str, Any]:
        with self.lock:
            draft = self.drafts.get(signal_id)
            if draft is None:
                raise KeyError(signal_id)
            before = next((item for item in self.feed if item["id"] == signal_id), None)
            if before is None:
                raise KeyError(signal_id)
            if action == "allowlist_source":
                self.stream.allowlist_source(draft.source, now)
            else:
                self.stream.confirm_malicious(draft.rule, draft.principal, now)
            record, decision, contributions, infer_ms = self._run(draft, now)
        return {
            "signal_id": signal_id,
            "action": action,
            "before": before["decision"],
            "after": {
                "record": record,
                "decision": decision,
                "contributions": contributions,
                "infer_ms": round(infer_ms, 1),
            },
        }

    def since(self, after: int) -> list[dict[str, Any]]:
        with self.lock:
            return [item for item in self.feed if item["seq"] > after][-30:]


state: dict[str, Any] = {}


async def triage_loop(service: TriageService) -> None:
    while True:
        await asyncio.sleep(FEED_INTERVAL_S)
        if time.time() - service.last_poll > IDLE_AFTER_S:
            continue
        try:
            await asyncio.to_thread(service.ingest, time.time())
        except Exception:
            log.exception("triage failed")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # uvicorn accepts no connections until this returns, so the replica goes ready only once
    # the model is resident and the queue already has signals in it.
    service = await asyncio.to_thread(TriageService)
    now = time.time()
    for i in range(SEED_SIGNALS):
        await asyncio.to_thread(
            service.ingest, now - (SEED_SIGNALS - i) * FEED_INTERVAL_S
        )
    state["service"] = service
    state["feed_limiter"] = RateLimiter(FEED_POLLS_PER_MINUTE)
    state["feedback_limiter"] = RateLimiter(FEEDBACK_PER_MINUTE)
    task = asyncio.create_task(triage_loop(service))
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
    max_age=600,
)


@app.get("/status")
async def status() -> JSONResponse:
    service: TriageService = state["service"]
    return JSONResponse(
        {"ok": True, "model": MODEL_ID, "device": service.device, "seq": service.seq}
    )


@app.get("/api/feed")
async def feed(request: Request, after: int = 0) -> JSONResponse:
    if not state["feed_limiter"].allow(client_key(request)):
        raise HTTPException(status_code=429, detail="Too many requests; slow down.")
    service: TriageService = state["service"]
    service.last_poll = time.time()
    return JSONResponse(
        {
            "now": time.time(),
            "interval_s": FEED_INTERVAL_S,
            "signals": service.since(after),
        }
    )


class FeedbackRequest(BaseModel):
    signal_id: str = Field(min_length=1, max_length=32)
    action: Literal["allowlist_source", "confirm_malicious"]


@app.post("/api/feedback")
async def feedback(req: FeedbackRequest, request: Request) -> JSONResponse:
    if not state["feedback_limiter"].allow(client_key(request)):
        raise HTTPException(
            status_code=429, detail="Too much feedback; try again in a minute."
        )
    service: TriageService = state["service"]
    try:
        result = await asyncio.to_thread(
            service.feedback, req.signal_id, req.action, time.time()
        )
    except KeyError:
        raise HTTPException(
            status_code=404, detail="That signal has left the queue."
        ) from None
    return JSONResponse(result)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
