# src/main.py

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from api.routes import router
import logging
import uuid


# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

app = FastAPI(title="Hawiyat Security Core")


@app.middleware("http")
async def add_trace_id_and_log(request: Request, call_next):
    trace_id = str(uuid.uuid4())
    request.state.trace_id = trace_id
    logging.info(f"[trace_id={trace_id}] Incoming request: {request.method} {request.url}")
    try:
        response = await call_next(request)
    except Exception as exc:
        logging.error(f"[trace_id={trace_id}] Unhandled error: {exc}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Internal server error", "trace_id": trace_id}
        )
    response.headers["X-Trace-Id"] = trace_id
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    logging.error(f"[trace_id={trace_id}] Exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": str(exc), "trace_id": trace_id}
    )

app.include_router(router)

@app.on_event("startup")
def on_startup():
    print("Security Engine API started.") 