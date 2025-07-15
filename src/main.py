# src/main.py
from fastapi import FastAPI
from api.routes import router

app = FastAPI(title="Hawiyat Security Core")

app.include_router(router)

@app.on_event("startup")
def on_startup():
    print("Security Engine API started.") 