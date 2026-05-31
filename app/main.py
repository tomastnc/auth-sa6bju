from fastapi import FastAPI

app = FastAPI(title="sa6bju googleauth")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
