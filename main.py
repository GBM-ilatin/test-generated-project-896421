from fastapi import FastAPI

app = FastAPI(title="Generated API", version="1.0.0")

@app.get("/")
def read_root():
    return {"message": "Hello from generated API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
