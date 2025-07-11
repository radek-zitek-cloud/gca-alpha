from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.get("/")
async def read_root():
    return {"message": "Welcome to the API Gateway"}


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    if item_id < 0:
        raise HTTPException(status_code=400, detail="Invalid item ID")
    return {"item_id": item_id}