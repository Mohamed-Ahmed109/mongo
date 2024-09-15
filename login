from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from pymongo import MongoClient, errors
from bson import ObjectId
from typing import List, Dict, Optional
import datetime

app = FastAPI()


SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


connection_string = "mongodb://localhost:27017/"
mongo = MongoClient(connection_string)
db = "mydatabase"
mycollection = "Mycollection"

class ItemModel(BaseModel):
    name: str
    value: str
    age: Optional[int] = Field(ge=0, le=100)

class User(BaseModel):
    username: str
    password: str


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    token = credentials.credentials
    payload = decode_token(token)
    return payload

# Authentication endpoint
@app.post("/login")
async def login(user: User):
    # Replace this with actual user verification
    if user.username == "user" and user.password == "password":
        access_token = create_access_token(data={"sub": user.username})
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# CRUD Operations
@app.post("/items/")
async def create_item(item: ItemModel, current_user=Depends(get_current_user)):
    try:
        result =mongo[db][mycollection].insert_one(item.dict())
        return {"msg": "Item created successfully", "id": str(result.inserted_id)}
    except errors.PyMongoError as e:
        raise HTTPException(status_code=500, detail={"msg": "Database error", "error": str(e)})

@app.get("/items/")
async def read_items(name: Optional[str] = None, value: Optional[str] = None, age: Optional[int] = None, current_user=Depends(get_current_user)) -> List[Dict]:
    try:
        query = {}
        if name:
            query["name"] = name
        if value:
            query["value"] = value
        if age is not None:
            query["age"] = age
        
        items = list(mongo[db][mycollection].find(query))
        for item in items:
            item["_id"] = str(item["_id"])  # Convert ObjectId to string for JSON serialization
        
        return items
    except errors.PyMongoError as e:
        raise HTTPException(status_code=500, detail={"msg": "Database error", "error": str(e)})

@app.patch("/items/{item_id}")
async def update_item(item_id: str, item: ItemModel, current_user=Depends(get_current_user)):
    try:
        object_id = ObjectId(item_id)
        update_result = mongo[db][mycollection].update_one({"_id": object_id}, {"$set": item.dict()})
        if update_result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Item not found")
        return {"msg": "Item updated successfully"}
    except errors.PyMongoError as e:
        raise HTTPException(status_code=500, detail={"msg": "Database error", "error": str(e)})

@app.delete("/items/{item_id}")
async def delete_item(item_id: str, current_user=Depends(get_current_user)):
    try:
        object_id = ObjectId(item_id)
        delete_result =mongo[db][mycollection].delete_one({"_id": object_id})
        if delete_result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Item not found")
        return {"msg": "Item deleted successfully"}
    except errors.PyMongoError as e:
        raise HTTPException(status_code=500, detail={"msg": "Database error", "error": str(e)})
