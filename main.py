from fastapi import FastAPI
from db import tables
from api import router
from database import engine

app = FastAPI()
tables.Base.metadata.create_all(bind=engine)
app.include_router(router)