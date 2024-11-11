from fastapi import FastAPI

app = FastAPI()

@app.post('/')
def ola():
    return {'hello' : 'hello'}