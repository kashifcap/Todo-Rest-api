from flask import jsonify,make_response,request
from api import app



@app.route('/')
def register():
    return "hello"