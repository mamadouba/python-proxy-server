import sys
from flask import Flask
from flask import request 


app = Flask(__name__)

@app.route("/")
def get():
    return "Hello world" * 4096

@app.route("/", methods=['POST'])
def post():
    return " ".join(request.form.keys())

@app.route("/fib/<number>")
def fib(number):
    def fibn(n):
        if n < 2:
           return n 
        return fibn(n-1) + fibn(n-2)

    f = fibn(int(number))
    return f"Fib({number}) = {f}"

#server.run(app=app)
