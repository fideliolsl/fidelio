from flask import Blueprint

bp = Blueprint("socket", __name__)

@bp.route("/trigger")
def triggers(socket):
    while not socket.closed:
        message = socket.recieve()
        socket.send(message)
