import zmq
import sys, os

def start_zmq():
    context = zmq.Context()
    print("[INFO] New ZMQ connection…")
    try:
        socket = context.socket(zmq.REQ)
        server = "stlx.online"
        port = "45670"
        socket.connect(f"tcp://{server}:{port}")
        socket.RCVTIMEO = 5000 #milliseconds
        socket.send(b"hello")
        m = socket.recv()
    except Exception as e:
        try:
            print(e)
            print("[ERROR] ZMQ server is not responding. Try to starting wallet with \"--disablezmq 1\" option.\n[ERROR] Exiting...\n\n")
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    
    if m == b"hello":
        print(f"[INFO] Connected to ZMQ server: {server}:{port}")
    else:
        print("[ERROR] ZMQ server nos responding properly. Try to starting wallet with \"--disablezmq 1\" option.\n[ERROR] Exiting...\n\n")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    
    return socket
    
def zmq_request(socket, value):
        socket.send(value)
        message = socket.recv()
        return message.decode("utf-8")