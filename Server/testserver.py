from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
import json

class MyReader():
    def __init__(self, reader):
        self.reader = reader
        self.buffer = b""
    def read(self, size=-1):
        if size < 0:
            return self.buffer + self.reader.read()
        elif size == 0:
            return b""
        elif size < len(self.buffer):
            ret = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return ret
        else:
            ret = self.buffer
            self.buffer = ""
            return ret + self.reader.read(size - len(ret))
    def read_until(self, delimeter=b"\n"):
        while delimeter not in self.buffer:
            ch = self.reader.read(1)
            if ch != b"":
                self.buffer += ch
                print(self.buffer)
        loc = self.buffer.find(delimeter) + len(delimeter)
        ret = self.buffer[:loc]
        self.buffer = self.buffer[loc:]
        return ret
    def readline(self):
        return self.read_until(b"\n")


class MyWriter():
    def __init__(self, writer):
        self.writer = writer
    def write(self, content):
        self.writer.write(content)
        self.writer.flush()

def readuntil(reader, delimeter):
    x = b''

class Handler(SimpleHTTPRequestHandler):
    def add_CORS(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self.add_CORS()
        self.end_headers()

    def do_POST(self):
        def response(success, content):
            self.send_response(200 if success else 403)
            self.add_CORS()
            self.send_header("Content-type", "application/json")
            self.end_headers()
            dicts = {}
            dicts["status"] = True if success else False
            dicts["data"] = content
            self.wfile.write(json.dumps(dicts).encode())
        if self.headers.get('Content-Type') == "application/json":
            content_len = int(self.headers.get('Content-Length'))
            post_body = self.rfile.read(content_len)
            content = json.loads(post_body)
            # start IPython
            import subprocess
            ipython_loc = "{}/profile_default/ipython_config.py".format(subprocess.Popen(["ipython", "locate"], stdout=subprocess.PIPE).stdout.readline().strip().decode())
            import base64
            try:
                if content["params"] is None:
                    import random
                    session_id = str(random.randrange(10**15, 10**16))
                    execution_count = 0
                    open("launch.py", "w").write("import dill\n")
                else:
                    session_id = content["params"]["id"]
                    execution_count = content["params"]["execution_count"]
                    open("state.pkl", "wb").write(base64.b64decode(content["data"]))
                    open("launch.py", "w").write("import dill\ndill.load_session('state.pkl')\n")
                    # import IPython; IPython.get_ipython().execution_count = {}\n".format(execution_count))
                ipython_shell = subprocess.Popen(["ipython", "-i", "launch.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)         
                    # integer check
                myreader = MyReader(ipython_shell.stdout)
                mywriter = MyWriter(ipython_shell.stdin)

                # temp measure
                execution_count2 = execution_count
                execution_count = 0

                temp = myreader.read_until("In [{}]: ".format(execution_count + 1).encode())
                mywriter.write(b"%cpaste\n")
                myreader.read_until(b":")
                mywriter.write((content["code"].strip() + "\n--\n").encode())
                myreader.read_until("Out[{}]: ".format(execution_count + 1).encode())
                delimeter = "In [{}]: ".format(execution_count + 2).encode()
                stdout = myreader.read_until(delimeter)[:-len(delimeter)].strip().decode()
                mywriter.write(b"dill.dump_session('state2.pkl')\n")
                myreader.read_until("In [{}]: ".format(execution_count + 3).encode())
                ipython_shell.kill()

                # temp measure
                execution_count = execution_count2
                # Return
                output = {
                    "params": {"id": session_id, "execution_count": execution_count + 1},
                    "outputs": [{
                        "output_type": "stream",
                        "name": "stdout",
                        "text": stdout
                    }],
                    "data": base64.b64encode(open("state2.pkl", "rb").read()).decode()
                }
                response(True, output)
            except:
                import traceback
                print(traceback.format_exc())
                response(False, "Exception when launching iPython")
        else:
            response(False, "Wrong Content Type!")

HandlerClass = Handler
ServerClass  = HTTPServer
Protocol     = "HTTP/1.0"
server_address = ('127.0.0.1', 8000)
HandlerClass.protocol_version = Protocol
httpd = ServerClass(server_address, HandlerClass)
sa = httpd.socket.getsockname()
print("Serving HTTP on", sa[0], "port", sa[1], "...")
httpd.serve_forever()