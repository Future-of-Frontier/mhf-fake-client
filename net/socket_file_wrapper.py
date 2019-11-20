#https://stackoverflow.com/a/55825906
def readnbyte(sock, n):
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff

class SocketFileWrapper(object):
    def __init__(self, sock):
        self.s = sock

    def read(self, n):
        return readnbyte(self.s, n)

    def write(self, data):
        return self.s.sendall(data)

