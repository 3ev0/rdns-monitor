import struct
import socket
                
def ipToInt(ipstr):
    return struct.unpack("!I", socket.inet_aton(ipstr))[0]

def intToIp(ipInt):
    return socket.inet_ntoa(struct.pack("!I", ipInt))
