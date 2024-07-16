from socket import *

serverName = 'localhost'
serverPort = 12000

clientSocket = socket(AF_INET, SOCK_DGRAM)

message = input('Input lowercase sentence:')

message_bytes = message.encode()

clientSocket.sendto(message_bytes, (serverName, serverPort))
modifiedMessage, serverAddress = clientSocket.recvfrom(1024)

# print modifiedMessage
print(modifiedMessage.decode())

clientSocket.close()
