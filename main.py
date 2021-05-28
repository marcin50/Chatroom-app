#!/usr/bin/env python3

import socket
import argparse
import os
import sys
import base64
import threading
import select
import json

########################################################################

# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.

CMD_FIELD_LEN = 1 # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN  = 12

# Changed for Lab 4.
CMD = { "CONNECT" : 1,
        "BYE" : 2,
        "NAME" : 3,
        "CHAT" : 4,
        "GETDIR" : 5,
        "MAKEROOM" : 6,
        "DELETEROOM" : 7 
        }

MSG_ENCODING = "utf-8"



########################################################################
# SERVER
########################################################################

class Server:

    
    # Chat Room Directory Server
    HOSTNAME = "127.0.0.1"
    PORT = 30000

    RECV_SIZE = 1024
    BACKLOG = 100

    server = []
    client = []

    CRD = {
    "test":["239.0.0.10", 2000],
    "test2":["239.0.0.69", 5463],
    }

    def __init__(self):

        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.BACKLOG)
            print("Chat Room Directory Service listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            while True:
                new_client = self.socket.accept()

                # A new client has connected. Create a new thread and
                # have it process the client using the connection
                # handler function.
                new_thread = threading.Thread(target=self.connection_handler,
                                              args=(new_client,))


                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()
        except (KeyboardInterrupt, EOFError):
            print()
        finally:
            self.socket.close()

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))

        # Read the command and see if it is a GET.
        while True:
            try:
                cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')
                
                if cmd == CMD["BYE"]:
                    print()
                    print("Closing client connection ... ")
                    connection.close()
                    break
                elif cmd == CMD["GETDIR"]:
                    self.getDirectory(connection)
                elif cmd == CMD["MAKEROOM"]:
                    self.makeNewRoom(connection)
                elif cmd == CMD["DELETEROOM"]:
                    self.deleteRoom(connection)
                
            except (KeyboardInterrupt, EOFError):
                    print()
                    print("Closing client connection ... ")
                    connection.close()
                    break
    
    def getDirectory(self,connection):
        data_string = json.dumps(self.CRD)
        connection.sendall(data_string.encode(MSG_ENCODING))


    def makeNewRoom(self,connection):
        #needs the chat room name, address and port
        #return message indicating that the room is created (use getDirectory to check)

        recvd_bytes=connection.recv(Server.RECV_SIZE)
        input_text=recvd_bytes.decode(MSG_ENCODING)

        if input_text.split()[1] in self.CRD:
            to_send = "room name already exist"
            connection.sendall(to_send.encode(MSG_ENCODING))
            return
        else:
            for room,values in self.CRD.items():
                if values[0] == input_text.split()[2] and values[1] == int(input_text.split()[3].strip()):
                    to_send = "address and port already exist"
                    connection.sendall(to_send.encode(MSG_ENCODING))
                    return
        
            self.CRD[input_text.split()[1]] = [input_text.split()[2],int(input_text.split()[3].strip())]
            to_send = f'Chatroom has {input_text.split()[1]} been added!'
            connection.sendall(to_send.encode(MSG_ENCODING))

        
    def deleteRoom(self,connection):
        #needs the chat room name
        #return message indicating that the room is deleted (use getDirectory to check)
        
        recvd_bytes = connection.recv(Server.RECV_SIZE)
        room_name = recvd_bytes.decode(MSG_ENCODING)

        if room_name in self.CRD:
            del self.CRD[room_name]
            to_send = 'Chatroom has been deleted'
            connection.sendall(to_send.encode(MSG_ENCODING))
        else:
            to_send = 'Cannot delete a room that does not exist'
            connection.sendall(to_send.encode(MSG_ENCODING))


########################################################################
# CLIENT
########################################################################

class Client:

    RECV_SIZE = 256 # Changed from 10 to 44 so we can recieve the full UDP broadcast.
 
    
    NAME = "Anonymous"; # Needs to be set. 
    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    def __init__(self):
        self.get_console_input()
        self.send_console_input_forever()
        
    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()
    
    def connect_to_server(self):
        try:
            self.get_socket()
            self.socket.connect((Server.HOSTNAME, Server.PORT))

            self.get_console_input()
            self.send_console_input_forever()
        except Exception as msg:
            print(msg)
            exit()
    
    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        try:
            while True:
                self.input_text = input("Input: ")
                print(f'Command entered: {self.input_text}')
                if self.input_text == "connect":
                    #create TCP socket and then connect to server
                    #once connected it can use the directory, create room and delete room commands
                    self.connect_to_server()
                elif self.input_text == 'bye':
                    #when closing it should return to main prompt
                    #close the current tcp socket
                    self.close_connection()
                elif "name" in self.input_text:
                    # Sets this client's chatname, working
                    self.NAME = self.input_text.split()[1]
                    print("Your chat name is now: ", self.NAME)
                elif self.input_text == 'getdir':
                    #requests directory list from remote server
                    self.getChatDirectory()
                elif "makeroom" in self.input_text:
                    self.createChatRoom(self.input_text.split()[1],self.input_text.split()[2],self.input_text.split()[3])
                elif "deleteroom" in self.input_text:
                    self.deleteChatRoom(self.input_text.split()[1])
                elif "chat" in self.input_text:
                    #go into chat mode
                    self.enterChat(self.input_text.split()[1])

                if self.input_text != "" :
                    break
                
        except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)

    def send_console_input_forever(self):
            while True:
                try:
                    self.get_console_input()
                    self.connection_receive()
                except (KeyboardInterrupt, EOFError):
                    print()
                    print("Closing server connection ...")
                    self.socket.close()
                    sys.exit(1)

    # used for "getdir" command
    def getChatDirectory(self):
        # Create the packet LIST field.
        list_field = CMD["GETDIR"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet.
        pkt = list_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)
        #recieve the list
        crd_list=self.connection_receive()
        self.CRD_client = json.loads(crd_list)

        self.get_console_input()
        self.send_console_input_forever()

        # used for "makeroom" command
    def createChatRoom(self,chatname,addressNum,portNum):
        # Create the packet LIST field.
        list_field = CMD["MAKEROOM"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        data_field=repr(" "+chatname+" "+addressNum+" "+portNum+" ").encode(MSG_ENCODING)

        # Create the packet.
        pkt = list_field+data_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)
        #recieve the list
        self.connection_receive()

        self.get_console_input()
        self.send_console_input_forever()

        # used for "deleteroom" command
    def deleteChatRoom(self,chatname):
        # Create the packet LIST field.
        list_field = CMD["DELETEROOM"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        room_name_field = str(chatname).encode(MSG_ENCODING)
        # Create the packet.
        pkt = list_field + room_name_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        #recieve the list
        self.connection_receive()
        

        self.get_console_input()
        self.send_console_input_forever()



    #called when recieving text data from server
    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                exit(1)

            print("Received: ", recvd_bytes.decode(MSG_ENCODING))
            return recvd_bytes.decode(MSG_ENCODING)

        except Exception as msg:
            print(msg)
            exit(1)

    
    def close_connection(self):
        # Create the packet LIST field.
        bye_field = CMD["BYE"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet.
        pkt = bye_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)
        print("Closing server connection ... ")
        self.socket.close()
        self.get_console_input()
        #need to check if these 2 lines are needed, after bye it needs to return to input
        exit(1)
        return


    # used for "chat" command
    def enterChat(self,chatname):
        if chatname in self.CRD_client:
            # Grabs the IP and PORT from the CRD on the clientside.
            value = list(self.CRD_client[chatname])
            # print(value[0])
            # print(value[1])

            self.RX_IFACE_ADDRESS="0.0.0.0"
            self.RX_BIND_ADDRESS = "0.0.0.0" #using this cuz i get error in windows

            # Set our PORT and IP to the one retrieved from CRD.
            self.MULTICAST_PORT = value[1]
            self.MULTICAST_ADDRESS = value[0]

            self.MULTICAST_ADDRESS_PORT = (self.MULTICAST_ADDRESS, self.MULTICAST_PORT)
            self.BIND_ADDRESS_PORT = (self.RX_BIND_ADDRESS, self.MULTICAST_PORT)

            #create multicast socket for sending
            self.create_send_socket_multicast()
            self.create_recieve_socket_multicast()

            # #use threads so chat does not block sending and recieving
            multicast_thread_receive = threading.Thread(target = self.receive_forever, args = ())
            multicast_thread_receive.daemon = True
            multicast_thread_receive.start()

            multicast_thread_send = threading.Thread(target = self.send_messages_forever(), args = ())
            multicast_thread_send.daemon = True
            multicast_thread_send.start()

        else:
            print("Error room does not exist")
            return

    ########################################################################
    # CLIENT multicast and chat functions
    ########################################################################

    def create_send_socket_multicast(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.TTL_BYTE)
            # self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Sender.TTL)  # this works fine too
            #self.socket.bind(("192.168.0.14", 0))  # This line may be needed.
            #once created we can ask for the username?
            self.input_text = input("Enter message to chat: ")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input_chat_message(self):
    # In this version we keep prompting the user until a non-blank
    # line is entered.
        while True:
            self.input_text = input("Enter message to chat: ")
            #self.input_text = input("")
            if self.input_text != "":
                break

    # def send_multicast_message(self):
    #     try:
    #         #print("Sending multicast packet (address, port): ", MULTICAST_ADDRESS_PORT)
    #         self.get_console_input_chat_message()
    #         #encode message
    #         send_packet=repr(self.input_text).encode(MSG_ENCODING)
    #         self.socket.sendto(send_packet, self.MULTICAST_ADDRESS_PORT)
    #     except Exception as msg:
    #         print(msg)
    #     except KeyboardInterrupt:
    #         print()
    #     #finally:
    #         #self.socket.close()

    def send_messages_forever(self):
        try:
            while True:
                self.get_console_input_chat_message()
                # Append NAME to each message. Simplest way to implement this.
                MESSAGE_ENCODED=repr(self.NAME +": "+self.input_text).encode(MSG_ENCODING)

                #print("Sending multicast packet (address, port): ", self.MULTICAST_ADDRESS_PORT)
                self.socket.sendto(MESSAGE_ENCODED, self.MULTICAST_ADDRESS_PORT)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        # finally:
        #     self.socket.close()
        #     sys.exit(1)

    def create_recieve_socket_multicast(self):
        try:

            print("USING FOLLOWING MULTICAST ADDRESS: ")
            print(self.MULTICAST_ADDRESS_PORT[0])
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that determines what packets make it to the
            # UDP app.
            self.socket.bind(self.BIND_ADDRESS_PORT)

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################
                        
            multicast_group_bytes = socket.inet_aton(self.MULTICAST_ADDRESS)

            #print("Multicast Group: ", self.MULTICAST_ADDRESS)

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(self.RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            #print("Adding membership (address/interface): ", self.MULTICAST_ADDRESS,"/", self.RX_IFACE_ADDRESS)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                data, address_port = self.socket.recvfrom(self.RECV_SIZE)
                address, port = address_port
                #print("Chat output: ", data.decode('utf-8'), " Address:", address, " Port: ", port)
                print("Chat output: ", data.decode('utf-8'))
                
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################