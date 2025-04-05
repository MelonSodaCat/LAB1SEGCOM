import socket

# We connect to a (host,port) tuple
import utils

CONNECTION_ADDR = ("cc5327.hackerlab.cl", 5312)

if __name__ == "__main__":
    sock_input, sock_output = utils.create_socket(CONNECTION_ADDR)
    while True:
        try:
            # Read a message from standard input
            response = input("send a message: ")
            # You need to use encode() method to send a string as bytes.
            print("[Client] \"{}\"".format(response))
            resp = utils.send_message(sock_input, sock_output, response)
            print("[Server] \"{}\"".format(resp))
            print("BYTES:", utils.bytes_to_hex(resp))
            # Wait for a response and disconnect.
        except Exception as e:
            print(e)
            print("Closing...")
            sock_input.close()
            break
