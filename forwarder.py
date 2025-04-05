import socket

# We connect to a (host,port) tuple
import utils

A_ADDR = ("cc5327.hackerlab.cl", 5312)
B_ADDR = ("cc5327.hackerlab.cl", 5313)

if __name__ == "__main__":
    a_input, a_output = utils.create_socket(A_ADDR)
    b_input, b_output = utils.create_socket(B_ADDR)
    while True:
        try:
            # Read a message from standard input
            msg = input("send a message: ")
            # You need to use encode() method to send a string as bytes.
            print(f"  [Client] \"{msg}\"")
            resp_a = utils.send_message(a_input, a_output, msg)
            print(f"[Server A] \"{resp_a}\"")
            # print(f"   [Bytes] {utils.hex_to_bytes(resp_a)}")
            resp_b = utils.send_message(b_input, b_output, resp_a)
            print(f"[Server B] \"{resp_b}\"")
            # Wait for a response and disconnect.
        except Exception as e:
            print(e)
            print("Closing...")
            a_input.close()
            break
