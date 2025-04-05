import socket

# We connect to a (host,port) tuple
import utils

A_ADDR = ("cc5327.hackerlab.cl", 5312)
B_ADDR = ("cc5327.hackerlab.cl", 5313)
BLOCKSIZE=16
MESSAGE= "a"*6

def decrypt_last_block(previous_block, last_block):
    #evitar que python solo cree otro puntero y cree un espacio de memoria distinto
    manipulated_block=bytearray(previous_block)
    decrypted_last_block = [0] * BLOCKSIZE 
    pt_last_block = [0] * BLOCKSIZE  # To store the decrypted bytes of the last block

    for pos in range(1, BLOCKSIZE + 1):
        pad_value = pos  # The padding value is the position (1 -> 16)

        for i in range(1, pos):
                manipulated_block[-i] = decrypted_last_block[-i] ^ pad_value  
      
        for candidate in range(256):
            print(f"Trying {candidate}")
            # prev block manipulado
            manipulated_block[-pos] = candidate
            
            
            # Reconstruct the manipulated ciphertext and send it to the server
            new_ct = utils.join_blocks([manipulated_block] + [last_block])
            resp_manipulated = utils.send_message(b_input, b_output, utils.bytes_to_hex(new_ct))
            
            # If the server response indicates valid padding, we have the correct byte
            if "json" in resp_manipulated:
                # Decrypt the byte using the padding value
                decrypted_byte = manipulated_block[-pos] ^ pad_value
                decrypted_last_block[-pos] = decrypted_byte  # Store the decrypted byte
                
                # Print the decrypted byte
                print(f"Decrypted byte at position {BLOCKSIZE - pos + 1}: {decrypted_byte}")
                
                # XOR with the corresponding byte in the previous block to recover the plaintext byte
                pt_byte = decrypted_byte ^ previous_block[-pos]
                pt_last_block[- pos] = pt_byte 
                print(f"Recovered plaintext byte: {pt_byte}")
                
                break  # Stop once the correct byte is found for this position

    return pt_last_block

if __name__ == "__main__":
    a_input, a_output = utils.create_socket(A_ADDR)
    b_input, b_output = utils.create_socket(B_ADDR)
    pt_last_block=""
    while len(pt_last_block) != BLOCKSIZE:
        
            # Read a message from standard input
            print("SENDING MESSAGE: ", MESSAGE)
            msg = MESSAGE
            # You need to use encode() method to send a string as bytes.
            print(f"  [Client] \"{msg}\"")
            resp_a = utils.send_message(a_input, a_output, msg)
            print(f"[Server A] \"{resp_a}\"")
            ct=resp_a
          
            resp_b = utils.send_message(b_input, b_output, resp_a)
            print(f"[Server B] \"{resp_b}\"")
            print()

            #ct bytes
            ct_bytes=utils.hex_to_bytes(ct)
            print("Ciphertext Bytes :", ct_bytes)
            #blocks
            blocks=utils.split_blocks(ct_bytes,BLOCKSIZE)
            number_blocks=len(blocks)
            print("Number of Blocks: ", number_blocks)
            #definimos los bloques de interes
            last_block=blocks[-1]
            before_last_block=blocks[-2]
            #decrypt last block
            pt_last_block=decrypt_last_block(before_last_block, last_block)

            print("Last Block bytes: ", pt_last_block)

            pt_last_block_bytes = bytearray(pt_last_block)
            print(f"Plaintext Last Block joined: {pt_last_block_bytes}")
            # Convert the plaintext to a string
            plaintext_last_block = bytes(pt_last_block_bytes).decode("utf-8", errors="ignore")
            print(f"Plaintext Last Block decoded: {plaintext_last_block}")
         


         