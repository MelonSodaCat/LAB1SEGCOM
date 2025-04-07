import socket
import utils

A_ADDR = ("cc5327.hackerlab.cl", 5312)
B_ADDR = ("cc5327.hackerlab.cl", 5313)
BLOCKSIZE = 16
MESSAGE= "secret"

def find_last_none(lst):
    """Find the last None in the list."""
    for i in range(len(lst)-1, -1, -1):
        if lst[i] is None:
            return i
    return -1

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
                print(f"Decrypted byte at position {BLOCKSIZE - pos + 1}: {decrypted_byte.to_bytes(1, 'big').hex()}")
                
                # XOR with the corresponding byte in the previous block to recover the plaintext byte
                pt_byte = decrypted_byte ^ previous_block[-pos]
                pt_last_block[- pos] = pt_byte 
                print(f"Recovered plaintext byte: {pt_byte.to_bytes(1, 'big').hex()}")
                
                break  # Stop once the correct byte is found for this position

    return pt_last_block


if __name__ == "__main__":
    a_input, a_output = utils.create_socket(A_ADDR)
    b_input, b_output = utils.create_socket(B_ADDR)

    solution = None

    while solution is None or None in solution[1:]: # While first iteration or solution is not complete
        broken = False
        # Read a message from standard input
        print("SENDING MESSAGE: ", MESSAGE)
        msg = MESSAGE
        print(f"  [Client] \"{msg}\"")
        
        resp_a = utils.send_message(a_input, a_output, msg)
        print(f"[Server A] \"{resp_a}\"")
        ct = resp_a
        
        resp_b = utils.send_message(b_input, b_output, resp_a)
        print(f"[Server B] \"{resp_b}\"")
        print()

        # Convert the ciphertext to bytes
        ct_bytes = utils.hex_to_bytes(ct)

        # Split the ciphertext into blocks
        ct_blocks = utils.split_blocks(ct_bytes, BLOCKSIZE)
        number_blocks = len(ct_blocks)
        if solution is None:
            solution = [None]*number_blocks

        last_block_id = find_last_none(solution) # Find the last missing block

        pt = []

        print("Ciphertext Bytes:", ct_bytes)
        print("Number of Blocks:", number_blocks)

        for i in range(last_block_id, 0, -1):
            print("Block no.: ", i)
            # Get the last block and the block before it
            last_block = ct_blocks[i]
            before_last_block = ct_blocks[i-1]

            # Decrypt the last block using the previous block
            pt_last_block = decrypt_last_block(before_last_block, last_block)
            print(pt_last_block)
            if len(pt_last_block) != BLOCKSIZE:
                broken = True
                break
            pt = pt_last_block + pt
            solution[i] = pt_last_block
            print(bytes(pt).decode())
        if broken:
            print("Retrying...")
            continue
        else:
            pt = utils.join_blocks(map(bytearray, solution[1:]))
            print(f"Plaintext: {pt}")
            a = bytearray(pt)
            print(f"Plaintext joined: {a}")
            # Convert the plaintext to a string
            plaintext = bytes(a).decode("utf-8", errors="ignore")
            print(f"Plaintext decoded: {plaintext}")
            break
            #Reconstruccion de la llave 
            #el mensaje de largo 8 genera un padding completo, cortamos los últimos 16 bytes, cortamos los primeros 8, tenemos la llave



      

          

                  
