import socket

# We connect to a (host,port) tuple
import utils

A_ADDR = ("cc5327.hackerlab.cl", 5312)
B_ADDR = ("cc5327.hackerlab.cl", 5313)
BLOCKSIZE=16
MESSAGE= "a"*6

if __name__ == "__main__":
    a_input, a_output = utils.create_socket(A_ADDR)
    b_input, b_output = utils.create_socket(B_ADDR)
    while True:
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


            ct_bytes=utils.hex_to_bytes(ct)
            ct_blocks=utils.split_blocks(ct_bytes, BLOCKSIZE)

            print("Ciphertext Bytes :", ct_bytes)

            blocks=utils.split_blocks(ct_bytes,BLOCKSIZE)
            number_blocks=len(blocks)
            print("Number of Blocks: ", number_blocks)
            #definimos los bloques de interes
            last_block=blocks[-1]
            before_last_block=blocks[-2]

            for candidate in range(256):
                  #asignamos el bit al candidato              
                  before_last_block[-1]=candidate
                  #rearmamos el ct
                  new_ct=utils.join_blocks([before_last_block]+[last_block])
                  #lo enviamos
                  resp_manipulated = utils.send_message(b_input, b_output, utils.bytes_to_hex(new_ct))
                  #si error de json ganamos
                  if "json" in resp_manipulated:
                    print(f"Found {candidate}")
                    print(f"[Server B Manipulated] \"{resp_manipulated}\"")
                    #dec =c_i-1' xor padd
                    decrypted_byte = before_last_block[-1] ^ 0x01 
                    print("Decrypted byte: ", decrypted_byte)
                    #pt =dec(ci) xor c_i-1
                    pt_byte= decrypted_byte ^ ct_blocks[-2][-1]
                    #Obtenemos el último byte
                    print("Plaintext Last byte: ", pt_byte)

                
                   
                  
                  
          




            



            

     





            
