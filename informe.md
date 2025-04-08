# Laboratorio 1: Padding Oracle Attack
## Nombres : Antonia G. Calvo y Raimundo Lorca Correa 
## Exploración de inputs 

Tal cual indica el enunciado la encriptación concatena el mensaje y la llave para generar el input que se le entrega al servidor, por lo cual aun cuando se mande un solo byte el texto cifrado.

$ C = Enc(m + k)$

Como ejemplo mostraremos los inputs probados.

```
input1 = "0"

respuesta1 = "b0d89bb1168ad9e162d8490bce0b69c9841c202663dcd4040924c132745d3fef9158cd61e615e7fd4503388248ac19a57609e92709001d9241a98bd55961fbd84cf4eef81a49f868371411179f54693c86b3d5d58b926dde3dfb3890c82e34b79278a5ecc3e5f4ab749885e6d7ab9bcedb0bdd0de8457b8ade60b01d092f2f9f"

input2="0000000000000000"

respuesta2="c9fa53eea2dbd3d270c4d8aad3ed181610cd608d9c9a397c4e9a9e18134d68664e88929afd6453f085fa373d015e923e6f44409681ab2ab56c85dbf9eb125630df3d0e94d1a990d38bb09ffebff531393ac57a87fa19344f2f8d6579ccabb7daf481a95bddc71d75755d6d800378047e"

input3="0000000000000001"
respuesta3="a423bb3155bbaf28ca12d8ea6509cf1448e7ba655372a60d541f505677020c4b8206bf68434c8a5fd1f9d6e044cb8dd63f78d41eda1bae0dd0decc9d04cdb4f71bdb9e766fa329b734c9debd59840cb7122925c6892ede9663ebe235e52e1f5a24e04d8bc7b280ac24d0a39cbfe7299ede68f2a4832d832e8d3c7154ab060395"

```

Notamos que hay un caso especial que nos permite determinar el largo de la llave. Por enunciado se sabe que el largo de bloque es 16 bytes, por lo cual tenemos que identificar un mensaje de largo tal que la función de padding agregue un bloque completo. 
```
inputBeforeWholeBlockPad="00000000"

respuestaBeforeWholeBlockPad="2587c967b688343c4d1ac36732a4d6b05518aafa54d7520c2b92cf02008985538c2728ede50a47a061da9d13dcb19a71b2e7c4e23be4e13b3d49a1705d8196e331da34f47491071a5cfa806f2421a921ab03910dc5c1820e090fb3bae0f6c3f6896690aa22de4ef8e1e497d11451aa59"

inputWholeBlockPad="000000000"

respuestaWholeBlockPad="366aecb33f2999ea5ab542f8b22c944d4448c5a4c28c5aebd20afcecdec9e3a7cc829b54a870798d5de9bf5e4a105f9fa829e15e64dd905593ed8e7fbc3e2200979fc103abcf42b6272772ddb32bcad815b8518b4ae13b45c1b4a098ecfac25c29fba30f7acb2c5b791c43704f6244a4d2788565bafd4f4ab3b676f3cc4afc3d"

```

Como se observa anteriormente el mensaje de largo 9 genera un nuevo bloque de padding. Por lo que al largo del texto cifrado se le puede sustraer el largo del mensaje y el bloque para obtener el largo de la llave.

$LargoTextoCifrado = LargoLlave + LargoMensaje + LargoBloque$

$LargoLlave = LargoTextoCifrado - (LargoMensaje + LargoBloque)$

$LargoLlave = 128 - (9 + 16) = 103$

Esto debido a que dos caracteres hexadecimales corresponden a un byte, por lo cual su largo es divido en 2 para realizar la formula. El largo de la llave corresponde a 103 bytes. 


## Código de reenvio de respuesta a A en B 
Usando el archivo `forwarder.py` se observa que el servidor B desencripta correctamente y no entrega la llave.


```python
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
            
            msg = input("send a message: ")
           
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

```

De manera exploratoria podemos ver que si interceptamos la comunicación y manipulamos el ciphertext que le llega al servidor B, podemos obtener tres escenarios.

El primero es donde no manipulamos nada, obtenemos el texto plano original.

El segundo es recibir un error de padding si manipulamos los bits, el cual nos indica que el formateo es incorrecto. 

El tercero es el caso de error de json, en donde logramos desencriptar. Para el ataque es este en el que nos vamos a centrar.

## En contexto generico: Conocer el tamaño del bloque

Para descubrir el tamaño del bloque se pueden enviar mensajes de largos crececientes hasta que el mensaje cifrado aumente un bloque completo, lo que significa que se completo un bloque y se padeo uno adicional, por lo cual se restan los tamaños del texto cifrado del penultimo y ultimo mensaje para obtener el largo del bloque.

## Descifrando el último bit 

Para esto nos colocaremos entre la comunicación del servidor A y el servidor B para utilizar el ciphertext que nos entrega A para manipular el texto cifrado. Esto lo vemos en el archivo `last_byte.py`, especificamente en el siguiente extracto.

```python
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
        new_ct=utils.join_blocks(blocks[:-2]+[before_last_block]+[last_block])
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
        print("Last byte: ", pt_byte)

```

Con esto obtenemos que el último byte es `3` esto dado que nuestro mensaje es `aaaaaa` y obteniene un padding de tres debido a la presencia de la llave.


## Descifrando un bloque completo

El proceso anterior luego se extiende para un bloque completo en el archivo `last_block.py`, del cual vemos la sección principal en el siguiente extracto.

```python
def decrypt_last_block(previous_block, last_block):
    #evitar que python solo cree otro puntero y cree un espacio de memoria distinto
    manipulated_block=bytearray(previous_block)
    decrypted_last_block = [0] * BLOCKSIZE 
    pt_last_block = [0] * BLOCKSIZE  # To store the decrypted bytes of the last block

    for pos in range(1, BLOCKSIZE + 1):
        pad_value = pos  # The padding value is the position (1 -> 16)

        #setteamos el padding de los bytes ya descubiertos
        for i in range(1, pos):
                manipulated_block[-i] = decrypted_last_block[-i] ^ pad_value  
      
        for candidate in range(256):
            # prev block manipulado
            manipulated_block[-pos] = candidate
            
            
            # Reconstruct manipulated ciphertext
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


```

Recordando que para iterar sobre el siguiente byte, los anteriores deben tener el valor correspondiente al padding objetivo de esa iteración, por ejemplo, para la segunda iteración el primer byte desencriptado debe tener valor de `2` antes de buscar el byte objetivo.

Aquí retornamos los bytes del último bloque. 

```

Last Block:  [99, 52, 97, 49, 54, 51, 57, 48, 48, 50, 48, 34, 125, 3, 3, 3]
Plaintext Last Block joined: bytearray(b'c4a16390020"}\x03\x03\x03')
Plaintext Las Block decoded: c4a16390020"}



```



## Obtención de key

Para obtener la llave es necesario desencriptar el texto completo, lo cual realizamos en los archivos `decryption.py`y `decryption-opt.py`.

A continuación un extracto de la sección más relevante para obtener la llave en `decryption.py`

```python
# Convert the ciphertext to bytes
        ct_bytes = utils.hex_to_bytes(ct)

        # Split the ciphertext into blocks
        ct_blocks = utils.split_blocks(ct_bytes, BLOCKSIZE)
        number_blocks=len(ct_blocks)

        pt=[]

        print("Ciphertext Bytes:", ct_bytes)
        print("Number of Blocks:", number_blocks)


        for i in range(number_blocks-1, 0, -1):
            print("BLOCK: ", i)
        # Get the last block and the block before it
            last_block = ct_blocks[i]
            before_last_block = ct_blocks[i-1]

            # Decrypt the last block using the previous block
            pt_last_block = decrypt_last_block(before_last_block, last_block)
            print(pt_last_block)
            pt=  pt_last_block + pt
            print("PT ARRAY: " ,pt)
     
        print("Plaintext: ", pt)
        a=bytes(pt)
        print("Plaintext joined: {}".format(a))
        

```



Luego de obtenido el plaintext de todos los bloques procedemos a juntarlos para decodificar el mensaje.


```

pt_bytes = [123, 34, 110, 97, 109, 101, 34, 58, 34, 97, 97, 97, 97, 97, 97, 34, 44, 34, 115, 101, 99, 114, 101, 116, 34, 58, 34, 56, 51, 99, 56, 48, 52, 98, 102, 55, 52, 102, 48, 52, 98, 56, 52, 49, 98, 57, 99, 49, 56, 54, 51, 52, 50, 99, 54, 50, 97, 49, 55, 57, 55, 99, 100, 56, 55, 98, 49, 102, 101, 54, 99, 101, 55, 98, 102, 53, 52, 100, 51, 50, 99, 52, 97, 49, 54, 51, 57, 48, 48, 50, 48, 34, 125, 3, 3, 3]


pt = b'{"name":"aaaaaa","secret":"83c804bf74f04b841b9c186342c62a1797cd87b1fe6ce7bf54d32c4a16390020"}\x03\x03\x03'
```

Aquí podemos observar que tenemos nuestro mensaje, en `name`, y la llave, en `secret`.

A continuación la llave

```

llave = 83c804bf74f04b841b9c186342c62a1797cd87b1fe6ce7bf54d32c4a16390020

```


