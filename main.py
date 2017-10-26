from simon import SimonCipher
import os.path

def perform(data, function):
    frame = bytearray()
    block_bytes_size = block_size // 8
    for x in range(0, (len(data) // block_bytes_size)):
        start = x * block_bytes_size
        end = start + block_bytes_size
        entero = int.from_bytes(data[start: end], byteorder='little')
        frame.extend(function(entero).to_bytes(block_bytes_size, byteorder='little'))
    return frame

def encrypt(data):
    cipher = SimonCipher(key, key_size, block_size, mode, init, counter)
    return perform(data, cipher.encrypt)

def decrypt(data):
    cipher = SimonCipher(key, key_size, block_size, mode, init, counter)
    return perform(data, cipher.decrypt)

def operate_file(from_file, function, to_file):
    with open(from_file, 'rb') as f:
        tof=f.read(2)
        if tof!= b'BM':
            raise ValueError("{}: not a bmp".format(from_file))

        f.seek(2)
        size=int.from_bytes(f.read(4), byteorder='little')
        f.seek(10)
        offset=int.from_bytes(f.read(4), byteorder='little')
        f.seek(offset)
        original_data=f.read(size - offset)
        out = open(to_file, 'wb+')
        f.seek(0)
        out.write(f.read(offset))
        out.write(function(original_data))
        out.close()

__valid_setups = {32: {64: 32},
                  48: {72: 36, 96: 36},
                  64: {96: 42, 128: 44},
                  96: {96: 52, 144: 54},
                  128: {128: 68, 192: 69, 256: 72}}

__valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
init = 0x123456789ABCDEF0
counter = 0x1

while True:
    try:
        block_size = int(input("Tamanio de bloque: "))
        possible_setups = __valid_setups[block_size]
        break
    except (KeyError, ValueError) as e:
        print('Por favor elija uno de los siguientes valores: ', [x for x in __valid_setups.keys()])

while True:
    try:
        key_size = int(input("Tamanio de clave: "))
        possible_setups[key_size]
        break
    except (KeyError, ValueError) as e:
        print('Por favor elija uno de los siguientes valores:', [x for x in possible_setups.keys()])

while True:
    try:
        mode = input("Modo: ")
        __valid_modes.index(mode)
        break
    except ValueError:
        print('Por favor elija uno de los siguientes modos:', __valid_modes)

while True:
    bmp_original = input("Archivo BMP: ")
    if os.path.isfile(bmp_original):
        break
    print('Por favor elija un archivo valido')

bmp_encriptado= './encrypted.bmp'
bmp_desencriptado= './decrypted.bmp'

operate_file(bmp_original, encrypt, bmp_encriptado)
operate_file(bmp_encriptado, decrypt, bmp_desencriptado)