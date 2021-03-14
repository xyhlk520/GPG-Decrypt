_S_BOXES = [
    [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
     [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
     [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
     [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
     [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
     [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
     [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
     [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
     [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
     [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
     [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
     [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
     [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    [[ 2, 12,  4,  1,  7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11,  2, 12,  4,  7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [ 4,  2,  1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11,  8, 12,  7,  1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
     [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
     [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
     [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
     [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
     [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
     [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
     [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
     [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
     [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ]
]

# 64-bit to 56-bit permutation on the key
_KEY_PERMUTATION1 = [56, 48, 40, 32, 24, 16,  8,  0, 
                    57, 49, 41, 33, 25, 17,  9,  1,
                    58, 50, 42, 34, 26, 18, 10,  2, 
                    59, 51, 43, 35, 62, 54, 46, 38, 
                    30, 22, 14,  6, 61, 53, 45, 37,
                    29, 21, 13,  5, 60, 52, 44, 36,
                    28, 20, 12,  4, 27, 19, 11,  3]

# 56-bit to 48-bit permutation on the key
_KEY_PERMUTATION2 = [13, 16, 10, 23,  0,  4,  2, 27,
                    14,  5, 20,  9, 22, 18, 11,  3, 
                    25,  7, 15,  6, 26, 19, 12,  1,
                    40, 51, 30, 36, 46, 54, 29, 39, 
                    50, 44, 32, 47, 43, 48, 38, 55, 
                    33, 52, 45, 41, 49, 35, 28, 31]

# Matrix that determines the shift for each round of keys
_KEY_SHIFT = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 32-bit to 48-bit
_EXPAND = [31,  0,  1,  2,  3,  4,  3,  4,
            5,  6,  7,  8,  7,  8,  9, 10,
           11, 12, 11, 12, 13, 14, 15, 16,
           15, 16, 17, 18, 19, 20, 19, 20,
           21, 22, 23, 24, 23, 24, 25, 26,
           27, 28, 27, 28, 29, 30, 31,  0]

# 32-bit permutation after S-BOX substitution
_CONTRACT = [15,  6, 19, 20, 28, 11, 27, 16,
              0, 14, 22, 25,  4, 17, 30,  9,
              1,  7, 23, 13, 31, 26,  2,  8,
             18, 12, 29,  5, 21, 10,  3, 24]

# Initial permutation on incoming block 
_INIT_PERMUTATION = [57, 49, 41, 33, 25, 17,  9, 1,
                     59, 51, 43, 35, 27, 19, 11, 3,
                     61, 53, 45, 37, 29, 21, 13, 5,
                     63, 55, 47, 39, 31, 23, 15, 7,
                     56, 48, 40, 32, 24, 16,  8, 0,
                     58, 50, 42, 34, 26, 18, 10, 2,
                     60, 52, 44, 36, 28, 20, 12, 4,
                     62, 54, 46, 38, 30, 22, 14, 6]

# Inverse of _INITIAL_PERMUTATION
_FINAL_PERMUTATION = [39,  7, 47, 15, 55, 23, 63, 31,
                      38,  6, 46, 14, 54, 22, 62, 30,
                      37,  5, 45, 13, 53, 21, 61, 29,
                      36,  4, 44, 12, 52, 20, 60, 28,
                      35,  3, 43, 11, 51, 19, 59, 27,
                      34,  2, 42, 10, 50, 18, 58, 26,
                      33,  1, 41,  9, 49, 17, 57, 25,
                      32,  0, 40,  8, 48, 16, 56, 24]

_SB_PERMUTATION = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

def _add_padding(msg):
    bit_cnt = 8 - (len(msg) %8)
    padding = bit_cnt * chr(bit_cnt)
    msg += padding.encode("utf-8")
    return msg

def _bytes_to_bit_array(byte_string):
    bit_count = len(byte_string) * 8
    result = [0] * bit_count
    idx = 0
    for byte in byte_string:
        for bit_pos in range(7,-1,-1):
            if byte & (1 << bit_pos) > 0:
                result[idx] = 1
            idx +=1    
    return result

def _remove_padding(message):
    bit_cnt = message[-1]
    return message[:-bit_cnt]

def _bit_array_to_bytes(bit_array):
    result = []
    byte = 0
    for pos in range(len(bit_array)):
        byte += bit_array[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            result += [byte]
            byte = 0
    return bytes(result)

def _permute(block,table):
    return [block[x] for x in table]

def _generate_subkeys(key):
    subkeys = []
    keybits = _bytes_to_bit_array(key)
    k = _permute(keybits,_KEY_PERMUTATION1)
    L = k[:28]
    R = k[28:]
    for i in range(16):
        L, R = _shift(L, R, _KEY_SHIFT[i])
        k_i = _permute(L + R, _KEY_PERMUTATION2)
        subkeys.append(k_i)
    return subkeys

def _shift(L_values, R_values, n):
    return L_values[n:] + L_values[:n], R_values[n:] + R_values[:n]

def _hex_print(block):
    s = [str(i) for i in block]
    b = int("".join(s),2)
    print(hex(b)[2:].zfill(16))
    return

def _nsplit(arr,split_size):
    if len(arr) % split_size != 0:
        msg = "Error: list of length {0} does not divide into {1}-sized splits"
        msg = msg.format(len(arr), split_size)
        raise ValueError(msg)
    for n in range(0, len(arr), split_size):
        yield arr[n:n+split_size]

def _split_encryption_keys(keys):
    keys = _bytes_to_bit_array(keys)
    key1 = keys[:64]
    key2 = keys[64:128]
    key3 = keys[128:192]
    key1 = _bit_array_to_bytes(key1)
    key2 = _bit_array_to_bytes(key2)
    key3 = _bit_array_to_bytes(key3)
    return key1,key2,key3
    
def encrypt(plaintext,key):
    subkeys = _generate_subkeys(key)
    pt = _add_padding(plaintext)
    pt = _bytes_to_bit_array(pt)
    ct = []
    for block in _nsplit(pt,64):
        ct += _encrypt_block(block, subkeys)
    ct = _bit_array_to_bytes(ct)
    return ct

def decrypt(ciphertext,key):
    subkeys = _generate_subkeys(key)
    subkeys = list(reversed(subkeys))
    ct = _bytes_to_bit_array(ct)
    pt = []
    for block in _nsplit(pt,64):
        pt += _encrypt_block(block, subkeys)
    pt = _bit_array_to_bytes(pt)
    pt = _remove_padding(pt)
    return pt


def _xor(x,y):
    return [xn^yn for xn, yn in zip(x,y)]

def _function(R, subkey):
    temp = _permute(R, _EXPAND)
    temp = _xor(temp, subkey)
    temp = _substitution(temp)
    temp = _permute(temp, _SB_PERMUTATION)
    return temp
    
def _substitution(bit_array):
    result = []
    for i,b in enumerate(_nsplit(bit_array, 6)):
        ends = [str(b[0]), str(b[-1])]
        row = int(''.join(ends), 2)
        mids = [str(b[1]), str(b[2]), str(b[3]), str(b[4])]
        col = int(''.join(mids), 2)
        sval = _S_BOXES[i][row][col]
        bstr = bin(sval)[2:].zfill(4)
        result += [int(x) for x in bstr]
    return result

    
def  _encrypt_block(block, subkeys):
    block = _permute(block, _INIT_PERMUTATION)
    L = block[:32]
    R = block[32:]
    for i in range(16):
        T = _xor(L, _function(R, subkeys[i]))
        L = R
        R = T
    
    block = _permute(R + L, _FINAL_PERMUTATION)
    return block