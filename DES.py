import DES_core as _core

def encrypt(data,key,mode="ECB",iv=None):
    
    if mode == "CBC" or mode == "OFB":
        iv = _core._bytes_to_bit_array(iv)
    if mode == "ECB" or mode == "CBC":
        data = _core._add_padding(data)
        
    subkeys = _core._generate_subkeys(key)
    data = _core._bytes_to_bit_array(data)
    
    result = []

    for pt_block in _core._nsplit(data, 64):
        if mode == "ECB":
            ct_block = _core._encrypt_block(pt_block, subkeys)
            result += ct_block
        elif mode == "CBC":
            ct_block = _core._xor(pt_block.iv)
            ct_block = _core._encrypt_block(ct_block,subkeys)
            iv = ct_block
            result += ct_block
        elif mode =="OFB":
            iv = _core._crypt_block(iv,subkeys)
            ct_block = _core._xor(pt_block.iv)
            result += ct_block
        else:
            raise ValueError("The mode '{}' is invalid".format(mode))
    result = _core._bit_array_to_bytes(result)
    return result

def decrypt(data,key,mode="ECB",iv=None):
    subkeys = _core._generate_subkeys(key)
    if mode == "ECB" or mode == "CBC":
        subkeys = list(reversed(subkeys))
    if mode == "CBC" or mode == "OFB":
        iv = _core._bytes_to_bit_array(iv)
    data = _core._bytes_to_bit_array(data)
    result = []
    for ct_block in _core._nsplit(data,64):
        
        if mode == "ECB":
            pt_block = _core._encrypt_block(ct_block, subkeys)
            result += pt_block
        elif mode == "CBC":
            pt_block = _core._encrypt_block(ct_block, subkeys)
            pt_block = _core._xor(pt_block, iv)
            iv = ct_block
            result += pt_block
        elif mode == "OFB":
            iv = _core._encrypt_block(iv,subkeys)
            pt_block = _core._xor(ct_block, iv)
            result += pt_block
        else:
            raise ValueError("The mode '{}' is invalid".format(mode))
        
    result = _core._bit_array_to_bytes(result)
    if mode == "ECB" or mode == "CBC":
         result = _core._remove_padding(result)
    return result

def tdencrypt(data,key,mode="ECB",iv=None):
    
    if mode == "CBC" or mode == "OFB":
        iv = _core._bytes_to_bit_array(iv)
    if mode == "ECB" or mode == "CBC":
        data = _core._add_padding(data)
        
    subkeys = _core._generate_subkeys(key)
    data = _core._bytes_to_bit_array(data)
    
    result = []

    for pt_block in _core._nsplit(data, 64):
        if mode == "ECB":
            ct_block = _core._encrypt_block(pt_block, subkeys)
            result += ct_block
        elif mode == "CBC":
            ct_block = _core._xor(pt_block.iv)
            ct_block = _core._encrypt_block(ct_block,subkeys)
            iv = ct_block
            result += ct_block
        elif mode =="OFB":
            iv = _core._crypt_block(iv,subkeys)
            ct_block = _core._xor(pt_block.iv)
            result += ct_block
        else:
            raise ValueError("The mode '{}' is invalid".format(mode))
    result = _core._bit_array_to_bytes(result)
    return result

def tddecrypt(data,key,mode="ECB",iv=None):
    key1,key2,key3 = _core._split_encryption_keys(key)
    subkeys1 = _core._generate_subkeys(key1)
    subkeys2 = _core._generate_subkeys(key2)
    subkeys3 = _core._generate_subkeys(key3)
    if mode == "OFB":
        subkeys2 = list(reversed(subkeys2))
    else:
        subkeys1 = list(reversed(subkeys1))
        subkeys3 = list(reversed(subkeys3))
        
    if mode == "CBC" or mode == "OFB":
        iv = _core._bytes_to_bit_array(iv)
    data = _core._bytes_to_bit_array(data)
    result = []
    for ct_block in _core._nsplit(data,64):
        
        if mode == "ECB":
            pt_block = _core._encrypt_block(ct_block, subkeys3)
            pt_block = _core._encrypt_block(pt_block, subkeys2)
            pt_block = _core._encrypt_block(pt_block, subkeys1)
            result += pt_block
        elif mode == "CBC":
            pt_block = _core._encrypt_block(ct_block, subkeys3)
            pt_block = _core._encrypt_block(pt_block, subkeys2)
            pt_block = _core._encrypt_block(pt_block, subkeys1)
            pt_block = _core._xor(pt_block, iv)
            iv = ct_block
            result += pt_block
        elif mode == "OFB":
            iv = _core._encrypt_block(iv,subkeys1)
            iv = _core._encrypt_block(iv,subkeys2)
            iv = _core._encrypt_block(iv,subkeys3)
            pt_block = _core._xor(ct_block, iv)
            result += pt_block
        else:
            raise ValueError("The mode '{}' is invalid".format(mode))
        
    result = _core._bit_array_to_bytes(result)
    if mode == "ECB" or mode == "CBC":
         result = _core._remove_padding(result)
    return result