#-----------------------------------
# Yunhu Xiang
# E00327100
# Project: Decrypt Simple GPG File
# Professor: Joshua Tallman
#-----------------------------------

import hashlib
import gpg_consts
import getpass
import DES_core as dcore
import DES as des
_packet_start_mask   = 0x80 # 0b 1000 0000
_packet_version_mask = 0x40 # 0b 0100 0000
_packet_new_tag_mask = 0x3f # 0b 0011 1111
_packet_old_tag_mask = 0x3c # 0b 0011 1100
_packet_old_len_mask = 0x03 # 0b 0000 0011


def process_gpg_packet(raw_data):
    header_byte = raw_data[0]
    # Use 0x80 tag to verify if it is a valid header
    if (header_byte & _packet_start_mask) == 0:
        msg = "Invalid GPG packet '{0}'(0x80 bit is clear)" 
        msg = msg.format(raw_data[0:8])
        raise ValueError(msg)

    # Extract the packet version to see if this is the new or old format
    if (header_byte & _packet_version_mask) == 0:
        version = "old"
        type_tag = (header_byte & _packet_old_tag_mask) >> 2
        gpg_packet_len_type = (header_byte & _packet_old_len_mask)

        #Get the length of this packet
        if gpg_packet_len_type == 0:
            data_length = raw_data[1]
            data_offset = 2
        elif gpg_packet_len_type == 1:
            data_length = int.from_bytes(raw_data[1:3],"big")
            data_offset = 3
        elif gpg_packet_len_type == 2:
            data_length = int.from_bytes(raw_data[1:5],"big")
            data_offset = 5
        elif gpg_packet_len_type == 3:
            msg = "packet has indeterminate length"
            raise ValueError(msg)
    else:
        version = "new"
        type_tag = (header_byte & _packet_new_tag_mask)

        #Get the length of this packet
        octet1 = int(raw_data[1])
        if octet1 < 192:
            data_length = octet1
            data_offset = 2
        elif octet1 < 224:
            octet2 = int(raw_data[2])
            data_length = ((octet1 - 192) << 8) + octet2 + 192
            data_offset = 3
        elif octet1 == 255:
            data_length = int.from_bytes(raw_data[2:6],"big")
            data_offset = 5
        else:
            msg = "GPG packet has invalid size (octet1 = {0})"
            msg = msg.format(octet1)
            raise ValueError(msg)
    
    header_byte = "Packet uses {0} PGP format (tag type {1}/{2} octets)"
    print(header_byte.format(version, type_tag, data_length))

    start = data_offset
    finish = data_offset + data_length
    gpg_packet = {
        'type_tag' : type_tag,
        'data_offset':data_offset,
        'data_length':data_length,
        'data_buffer':raw_data[start:finish],
    }

    return gpg_packet

S2K_SIMPLE = 0

def _symmetric_key_session_key_packet(raw_data, password):
    #parse packets into packet info
    version = raw_data[0]
    enc_type = raw_data[1]
    s2k_mode = raw_data[2]
    s2k_hash = raw_data[3]

    if s2k_mode != S2K_SIMPLE:
        msg = "Error: S2K mode '{0}' is unknown or not implemented"
        raise ValueError(msg.format(s2k_mode))

    if s2k_hash != gpg_consts._hash_algorithms.index("MD5"):
        msg = "Error: invalid hash algorithm '{0}' ; see 'gpg_consts._hash_algorithms'"
        raise ValueError(msg.format(s2k_hash))

    if enc_type != gpg_consts._sym_algorithms.index("Triple DES"):
        msg = "Error: invalid cryptopraphic algorithm '{0}'；see 'gpg_consts._sys_algorithms'"
        raise ValueError(msg.format(enc_type))
    #convert passphrase into session key
    skey = _S2K_S_key(password)
    
    print("Symmetric-Key Encrypted Session Key")
    print(" Simple S2K Mode")
    print(" Packet Version   : {0}".format(version))
    print(" Cipher Algorithm : {0}".format(gpg_consts._sym_algorithms[enc_type]))
    print(" Hash Algorithm   : {0}".format(gpg_consts._hash_algorithms[s2k_hash]))
    print(" Session Key      : {0}".format(skey.hex()))
    return skey

def _S2K_S_key(password):
    result = b''
    key_size = 24
    used_count = 0
    pass_count = 0
    while used_count < key_size:
        
        buffer = b"\x00" * pass_count + password
        md5obj = hashlib.md5(buffer)
        mdhash = md5obj.digest()

        if len(mdhash) > key_size - used_count:
            byte_count = key_size - used_count
        else:
            byte_count = len(mdhash)

        result += mdhash [:byte_count]
        used_count += byte_count
        pass_count += 1

    return result    


def _decrypt_with_3des(raw_data,key):
    #using the 3DES decrypt method to decrypt raw data
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    enc_data = raw_data[1:]
    b1 = des.tddecrypt(enc_data[0:8],key,"OFB",iv)
    dec_data = b1
    count = 8
    while(count<=len(enc_data)):
        block = des.tddecrypt(enc_data[count:count+8],key,"OFB",enc_data[count-8:count])
        dec_data += block
        count += 8
    return dec_data



##########################################################################
password = "test"
password = password.encode('utf-8')

with open("test.txt.gpg","rb") as f:
    gpg_file_contents = f.read()
next_rec = 0
# Parse first packet for GPG session key

gpg_packet = process_gpg_packet(gpg_file_contents[next_rec:])
raw_data = gpg_packet['data_buffer']
type_tag = gpg_packet['type_tag']
next_rec = gpg_packet['data_offset'] + gpg_packet['data_length']

if type_tag != gpg_consts._ptag_symkey_enc_session:
    tag = "Symmetric-Key Encrypted Session Key Packet. (tag 3)"
    raise ValueError("Expected {0}, found tag {1}".format(tag,type_tag))

enc_skey = _symmetric_key_session_key_packet(raw_data,password)

# Parse second packet for GPG encrypted data

gpg_packet = process_gpg_packet(gpg_file_contents[next_rec:])
raw_data = gpg_packet['data_buffer']
type_tag = gpg_packet['type_tag']
next_rec = gpg_packet['data_offset'] + gpg_packet['data_length']

if type_tag != gpg_consts._ptag_sym_enc_int_data:
    tag = "Symmetric Encrypted and Intefrity Protected Data packet(tag 18)"
    raise ValueError("Expected {0}, found tag{1}".format(tag, type_tag))

decrypted = _decrypt_with_3des(raw_data,enc_skey)
f = open("decrypted_data.txt","wb")
f.write(decrypted)
f.close()
print(decrypted.hex())





