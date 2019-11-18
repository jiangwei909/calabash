# -*- encoding: utf-8 -*-

import ctypes
import binascii

cso = ctypes.CDLL("./libcalabash.so")

key = "12345678"
key_len = 8
plain_len = 16
plain = ctypes.create_string_buffer(binascii.a2b_hex("00000000123456780000000012345678"), plain_len)

cipher = ctypes.create_string_buffer(plain_len)

cipher_len = cso.des_ecb_encrypt(key, key_len, plain, plain_len, cipher)
print("cipher len=%d,%s" % (cipher_len, binascii.b2a_hex(cipher.raw)))

pvklen = ctypes.c_int(0)
puklen = ctypes.c_int(0)

pvk = ctypes.create_string_buffer(32)
puk = ctypes.create_string_buffer(65)

#ret = cso.sm2_generate_keypair(pvk, ctypes.byref(pvklen), puk, ctypes.byref(puklen))
ret = cso.cb_sm2_keypair(pvk, puk)
#print("ret=%d private key length=%d, public key length=%d" % (ret, pvklen.value, puklen.value))
print("ret=%d private key = %s\n public key = %s" % (ret, binascii.b2a_hex(pvk), binascii.b2a_hex(puk)))

