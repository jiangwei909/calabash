var ffi = require('ffi');
var ref = require("ref");

var intPtr = ref.refType('int');
var libcalabash = ffi.Library('./libcalabash', 
//    {'des_ecb_encrypt': 
//        ['int', ['string', 'int', 'string', 'int', 'pointer']],
//    {'bin_to_hex': 
//        ['int', ['string', 'int', 'pointer', intPtr]],
   { 'cb_sm2_keypair': ['int', ['pointer', 'pointer']]
    });

var key = "12345678";
var plain = "12345678";
var cipher = Buffer.alloc(10);;

//#var cipher_len = libcalabash.des_ecb_encrypt(key, key.length, plain, plain.length, cipher);
//#console.log(`cipher_len=${cipher_len} cipher=${cipher}`)

var cipher_hex = Buffer.alloc(16);
var cipher_hex_len_ref = ref.alloc('int');

//var hex_len = libcalabash.bin_to_hex(cipher, cipher_len, cipher_hex, cipher_hex_len_ref);
//var cipher_hex_len = cipher_hex_len_ref.deref();
//console.log(`cipher_hex_len=${cipher_hex_len} cipher_hex=${cipher_hex}`)

let pvkLenPtr = ref.alloc('int')
let pukLenPtr = ref.alloc('int')
let pvk = Buffer.alloc(64)
let puk = Buffer.alloc(128)

//let result = libcalabash.sm2_generate_keypair(pvk, pvkLenPtr, puk, pukLenPtr)
let result = libcalabash.cb_sm2_keypair(puk, pvk)
console.log(`result=${result}`)

const crypto = require('crypto')

let curves = crypto.getCurves()

console.log(`curves=${curves}`)

