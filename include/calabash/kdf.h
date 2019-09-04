#ifndef KDF_H
#define KDF_H

#define CB_KDF_SUBKEY_MAX_BYTES 512

void cb_kdf_digest_to_key(const char* digest, char* key);
int cb_kdf_derive_from_key(const char* master_key, unsigned int subkey_id, const char* context, unsigned int subkey_size, char* subkey);

#endif // !KDF_H