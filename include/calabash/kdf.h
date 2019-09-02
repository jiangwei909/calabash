#ifndef KDF_H
#define KDF_H

int cb_kdf_derive_from_key(const char* master_key, unsigned int subkey_id, const char* context, unsigned int subkey_size, char* subkey);

#endif // !KDF_H