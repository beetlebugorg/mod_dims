#ifndef _ENCRYPTION_H_
#define _ENCRYPTION_H

int aes_errors(const char *message, size_t length, void *u);
char *aes_128_decrypt(request_rec *r, unsigned char *key, unsigned char *encrypted_text, int encrypted_length);
char *aes_128_gcm_decrypt(request_rec *r, unsigned char *key, unsigned char *base64_encrypted_text);

#endif
