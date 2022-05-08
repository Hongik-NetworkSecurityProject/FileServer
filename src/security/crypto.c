#include "../include/crypto.h"

int generateSymmetricKey(uint8_t *symmetricKey){
    uint8_t randomKey[SYM_KEY_SIZE];
    RAND_bytes(randomKey, sizeof(randomKey));
    rc4(randomKey, symmetricKey, SIZE_32);
    return TRUE;
}

void encryptSymmetricKey(uint8_t* plainText, uint8_t* cipher, int SIZE, uint8_t* symmetricKey, uint8_t* initialVector){
    AES_KEY key;
    AES_set_decrypt_key(symmetricKey, SYM_KEY_BIT, &key);
    AES_cbc_encrypt(plainText, cipher, SIZE, &key, initialVector, AES_ENCRYPT);
}

void decryptSymmetricKey(uint8_t* cipher, uint8_t* plainText, int SIZE, uint8_t* symmetricKey, uint8_t* initialVector){
    AES_KEY key;
    AES_set_decrypt_key(symmetricKey, SYM_KEY_BIT, &key);
    AES_cbc_encrypt(cipher, plainText, SIZE, &key, initialVector, AES_DECRYPT);
}

RSA* rsaFromPublicKey(const char * publicKey){
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(publicKey, strlen(publicKey));
    PEM_read_bio_RSAPublicKey(bio, &rsa, 0, 0);
    BIO_free_all(bio);

    return rsa;
}

void rc4(unsigned char *inputKey,unsigned char *outputKey,int keyType){
    RC4_KEY *rc4Key = (RC4_KEY*)malloc(sizeof(RC4_KEY));
    switch(keyType){
        case SIZE_16:
            RC4_set_key(rc4Key, CHALLENGE_SIZE, inputKey);
            RC4(rc4Key, CHALLENGE_SIZE, inputKey, outputKey);
            break;
        case SIZE_32:
            RC4_set_key(rc4Key, SYM_KEY_SIZE, inputKey);
            RC4(rc4Key, SYM_KEY_SIZE, inputKey, outputKey);
            break;
    }
    free(rc4Key);
}