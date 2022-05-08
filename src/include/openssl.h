#ifndef __OPENSSL__
#define __OPENSSL__

#include "macro.h"

#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>

typedef enum _keyType{
    SIZE_16,
    SIZE_32
}KEYTYPE;

#endif