#include <unistd.h>

#include "crypto.h"
#include "init.h"
#include "macro.h"
#include "time.h"


void decryptToken(uint8_t* token, uint8_t* symmetricKeyAuthenticationServerFileServer, uint8_t* initialVectorUse, uint8_t* id, uint8_t* timestamp, uint8_t* symmetricKey2);
void makeRequestFileHash(uint8_t* requestFileHash, uint8_t* symmetricKey2, uint8_t* id);

int tracefile(uint8_t* fileName,uint8_t** file, uint8_t** encryptedFile, long* fileSize, long* encryptedFileSize);
int verifyToken(uint8_t* symmetricKey2, uint8_t* id, uint8_t* requestFileHash);
