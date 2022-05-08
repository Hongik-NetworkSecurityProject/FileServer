#include "../include/phase.h"

void phase0PreparationServer(int *fileSock,uint8_t* symmetricKeyAuthenticationServerFileServer, RSA* authenticationServerPublicRSAKey){
    uint8_t *publicKey;
    int authenticationserverPublicKeySize;

    uint8_t symmetricKeyAuthenticationServerFileServerEncrypted[RSA_ENC_SIZE];

    read(*fileSock, &authenticationserverPublicKeySize, sizeof(int));
    publicKey = malloc(sizeof(uint8_t) * authenticationserverPublicKeySize);
    read(*fileSock, publicKey, authenticationserverPublicKeySize);
    puts("Phase 0 :: AS_public key received.");

    printf("public key : %s\n", publicKey);

    puts("Phase 0 :: Make symmetric key.");
    authenticationServerPublicRSAKey = rsaFromPublicKey(publicKey);
    generateSymmetricKey(symmetricKeyAuthenticationServerFileServer);
    printSymmetricKey(symmetricKeyAuthenticationServerFileServer);

    puts("Phase 0 :: Encrypt symmetric key.");
    RSA_public_encrypt(SYM_KEY_SIZE, symmetricKeyAuthenticationServerFileServer, symmetricKeyAuthenticationServerFileServerEncrypted, authenticationServerPublicRSAKey, RSA_PKCS1_PADDING);
    printEncryptedSymmetricKey(symmetricKeyAuthenticationServerFileServerEncrypted);

    write(*fileSock,symmetricKeyAuthenticationServerFileServerEncrypted,RSA_ENC_SIZE);
    puts("Phase 0 :: Encrypted symmetric key sended.");

    close(*fileSock);
    free(publicKey);
    printAuthenticationServerDisconnection();
}
void phase1VerifyToken(int* clientSock, uint8_t* symmetricKeyAuthenticationServerFileServer, uint8_t* symmetricKey2, uint8_t* initialVector,uint8_t** fileName){
    uint8_t token[TOKEN_SIZE];
    uint8_t requestFileHash[HASH_SIZE];
    uint8_t hash[HASH_SIZE];
    uint8_t initialVectorUse[AES_BLOCK_SIZE];

    uint8_t timestamp[TIMESTAMP_SIZE];
    uint8_t id[ID_SIZE];
    int fileNameSize;

    read(*clientSock, token, TOKEN_SIZE);
    puts("Phase 1 :: Token received.");
    printToken(token, CIPHER);

    read(*clientSock, initialVector, AES_BLOCK_SIZE);
    puts("Phase 1 :: IV received.");
    printInitialVector(initialVector);

    read(*clientSock, requestFileHash, HASH_SIZE);
    puts("Phase 1 :: File request message received.");
    printHashFile(requestFileHash);

    read(*clientSock, &fileNameSize, sizeof(int));
    *fileName = (uint8_t*)malloc(sizeof(uint8_t) * fileNameSize);

    read(*clientSock, *fileName, fileNameSize);
    puts("Phase 1 :: File name received.");

    puts("Phase 1 :: Decrypt Token.");
    memcpy(initialVectorUse, initialVector, AES_BLOCK_SIZE);
    decryptToken(token, symmetricKeyAuthenticationServerFileServer, initialVectorUse, id, timestamp, symmetricKey2);

    puts("Phase 1 :: Verify User.");
    if (verifyToken(symmetricKey2, id, requestFileHash) == 0)
    {
        puts("Phase 1 :: Verification failed.");
        printClientDisconnection();
        exit(0);
    }
    puts("Phase 1 :: Verification success.");
    puts("==================================================");

}
void phase2SendFile(int * clientSock,uint8_t** fileName,uint8_t* symmetricKey2, uint8_t* initialVector){
    uint8_t *file=NULL;
    uint8_t *encryptedFile=NULL;
    uint8_t initialVectorUse[AES_BLOCK_SIZE];

    long fileSize=-1;
    long fileEncryptSize;

    printf("Phase 2 :: Find \"%s\"\n", *fileName);
    if (tracefile(*fileName, &file, &encryptedFile, &fileSize, &fileEncryptSize) == 0)
    {
        printf("Phase 2 :: Failed to find \"%s\"\n", *fileName);
        printClientDisconnection();
        exit(0);
    }
    printFile(file, fileSize, PLAINTEXT);

    puts("Phase 2 :: Encrypt file.");
    memcpy(initialVectorUse, initialVector, AES_BLOCK_SIZE);
    for(long i= fileSize;i< fileEncryptSize;i++) file[i]='\0';
    encryptSymmetricKey(file,encryptedFile, fileEncryptSize, symmetricKey2, initialVectorUse);

    printFile(encryptedFile, fileEncryptSize,CIPHER);
    if (enterKey() == 0){
        printClientDisconnection();
        exit(0);
    } 

    write(*clientSock, &fileSize, sizeof(long));

    write(*clientSock, encryptedFile, fileEncryptSize);
    puts("Phase 2 :: Encrypted file sended.");
    free(*fileName);
    free(encryptedFile);
    free(file);
}