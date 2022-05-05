#include "../include/security.h"

void decryptToken(uint8_t* token, uint8_t* symmetricKeyAuthenticationServerFileServer, uint8_t* initialVectorUse, uint8_t* id, uint8_t* timestamp, uint8_t* symmetricKey2){
    uint8_t plaintext[TOKEN_SIZE];
    
    decryptSymmetricKey(token,plaintext,TOKEN_SIZE,symmetricKeyAuthenticationServerFileServer, initialVectorUse);
    printToken(plaintext,PLAINTEXT);

    for(int i=0;i<ID_SIZE;i++)
        id[i]=plaintext[i];
    for(int i=ID_SIZE,j=0;i<ID_SIZE+TIMESTAMP_SIZE;i++,j++)
        timestamp[j]=plaintext[i];
    for(int i=ID_SIZE+TIMESTAMP_SIZE,j=0;i<TOKEN_SIZE;i++,j++)
        symmetricKey2[j]=plaintext[i];
}

void makeRequestFileHash(uint8_t* requestFileHash, uint8_t* symmetricKey2, uint8_t* id){
    uint8_t hash[ID_SIZE+SYM_KEY_SIZE];

    for(int i=0;i<SYM_KEY_SIZE;i++)
        hash[i]=symmetricKey2[i];
    for(int i=SYM_KEY_SIZE, j=0; i<SYM_KEY_SIZE+ID_SIZE;i++, j++)
        hash[i]=id[j];
        
    SHA256(hash,SYM_KEY_SIZE+ID_SIZE, requestFileHash);
}

int tracefile(uint8_t* fileName,uint8_t** file, uint8_t** encryptedFile, long* fileSize, long* encryptedFileSize){
    FILE* fp = NULL;
    if(chdir("./db")==-1){
        puts("Phase 2 :: Cannot open directory \"db\".");
        return FALSE;
    }

    if((fp = fopen(fileName, "rb"))==NULL){
        printf("Phase 2 :: Cannot open file \"%s\".\n", fileName);
        return FALSE;
    }
   
    fseek(fp,0,SEEK_END);
    *fileSize = ftell(fp);
    fseek(fp,0,SEEK_SET);

    if(*fileSize%AES_BLOCK_SIZE==0) *encryptedFileSize= *fileSize;
    else *encryptedFileSize = *fileSize + AES_BLOCK_SIZE - (*fileSize)%AES_BLOCK_SIZE;

    printf("File size : %ld\n", *fileSize);
    printf("Encrypted file size : %ld\n", *encryptedFileSize);

    *file = (uint8_t*)malloc(sizeof(uint8_t)* (*encryptedFileSize));
    *encryptedFile = (uint8_t*)malloc(sizeof(uint8_t)* (*encryptedFileSize));
    
    fread(*file, sizeof(uint8_t), *fileSize, fp);
    
    fclose(fp);
    chdir("..");
    return TRUE;
}


int verifyToken(uint8_t* symmetricKey2, uint8_t* id, uint8_t* requestFileHash)
{
    uint8_t hash[HASH_SIZE];
    makeRequestFileHash(hash, symmetricKey2, id);
    
    for(int i=0;i<HASH_SIZE;i++)
        if(hash[i]!=requestFileHash[i])
            return FALSE;
    return TRUE;
}
