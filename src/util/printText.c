#include "../include/printText.h"

void printAuthenticationServerConnection(){
    puts("==================================================");
    puts("\tConnected to Authentication server\t");
    puts("==================================================");
}
void printAuthenticationServerDisconnection(){
    puts("==================================================");
    puts("\tDisconnected to Authentication Server\t");
    puts("==================================================");
}

void printClientConnection(){
    puts("==================================================");
    puts("\tConnected to New Client\t");
    puts("==================================================");
}
void printClientDisconnection(){
    puts("==================================================");
    puts("\tDisconnected to client\t");
    puts("==================================================");
}

void printEncryptedSymmetricKey(uint8_t* symmetricKey1Encrypted){
    int i,j;
    printf("\nEncrypted symmetric key : \n\t");
    for(i=0, j=0;i<RSA_ENC_SIZE; i++,j++,j%=PRINT_LINE_SIZE){
        printf("%02x", symmetricKey1Encrypted[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}
void printFile(uint8_t* file, long file_size, int flag){
    int i,j;
    if(flag==PLAINTEXT) printf("\nPlaintext File : \n\t");
    if(flag==CIPHER)    printf("\nEncrypted File : \n\t");
    for(i=0, j=0;i<file_size; i++,j++,j%=PRINT_LINE_SIZE){
        printf("%02x", file[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}

void printHashFile(uint8_t* requestFileHash){
    int i;
    for(i=0; i<HASH_SIZE;i++){
        printf("%02x", requestFileHash[i]);
    }
    printf("\n");
}
void printInitialVector(uint8_t* initialVector){
    int i;
    printf("\nIV : ");
    for(i=0; i<AES_BLOCK_SIZE;i++){
        printf("%02x", initialVector[i]);
    }
    printf("\n\n");
}

void printSymmetricKey(uint8_t* symmetricKey1){
    int i;
    printf("\nSymmetric key : ");
    for(i=0; i<SYM_KEY_SIZE;i++){
        printf("%02x", symmetricKey1[i]);
    }
    printf("\n\n");
}

void printToken(uint8_t* token, int flag){
    int i,j;
    if(flag==PLAINTEXT)printf("\nToken PlainText : \n\t");
    if(flag==CIPHER)printf("\nToken Cipher : \n\t");
    for(i=0, j=0;i<TOKEN_SIZE; i++,j++,j%=PRINT_LINE_SIZE){
        printf("%02x", token[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}