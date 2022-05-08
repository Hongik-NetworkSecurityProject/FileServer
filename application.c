#include "src/include/init.h"
#include "src/include/macro.h"
#include "src/include/error.h"
#include "src/include/openssl.h"
#include "src/include/phase.h"



int main(int argc, char *argv[])
{
    int serverSock,clientSock,fileSock;
    struct sockaddr_in clientAddr;
    socklen_t clientAddrSize;
    pid_t pid;

    char id[ID_SIZE];
    uint8_t symmetricKeyAuthenticationSeverFileServer[SYM_KEY_SIZE];
    uint8_t symmetricKey2[SYM_KEY_SIZE];
    uint8_t initialVector[AES_BLOCK_SIZE];
    uint8_t *fileName;
    RSA *authenticationServerPublicRSAKey = NULL;

    if (argc != 3)
    {
        printf("Usage: %s <authentication server port> <file server port>\n", argv[0]);
        errorHandler(ARGUMENT);
    }
    
    if(initClient(&fileSock, argv[1])){
        printAuthenticationServerConnection();
    }
    phase0PreparationServer(&fileSock,symmetricKeyAuthenticationSeverFileServer, authenticationServerPublicRSAKey);

    initServer(&serverSock, argv[2]);
    while(1){
        clientAddrSize = sizeof(clientAddr);
        clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if(clientSock == -1) continue;
        else printClientConnection();

        pid =fork();
        if(pid==-1) {
            printClientDisconnection();
            close(clientSock);
        }
        if(pid==0){
            close(serverSock);
            phase1VerifyToken(&clientSock, symmetricKeyAuthenticationSeverFileServer, symmetricKey2, initialVector, &fileName);
            phase2SendFile(&clientSock, &fileName, symmetricKey2, initialVector);
            printClientDisconnection();
            close(clientSock);
            return 0;
        }
        else{
            close(clientSock);
        }
    }
    close(serverSock);
    return 0;
}