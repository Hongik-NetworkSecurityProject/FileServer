#ifndef __PHASE__
#define __PHASE__


#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "security.h"
#include "crypto.h"
#include "error.h"
#include "init.h"
#include "input.h"
#include "macro.h"
#include "printText.h"

void phase0PreparationServer(int *fileSock,uint8_t* symmetricKeyAuthenticationServerFileServer, RSA* authenticationServerPublicRSAKey);
void phase1VerifyToken(int* clientSock, uint8_t* symmetricKeyAuthenticationServerFileServer, uint8_t* symmetricKey2, uint8_t* initialVector,uint8_t** fileName);
void phase2SendFile(int * clientSock,uint8_t** fileName,uint8_t* symmetricKey2, uint8_t* initialVector);

#endif