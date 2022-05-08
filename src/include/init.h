#ifndef __INIT__
#define __INIT__

#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "macro.h"

typedef struct __user_info{
    uint8_t id[ID_SIZE];
    uint8_t passwordHash[HASH_SIZE];
    struct __user_info* next;
}USER;

int initClient(int *sock, const char* argv);
int initServer(int *servSock,const char* argv);
void readChildProcess(int sig);

#endif