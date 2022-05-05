#include "../include/init.h"
#include "../include/error.h"

int initClient(int *sock, const char* argv){
    struct sockaddr_in servAddr;
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*sock==-1)
        errorHandler(SOCKET);
    
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family=AF_INET;
    servAddr.sin_addr.s_addr=inet_addr("127.0.0.1");
    servAddr.sin_port=htons(atoi(argv));

    if(connect(*sock,(struct sockaddr*)&servAddr, sizeof(servAddr))==-1)
        errorHandler(CONNECT);

    return TRUE;
}

int initServer(int *servSock,const char* argv){
    struct sockaddr_in servAddr;
    struct sigaction act;
    int state;

    act.sa_handler= readChildProcess;
    sigemptyset(&act.sa_mask);
    act.sa_flags=0;
    state=sigaction(SIGCHLD,&act,0);

    *servSock = socket(PF_INET, SOCK_STREAM, 0);
    if(*servSock == -1)
        errorHandler(SOCKET);
    
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(atoi(argv));

    if(bind(*servSock, (struct sockaddr*)&servAddr, sizeof(servAddr))==-1)
        errorHandler(BIND);
    
    if(listen(*servSock, CLIENT_NUM) ==-1)
        errorHandler(LISTEN);

    return TRUE;
}

void readChildProcess(int sig){
    pid_t pid;
    int status;
    pid=waitpid(-1,&status,WNOHANG);
}

