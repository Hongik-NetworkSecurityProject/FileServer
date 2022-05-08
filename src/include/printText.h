#ifndef __PRINTTEXT__
#define __PRINTTEXT__

#include <stdio.h>
#include <stdint.h>

#include "crypto.h"
#include "openssl.h"
#include "macro.h"

void printAuthenticationServerConnection();
void printAuthenticationServerDisconnection();

void printClientConnection();
void printClientDisconnection();

void printEncryptedSymmetricKey(uint8_t* symmetricKey1Encrypted);
void printFile(uint8_t* file, long file_size, int flag);

void printHashFile(uint8_t* requestFileHash);
void printInitialVector(uint8_t* initialVector);

void printSymmetricKey(uint8_t* symmetricKey1);
void printToken(uint8_t* token, int flag);

#endif