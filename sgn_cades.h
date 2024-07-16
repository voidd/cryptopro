#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <reader/tchar.h>
#include <CSP_WinCrypt.h>
#include <CSP_WinDef.h>
#include <WinCryptEx.h>
#include <cades.h>

const char* GetHashOid(PCCERT_CONTEXT pCert);
int sign_message_cades_bes(PCCERT_CONTEXT pCertContext , unsigned int dwFlag, BYTE* message, char* out, int *size);
int sign_message_cades_xlt(PCCERT_CONTEXT pCertContext, BYTE* data, char* out, int *size);
void log_out(BYTE* data, char* out, int *size);
