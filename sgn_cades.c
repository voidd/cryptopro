#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <reader/tchar.h>
#include <CSP_WinCrypt.h>
#include <CSP_WinDef.h>
#include <WinCryptEx.h>
#include <cades.h>

#include "sgn_cades.h"
#include "_cgo_export.h"
#define SERVICE_URL_2012 L"http://testca2012.cryptopro.ru/tsp/tsp.srf"

const char* GetHashOid(PCCERT_CONTEXT pCert) {
    const char *pKeyAlg = pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(pKeyAlg, szOID_CP_GOST_R3410EL) == 0)
    {
        return szOID_CP_GOST_R3411;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_256) == 0)
    {
        return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_512) == 0)
    {
        return szOID_CP_GOST_R3411_12_512;
    }
    return NULL;
}

int sign_message_cades_bes(PCCERT_CONTEXT pCertContext , unsigned int dwFlag, BYTE* message, char* out, int *size) {
	CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
	signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	signPara.pSigningCert = pCertContext; // 0 for window
	signPara.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(pCertContext);

	CERT_CHAIN_PARA             ChainPara = { sizeof(ChainPara) };
	PCCERT_CHAIN_CONTEXT        pChainContext = NULL;
	CertGetCertificateChain(NULL, pCertContext, NULL, NULL, &ChainPara, 0, NULL, &pChainContext);

	PCCERT_CONTEXT certs[pChainContext->rgpChain[0]->cElement];
	for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement-1; ++i) {
		certs[i]=pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;
	}

	if (sizeof(certs) > 0) {
		signPara.cMsgCert = pChainContext->rgpChain[0]->cElement-1;
		signPara.rgpMsgCert = &certs[0];
	}

	const BYTE *pbToBeSigned[] = { message };
	DWORD pcbSignedBlob;
	if(!CryptSignMessage(&signPara,dwFlag,1,pbToBeSigned,size,NULL, &pcbSignedBlob)) {
		*size = sprintf(out,"CryptSignMessage() failed: %d", GetLastError());

		return -1;
	}

	if(!CryptSignMessage(&signPara,dwFlag,1,pbToBeSigned,size,out, &pcbSignedBlob)) {
		*size = sprintf(out,"CryptSignMessage() failed: %d", GetLastError());

		return -1;
	}
	if (pChainContext)
		CertFreeCertificateChain(pChainContext);

	*size=pcbSignedBlob;

	return 0;
}

int sign_message_cades_xlt(PCCERT_CONTEXT pCertContext, BYTE* data, char* out, int *size) {
        int i;
	printf("hash value: ");
        for (i = 0; i < *size; i++)
        {
                printf("%02x", data[i]);
        }
        printf("\n");

	CADES_SERVICE_CONNECTION_PARA tspConnectionPara = { sizeof(tspConnectionPara) };
	tspConnectionPara.wszUri = SERVICE_URL_2012;

	CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
	cadesSignPara.dwCadesType = CADES_X_LONG_TYPE_1; 
	cadesSignPara.pTspConnectionPara = &tspConnectionPara;

	CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
	signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	signPara.pSigningCert = pCertContext;
	signPara.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(pCertContext);

	CERT_CHAIN_PARA             ChainPara = { sizeof(ChainPara) };
	PCCERT_CHAIN_CONTEXT        pChainContext = NULL;
	if (!CertGetCertificateChain(NULL, pCertContext, NULL, NULL, &ChainPara, 0, NULL, &pChainContext)) {
		*size = sprintf(out,"CertGetCertificateChain() failed: %i", GetLastError());
		return -1;
	}

	PCCERT_CONTEXT certs[pChainContext->rgpChain[0]->cElement];
	for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement-1; ++i) {
		certs[i]=pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;
	}

	if (sizeof(certs) > 0) {
		signPara.cMsgCert = pChainContext->rgpChain[0]->cElement-1;
		signPara.rgpMsgCert = &certs[0];
	}

	CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
	para.pSignMessagePara = &signPara;
	para.pCadesSignPara = &cadesSignPara;

	PCRYPT_DATA_BLOB pSignedMessage = 0;

	if (!CadesSignHash(&para, data, *size, (LPSTR) GetHashOid(pCertContext), &pSignedMessage)) {
		*size = sprintf(out,"CadesSignHash() failed: %i", GetLastError());
		CertFreeCertificateContext(pCertContext);
		return -1;
	}

	if (pChainContext)
		CertFreeCertificateChain(pChainContext);

	strcpy(out, pSignedMessage->pbData);
	*size = pSignedMessage->cbData;

	return 0;
}
