/*
    中软杯项目——Linux下基于签名技术的软件保护——团队“双流咸鱼王”
    本文件封装OpenSSL中提供的RSA-2048签名算法
    以及公钥、私钥、证书验证，供SignSection.c中调用。
*/
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include "Encrypt.h"
#include "ErrorCode.h"


int rsaPrivateEncrypt(unsigned char* InputBuf,unsigned char* OutputBuf)
{
    FILE *PrivateKeyFile = NULL;
	RSA *PrivateRsa = NULL;

	if ((PrivateKeyFile = fopen(PrivateKeyPath, "r")) == NULL) 
	{
		printf("ERROR:Private key path error\n");
		exit(OPEN_PRK_ERROR);
	} 	
   
	if ((PrivateRsa = PEM_read_RSAPrivateKey(PrivateKeyFile, NULL, NULL, NULL)) == NULL) 
	{
		printf("ERROR:PEM_read_RSAPrivateKey error\n");
		exit(READ_PRK_ERROR);
	}

	fclose(PrivateKeyFile);

	int RsaLen = RSA_size(PrivateRsa);
    memset(OutputBuf,0,RsaLen);
    
	if (RSA_private_encrypt(RsaLen-PADDING, InputBuf, OutputBuf, PrivateRsa, RSA_PKCS1_PADDING) < 0)
	{
        printf("ERROR:RSA_private_encrypt error\n");
        RSA_free(PrivateRsa);
        exit(ENCRYPT_ERROR);
    }
    RSA_free(PrivateRsa);
    return SUCCESS;
}

int rsaPublicDecrypt(unsigned char* InputBuf,unsigned char* OutputBuf)
{
    FILE *PublicKeyFile = NULL;
	RSA *PublicRsa = NULL;

	if (extractPublicKeyFromCert(&PublicRsa) == 0||PublicRsa == NULL) 
	{
        printf("ERROR:OPEN_PUK_ERROR error\n");
		exit(OPEN_PUK_ERROR);
	} 	

	int RsaLen = RSA_size(PublicRsa);
    memset(OutputBuf,0,RsaLen);

    RSA_print_fp(stdout, PublicRsa, 0);

	if (RSA_public_decrypt(RsaLen, InputBuf, OutputBuf, PublicRsa, RSA_PKCS1_PADDING) < 0)
	{
        printf("ERROR:DECRYPT_ERROR error\n");
        RSA_free(PublicRsa);
        exit(DECRYPT_ERROR);
    }

    RSA_free(PublicRsa);

    return SUCCESS;
}

int extractPublicKeyFromCert(RSA** PublicRsa) 
{

    BIO *CertBIO = NULL;
    X509 *Cert = NULL;
    EVP_PKEY *PKEY = NULL;
    int Ret;
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    CertBIO = BIO_new(BIO_s_file());
    Ret = BIO_read_filename(CertBIO, CertPath);

    if (! (Cert = PEM_read_bio_X509(CertBIO, NULL, 0, NULL)))
    {
        printf("ERROR:READ_CRT_ERROR error\n");
        exit(READ_CRT_ERROR);
    }

    if ((PKEY = X509_get_pubkey(Cert)) == NULL)
    {
        printf("ERROR:CRT_ERROR_PUK error\n");
        exit(CRT_ERROR_PUK);
    }  

    if ((*PublicRsa = EVP_PKEY_get1_RSA(PKEY)) == NULL)
    {
        printf("ERROR:READ_PUK_ERROR error\n");
	    exit(READ_PUK_ERROR);
    }

    X509_free(Cert);
    BIO_free_all(CertBIO);
    return Ret;
}