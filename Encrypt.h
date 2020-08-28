/*
    中软杯项目——Linux下基于签名技术的软件保护——团队“双流咸鱼王”
    本文件封装OpenSSL中提供的RSA-2048签名算法
    以及公钥、私钥、证书验证，供SignSection.c中调用。
*/
#ifndef _Encrypt_H
#define _Encrypt_H
#include <openssl/bio.h>

#define PADDING 11

static const char PrivateKeyPath[] = "rsa_private.key";
static const char CertPath[] = "cert.crt";

int rsaPrivateEncrypt(unsigned char* InputBuf,unsigned char* OutputBuf);
int rsaPublicDecrypt(unsigned char* InputBuf,unsigned char* OutputBuf);
int extractPublicKeyFromCert(RSA** PublicRsa);
#endif