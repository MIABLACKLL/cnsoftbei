/*
    中软杯项目——Linux下基于签名技术的软件保护——团队“双流咸鱼王”
    本文件记录所有可能产生的错误的错误码
*/
#ifndef _ErrorCode_H
#define _ErrorCode_H

#define RUNNING -14
#define SUCCESS 0
#define OPEN_ELF_ERROR 1
#define OPEN_PRK_ERROR 2
#define OPEN_PUK_ERROR 3
#define READ_ELF_ERROR 4
#define READ_PRK_ERROR 5
#define READ_PUK_ERROR 6
#define ENCRYPT_ERROR 7
#define DECRYPT_ERROR 8
#define MEMORY_ERROR 9
#define SIGN_ERROR 10
#define SIGN_INVALID 11
#define OPEN_CRT_ERROR 12
#define READ_CRT_ERROR 13
#define CRT_INVALID 14
#define CRT_ERROR_PUK 15
#define BIO_WRITE_ERROR 16

#endif
