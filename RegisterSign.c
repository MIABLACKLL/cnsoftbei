#include <time.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "Encrypt.h"
#include "SignSection.h"
#include "RegisterSign.h"
#include "ErrorCode.h"

int registerSignSection(char *FIlePath)
{

    readElfFile(FIlePath,"rb");
    isElfFile();

/*
    if(!findTargetSection(SignSectionName));
    else
    {
        printf("ERROR:目标ELF文件已被签名！\n");
        return SIGN_ERROR;
    }
*/

    readElfFile(FIlePath,"rb");
    unsigned char hashValue[SHA256LEN+1] = {0};
    hashLoadSegment(hashValue,0);

    unsigned char EnOutputBuf[RSA2048LEN+1]={0};
    rsaPrivateEncrypt(hashValue,EnOutputBuf);
    
    SSignSection NewSignSection;
    strcpy(NewSignSection.Ident,"SIG");
    NewSignSection.SignTime = time(NULL);
    strcpy(NewSignSection.LinuxUserName,getpwuid(getuid())->pw_name);
    memcpy(NewSignSection.Sign,EnOutputBuf,RSA2048LEN+1);

    readElfFile(FIlePath,"rb+");
    addSignSection(SignSectionName,&NewSignSection);

    printf("SUCCESS:\n签名时间戳（from 1970/1/1 00:00:00）：%d\n签名用户：%s\n",NewSignSection.SignTime,NewSignSection.LinuxUserName,NewSignSection.Sign);

    printf("签名数据：\n");
    for(int i=0;i<=RSA2048LEN;i++)
    {
        printf("%x",NewSignSection.Sign[i]);
        if(i&&i%4==0)
        {
            printf(" ");
        }
        if(i&&i%16==0)
        {
            printf("\n");
        }
    }
        

    return SUCCESS;
}

int main(char argc,char *argv[])
{
    registerSignSection(argv[1]); 
}