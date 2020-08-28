#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "Encrypt.h"
#include "SignSection.h"
#include "VerifySign.h"
#include "ErrorCode.h"

int VerifySignSection(char *FIlePath)
{
    readElfFile(FIlePath,"rb");
    unsigned char hashValue[33] = {0};
    hashLoadSegment(hashValue,1);

    readElfFile(FIlePath,"rb");
    long SectionOffset = findTargetSection(SignSectionName);

    if(SectionOffset==0)
        exit(SIGN_ERROR);

    readElfFile(FIlePath,"rb");
    SSignSection FileSignSection = fetchSignSection(SectionOffset);
    
    unsigned char DeOutputBuf[257]={0};
    rsaPublicDecrypt(FileSignSection.Sign,DeOutputBuf);
    
    int CmpResult = strcmp(hashValue,DeOutputBuf);

    return CmpResult ? SIGN_INVALID:SUCCESS;
}

int main(char argc,char *argv[])
{
    int StatusCode = VerifySignSection(argv[1]); 
    printf("%d",StatusCode);
    exit(StatusCode); 
}