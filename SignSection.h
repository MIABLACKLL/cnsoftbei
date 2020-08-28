/*
    中软杯项目——Linux下基于签名技术的软件保护——团队“双流咸鱼王”
    本文件实现，对于Linux下给定的ELF可执行程序，
    读取对应程序的代码段（Load Segment），对其
    首先使用SHA-256算法进行散列，然后对散列值使用RSA-2048算法进行签名，
    签名数据作为单独的节（Section）附加到原ELF可执行程序的尾部”。
*/


#ifndef _Sign_Section_H
#define _Sign_Section_H

#define MAGICNUM 0x464c457f
#define SIGNIDENT 4
#define NAMESIZE 32
#define SHA256LEN 32
#define RSA2048LEN 256

static const char SignSectionName[] = "cnsoftbei_sign";

typedef struct
{
    unsigned char Ident[SIGNIDENT]; //存储'SIG'字符串作为MagicNum验证
    long SignTime; //签名时间戳
    unsigned char LinuxUserName[NAMESIZE+1]; //签名者的用户名
    unsigned char Sign[RSA2048LEN+1]; //签名数据

}SSignSection;

void addSignSection(const char *SectionName, SSignSection* SignSection);

void hashLoadSegment(unsigned char* HashBuf,int Type);

void signHashValue(unsigned char* HashBuf,unsigned char* SignBuf);

int readElfFile(char *FIlePath,char *Type);

int isElfFile();

long findTargetSection(const char *SectionName);

SSignSection fetchSignSection(long SignSectionOffset);

void releaseAll();

#endif
