/*
    中软杯项目——Linux下基于签名技术的软件保护——团队“双流咸鱼王”
    本文件实现，对于Linux下给定的ELF可执行程序，
    读取对应程序的代码段（Load Segment），对其
    首先使用SHA-256算法进行散列，然后对散列值使用RSA-2048算法进行签名，
    签名数据作为单独的节（Section）附加到原ELF可执行程序的尾部”。
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <elf.h>
#include <time.h>
#include <openssl/sha.h>
#include "SignSection.h"
#include "ErrorCode.h"

FILE* ElfFile = NULL;

//******************************************
//function:
void releaseAll()
{
    if(ElfFile)
    {
        fclose(ElfFile);
        ElfFile = NULL;
    }
}

//******************************************
//function:
SSignSection fetchSignSection(long SignSectionOffset)
{
    if(ElfFile == NULL)
	{
		printf("ERROR:Open file failed\n");
		exit(OPEN_ELF_ERROR);
	}

    fseek(ElfFile, SignSectionOffset, SEEK_SET);
    SSignSection FileSignSection;
    fread(&FileSignSection, 1, sizeof(SSignSection), ElfFile);
    
    	fclose(ElfFile);
    return FileSignSection;
}


//******************************************
//function:
long findTargetSection(const char *SectionName)
{
    if(ElfFile == NULL)
	{
		printf("ERROR:Open file failed\n");
		exit(OPEN_ELF_ERROR);
	}

    Elf64_Ehdr *ElfHeader;
    Elf64_Shdr *SectionHeader;

	fseek(ElfFile, 0, SEEK_END);
	unsigned ELFSize = ftell(ElfFile);
    char* Base = (char*)malloc(ELFSize);

    	fseek(ElfFile, 0, SEEK_SET);
	fread(Base, 1, ELFSize, ElfFile);

	if(Base == (void*) -1)
	{
		printf("ERROR:Memory alloc failed\n");
		exit(MEMORY_ERROR);
	}

    ElfHeader = (Elf64_Ehdr*)Base;
	SectionHeader = (Elf64_Shdr*)(Base + ElfHeader->e_shoff);
    char* SectionStrTableAddr = Base + SectionHeader[ElfHeader->e_shstrndx].sh_offset;

    Elf64_Off TargetSectionOffset = 0;
    for(int i=0;i<ElfHeader->e_shnum;i++,SectionHeader++)
    {
        if(!strcmp(SectionStrTableAddr+SectionHeader->sh_name,SectionName))
        {
            TargetSectionOffset = SectionHeader->sh_offset;
            break;
        }
    }

	fclose(ElfFile);
	free(Base);

    return TargetSectionOffset;
}

//******************************************
//function:
void hashLoadSegment(unsigned char* HashBuf,int Type)
{
    	if(ElfFile == NULL)
	{
		printf("ERROR:Open file failed\n");
		exit(OPEN_ELF_ERROR);
	}

    Elf64_Ehdr *ElfHeader;
    Elf64_Phdr *ProgramHeader;

	fseek(ElfFile, 0, SEEK_END);
	unsigned ELFSize = ftell(ElfFile);
    char* Base = (char*)malloc(ELFSize);

    	fseek(ElfFile, 0, SEEK_SET);
	fread(Base, 1, ELFSize, ElfFile);

	if(Base == (void*) -1)
	{
		printf("ERROR:Memory alloc failed\n");
		exit(MEMORY_ERROR);
	}

    ElfHeader = (Elf64_Ehdr*)Base;
    ProgramHeader = (Elf64_Phdr*)(Base + sizeof(Elf64_Ehdr));
    Elf64_Word LoadSegmentSize = 0;

    if(Type)
    {
        	ElfHeader->e_shnum--;
        Elf64_Off Olde_shoff = ElfHeader->e_shoff;
        ElfHeader->e_shoff = Olde_shoff - sizeof(SSignSection) - strlen(SignSectionName) -1;
    }

    Elf64_Phdr *TempProgramHeader = ProgramHeader;
    	for(int i=0;i<ElfHeader->e_phnum;i++,TempProgramHeader++)
	{
        	if(TempProgramHeader->p_type == PT_LOAD)
		{
            LoadSegmentSize += TempProgramHeader->p_filesz;
        }
    }

    char* LoadSegmentBuf = (char*)malloc(LoadSegmentSize);
    memset(LoadSegmentBuf,0,LoadSegmentSize);
    Elf64_Off BufOffset = 0; 	

    TempProgramHeader = ProgramHeader;
    	for(int i=0;i<ElfHeader->e_phnum;i++,TempProgramHeader++)
	{
        	if(TempProgramHeader->p_type == PT_LOAD)
		{
        
            memcpy(LoadSegmentBuf+BufOffset,Base+TempProgramHeader->p_offset
            ,TempProgramHeader->p_filesz);

            BufOffset += TempProgramHeader->p_filesz;
        }
    }

    SHA256(LoadSegmentBuf, LoadSegmentSize, HashBuf);

	fclose(ElfFile);
	free(Base);
    free(LoadSegmentBuf);

    //return ;//to do
}

int readElfFile(char *FIlePath,char *Type)
{
    ElfFile = fopen(FIlePath,Type);
    if(ElfFile) {return true;}
    return false;
}

//******************************************
//function:
int isElfFile()
{
    	if(ElfFile == NULL)
	{
		printf("ERROR:Open file failed\n");
		exit(OPEN_ELF_ERROR);
	}
    int MagicNum;
	fseek(ElfFile, 0, SEEK_SET);
	fread(&MagicNum, 1, sizeof(MagicNum), ElfFile);

    if(MagicNum != MAGICNUM)
    {
        printf("ERROR:Not standard ELF file\n");
        exit(READ_ELF_ERROR);
    }
    return true;
}

//******************************************
//function:
void addSignSection(const char *SectionName, SSignSection* SignSection)
{
	if(ElfFile == NULL)
	{
		printf("ERROR:Open file failed\n");
		exit(OPEN_ELF_ERROR);
	}

    char *Base = NULL,*WriteBuf = NULL;
	Elf64_Ehdr *ElfHeader;
	Elf64_Shdr *SectionHeader;
	unsigned OldELFSize = 0;
    unsigned SectionNameLen = strlen(SectionName);
    unsigned SignSectionSize = sizeof(SSignSection);

	fseek(ElfFile, 0, SEEK_END);
	OldELFSize = ftell(ElfFile);

    unsigned nWriteLen = OldELFSize + SignSectionSize + sizeof(Elf64_Shdr) + SectionNameLen +1;

	Base = (char*)malloc(OldELFSize);
    WriteBuf = (char*)malloc(nWriteLen);

	memset(Base, 0, OldELFSize);
    memset(WriteBuf, 0, nWriteLen);

	fseek(ElfFile, 0, SEEK_SET);
	fread(Base, 1, OldELFSize, ElfFile);

	if(Base == (void*) -1)
	{
		printf("ERROR:Memory alloc failed\n");
		exit(MEMORY_ERROR);
	}

	ElfHeader = (Elf64_Ehdr*) Base;
	SectionHeader = (Elf64_Shdr*)(Base + ElfHeader->e_shoff);

	ElfHeader->e_shnum++;
    Elf64_Off Olde_shoff = ElfHeader->e_shoff;
    ElfHeader->e_shoff = Olde_shoff + SignSectionSize + SectionNameLen +1;

    Elf64_Word OldShstrndxSize = SectionHeader[ElfHeader->e_shstrndx].sh_size;
	SectionHeader[ElfHeader->e_shstrndx].sh_size = OldShstrndxSize + SectionNameLen + 1;

    unsigned BeforeShstrndx = SectionHeader[ElfHeader->e_shstrndx].sh_offset + OldShstrndxSize;
    unsigned OldSecHeaderSize = (ElfHeader->e_shnum-1)*ElfHeader->e_shentsize;

	memcpy(WriteBuf, Base, BeforeShstrndx);
	strcpy(WriteBuf + BeforeShstrndx, SectionName);
    memcpy(WriteBuf + BeforeShstrndx + SectionNameLen + 1,
            Base + BeforeShstrndx, OldELFSize - BeforeShstrndx - OldSecHeaderSize);
    memcpy(WriteBuf + Olde_shoff + SectionNameLen +1, SignSection, SignSectionSize);
	

	Elf64_Shdr NewSectionHeader = {0};
	NewSectionHeader.sh_name = OldShstrndxSize;
	NewSectionHeader.sh_type = SHT_NOTE;
	//NewSectionHeader.sh_flags = SHF_WRITE;
	NewSectionHeader.sh_size = SignSectionSize;
	NewSectionHeader.sh_offset = Olde_shoff + SectionNameLen + 1;
	NewSectionHeader.sh_addr = 0;
	NewSectionHeader.sh_addralign = 1;

    Elf64_Off ShstrndxOffset = SectionHeader[ElfHeader->e_shstrndx].sh_offset;
    int SecHeaderNum = ElfHeader->e_shnum;
    SectionHeader = (Elf64_Shdr*)(WriteBuf + ElfHeader->e_shoff);
    for(int i=0;i<SecHeaderNum;i++,SectionHeader++)
    {
        if(ShstrndxOffset < SectionHeader->sh_offset)
            SectionHeader->sh_offset += SectionNameLen + 1;
    }

    memcpy(WriteBuf + ElfHeader->e_shoff, Base + Olde_shoff, OldSecHeaderSize);
	memcpy(WriteBuf + ElfHeader->e_shoff + OldSecHeaderSize, &NewSectionHeader, sizeof(Elf64_Shdr));

	fseek(ElfFile, 0, SEEK_SET);
	fwrite(WriteBuf, 1, nWriteLen, ElfFile);
	fclose(ElfFile);
	free(Base);
	free(WriteBuf);

}