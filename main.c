#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <asm/elf.h>
#include <uapi/linux/elf.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include "ErrorCode.h"
#include "khook/engine.c"


static char *envp[] = {
    "HOME=/",
    "TERM=linux",
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
static char PathBuf[4096];


//对某些指定路径的文件不进行签名检查（系统内核文件以及最低限度保持系统正常运行的文件）
static const char *passELF[] = {
    "/usr/bin/kmod",
    "/usr/bin/dash",
    "/usr/lib/x86_64-linux-gnu/ld-2.24.so",
    "/usr/bin/dmesg",
    "/usr/bin/sudo",
    "/usr/bin/dbus-send",
    "/usr/lib/systemd/systemd-cgroups-agent",
    "/usr/lib/deepin-daemon/default-terminal",
    "/usr/bin/dde-shutdown"
};
//指定passELF的个数
static const int passFileNum = 9;


int isPassELF(char* FilePath)
{
    int i;
    for(i = 0;i<passFileNum;i++)
    {
        if(strcmp(passELF[i],FilePath)==0)
        {
            return 1;
        }
    }
    return 0;
}

const char* getErrorMsg(int ErrorCode)
{
    if(ErrorCode==RUNNING)
    {
        return "Sign checking...";
    }
    switch(ErrorCode/256)
    {
        case SUCCESS:return "run success.";
        case OPEN_ELF_ERROR: return "open ELF file error.";
        case OPEN_PRK_ERROR: return "open private_key file error.";
        case OPEN_PUK_ERROR: return "open public_key file error.";
        case READ_ELF_ERROR: return "read ELF file error.";
        case READ_PRK_ERROR: return "read private_key file error.";
        case READ_PUK_ERROR: return "read public_key file error.";
        case ENCRYPT_ERROR: return "RSA encrypt error.公私钥不匹配！";
        case DECRYPT_ERROR: return "RSA decrypt error.公私钥不匹配！";
        case MEMORY_ERROR: return "memory alloc error.";
        case SIGN_ERROR: return "ELF file not be signed.";
        case SIGN_INVALID: return "sign invalid.This ELF file may be modified after signature.";
        case OPEN_CRT_ERROR: return "open crt file error.";
        case READ_CRT_ERROR: return "read crt file error.";
        case CRT_INVALID: return "crt file invalid.证书与公钥不匹配！";
        case CRT_ERROR_PUK: return "读取公钥错误！";
        default : return "unknown error happened.";
    }
}

KHOOK_EXT(Elf64_Phdr*, load_elf_phdrs, const struct elfhdr *elf_ex,struct file *elf_file);
static Elf64_Phdr* khook_load_elf_phdrs(const struct elfhdr *elf_ex, struct file *elf_file)
{
	Elf64_Phdr* ret = NULL;
    int StatusCode = 0; 
    char* Path = d_path(&elf_file->f_path,PathBuf,4096);
    if(isPassELF(Path)==0&&
    strcmp(elf_file->f_path.dentry->d_iname,"VerifySign")!=0&&
    strcmp(elf_file->f_path.dentry->d_iname,"RegisterSign")!=0)
    { 
        char *argv[] = {"/home/VerifySign", Path};
        printk("目标文件进行签名检查：%s",Path);
        StatusCode = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
        printk("签名检查结果：%s StateCode:%d",getErrorMsg(StatusCode),StatusCode/256);
        if(StatusCode)
        {
            goto out;
        }
    }
    else
    {
        printk("被标记为不进行签名检查的文件：%s",Path);
    }
	ret = KHOOK_ORIGIN(load_elf_phdrs, elf_ex, elf_file);

out:
	return ret;
}

////////////////////////////////////////////////////////////////////////////////

int init_module(void)
{
    return khook_init();
}

void cleanup_module(void)
{
	khook_cleanup();
}

MODULE_LICENSE("GPL\0");
