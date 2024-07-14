#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>

extern int startup(int argc, char **argv, void (*start)()); // start the loaded program

int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg) {
    Elf32_Ehdr *elfHeader = (Elf32_Ehdr *)map_start; // Points to the ELF header, which is at the start of the mapped memory
    Elf32_Phdr *headerTable = (Elf32_Phdr *)(map_start + (*elfHeader).e_phoff); // Points to the program header table by adding the offset (e_phoff) to the start of the mapped memory
    printf("Type\t\tOffset\t\tVirtAddr\tPhysAddr\tFileSiz\tMemSiz\tFlg\tAlign\n");
    for(int i=0; i < (*elfHeader).e_phnum; i++) 
        func(headerTable + i, arg);
    return 0;
}

char* getFlagChar(int flg){ // Returns a string representing the flag character based on the program header's flags
    switch (flg){
        case 0x004: return "R"; // read permission
        case 0x005: return "R E"; // read and execute permissions
        case 0x006: return "RW"; // read and write permissions
        case 0x007: return "RWE"; // read, write, and execute permissions
        default: return "Unknown";
    }
}

char* getType(int type) {
    switch (type) {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_NOTE: return "NOTE";
        case PT_LOPROC: return "LOPROC";
        case PT_GNU_RELRO: return "GNU_RELRO";
        case PT_SHLIB: return "SHLIB";
        case PT_INTERP: return "INTERP";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
        case PT_LOOS: return "LOOS";
        case PT_HIOS: return "HIOS";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_HIPROC: return "HIPROC";
        case PT_GNU_STACK: return "GNU_STACK";
        default: return "UNKNOWN";
    }
}

int getProtectionFlags(Elf32_Phdr *phdr){ // Returns protection flags for memory mapping based on the program header's flags.
  int protectionFlags = 0;
  if ((*phdr).p_flags & PF_R) // read permission
    protectionFlags = protectionFlags | PROT_READ;
  if ((*phdr).p_flags & PF_X) // execute permission
    protectionFlags = protectionFlags | PROT_EXEC;
  if ((*phdr).p_flags & PF_W) // write permission
    protectionFlags = protectionFlags | PROT_WRITE;
  return protectionFlags;
}

void printProtectionFlags(Elf32_Phdr *phdr) { // Prints the protection and mapping flags for a program header
    int mmapFlags = ((*phdr).p_flags & PF_R) ? (MAP_PRIVATE) : MAP_SHARED;
    int protectionFlags = getProtectionFlags(phdr);
    printf("Protection Flags: %d, Mapping Flags: %d\n", protectionFlags, mmapFlags);
}

void printInformation(Elf32_Phdr *phdr, int i) { // Prints detailed information about a program header like readelf -l
  printf("%-13.13s\t%#08x\t%#08x\t%#08x\t%#06x\t%#06x\t%s\t%#06x\n",
    getType((*phdr).p_type), (*phdr).p_offset, (*phdr).p_vaddr, (*phdr).p_paddr, (*phdr).p_filesz, (*phdr).p_memsz, getFlagChar((*phdr).p_flags), (*phdr).p_align);
  printProtectionFlags(phdr);
}

int openFile(char* fileName){
  int fileDescriptor = open(fileName, O_RDONLY);
  if(fileDescriptor < 0) {
    perror("ERROR: cannot open file");
    exit(1);
  }
  return fileDescriptor;
}

void load_phdr(Elf32_Phdr *phdr, int fd) { // Maps a program header segment to memory
  printInformation(phdr, 0);
  void *map_start;
  if ((*phdr).p_type == PT_LOAD) 
  {
    void *vaddr = (void*) ((*phdr).p_vaddr & 0xfffff000); 
    int offset = (*phdr).p_offset & 0xfffff000; 
    int padding = (*phdr).p_vaddr & 0xfff;
    map_start = mmap(vaddr, (*phdr).p_memsz + padding, getProtectionFlags(phdr), MAP_PRIVATE | MAP_FIXED, fd ,offset);
    if (map_start == MAP_FAILED) {
        perror("ERROR: mmap failed");
        exit(1);
    }
  }
}

int getFileSize(int fileDescriptor){
  int size = lseek(fileDescriptor, 0, SEEK_END);
  lseek(fileDescriptor, 0, SEEK_SET); // Moves the file offset to the end to get the file size, then resets it to the start
  return size;
}

int main(int argc, char **argv) {
  void *map_start;
  if (argc <= 1){
    printf("No file name is provided\n");//
    exit(1);
  }
  int fileDescriptor = openFile(argv[1]);
  int fileDescriptorSize = getFileSize(fileDescriptor);
  map_start = mmap(0, fileDescriptorSize, PROT_READ, MAP_PRIVATE, fileDescriptor, 0);
  if (map_start == MAP_FAILED) {
    printf("ERROR: mmap failed\n");
    exit(1);
  }
  Elf32_Ehdr *elfHeader = (Elf32_Ehdr *) map_start;
  foreach_phdr(map_start, &load_phdr, fileDescriptor); 
  startup(argc-1, argv+1, (void *)((*elfHeader).e_entry));//this function is in task does the same as the command line
  close(fileDescriptor);
  exit(0);
}
