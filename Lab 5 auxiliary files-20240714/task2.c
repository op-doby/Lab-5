#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>

 extern int startup(int argc, char **argv, void (*start)());

//e_phoff refers to the offset, in bytes, of the program
// header table from the beginning of the file.

int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg) {
    // Casting the start of the map to the ELF header
    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)map_start;
    // Getting the program header table by adding the offset to the start of the map
    Elf32_Phdr *program_header_table = (Elf32_Phdr *)(map_start + elf_header->e_phoff);
    printf("Type\t\tOffset\t\tVirtAddr\tPhysAddr\tFileSiz\tMemSiz\tFlg\tAlign\n"); //title

    // Looping through each entry in the program header table and calling the passed function on it
    int ind=0;
    while (ind < elf_header->e_phnum) {
        func(program_header_table + ind, arg);
        ind++;
    }

    return 0;
}


//get information
char* get_phdr_type(int type) {
    switch (type) {
        case PT_NULL:
            return "NULL";
        case PT_LOAD:
            return "LOAD";
        case PT_NOTE:
            return "NOTE";
        case PT_INTERP:
            return "INTERP";
        case PT_SHLIB:
            return "SHLIB";
        case PT_PHDR:
            return "PHDR";
        case PT_TLS:
            return "TLS";
        case PT_LOOS:
            return "LOOS";
        case PT_HIOS:
            return "HIOS";
        case PT_DYNAMIC:
            return "DYNAMIC";
        case PT_LOPROC:
            return "LOPROC";
        case PT_HIPROC:
            return "HIPROC";
        case PT_GNU_EH_FRAME:
            return "GNU_EH_FRAME";
        case PT_GNU_STACK:
            return "GNU_STACK";
        case PT_GNU_RELRO:
            return "GNU_RELRO";
        default:
            return "UNKNOWN";
    }
}


//get information
char* get_phdr_flag_char(int flg){//get the flag char from the p_flags field of the program header
    switch (flg){
        case 0x004: return "R";
        case 0x005: return "R E";
        case 0x006: return "RW";
        case 0x007: return "RWE";
        default:return "Unknown";
    }
}
//1 is read, 2 is write, 4 is execute





//1b
//get protection flags from the p_flags field of the program header
int get_protection_flags(Elf32_Phdr *phdr){
  int prot_flags = 0;
  if (phdr->p_flags & PF_R) //PF_R is a flag that indicates read permission
    prot_flags = prot_flags | PROT_READ;// 
  if (phdr->p_flags & PF_X) //PF_X is a flag that indicates execute permission
    prot_flags = prot_flags | PROT_EXEC;
  if (phdr->p_flags & PF_W) //PF_W is a flag that indicates write permission
    prot_flags = prot_flags | PROT_WRITE;
  return prot_flags;
}




void print_prot_mmap_flags(Elf32_Phdr *phdr) {
    int prot_flags = get_protection_flags(phdr);//get protection flags from the function above
    int mmap_flags = (phdr->p_flags & PF_R) ? (MAP_PRIVATE) : MAP_SHARED;
    printf( "----Protection flags:%d\n----Mapping flags:%d\n", prot_flags, mmap_flags);
}
//1a
// readelf -l
void print_phdr_information(Elf32_Phdr *phdr, int i) {
  printf("%-13.13s\t%#08x\t%#08x\t%#08x\t%#06x\t%#06x\t%s\t%#06x\n",
    get_phdr_type(phdr->p_type),
    phdr->p_offset,
    phdr->p_vaddr,
    phdr->p_paddr,
    phdr->p_filesz,
    phdr->p_memsz,
    get_phdr_flag_char(phdr->p_flags),
    phdr->p_align);
  print_prot_mmap_flags(phdr);
}



int openFile(char* fileName){
  int fileDes = open(fileName, O_RDONLY);
  if(fileDes < 0) {
    perror("fail - cannot open file");
    exit(EXIT_FAILURE);
  }
  return fileDes;
}

//2b
void load_phdr(Elf32_Phdr *phdr, int fd) {
  print_phdr_information(phdr, 0);//print the information of the program header
  void *map_start;//the start of the map
  if (phdr->p_type == PT_LOAD) {//if the type of the program header is PT_LOAD
    void *vaddr = (void*) (phdr->p_vaddr & 0xfffff000);//get the virtual address
    int offset = phdr->p_offset & 0xfffff000;//get the offset
    int padding = phdr->p_vaddr & 0xfff;//get the padding
    map_start = mmap(vaddr, phdr->p_memsz + padding, get_protection_flags(phdr), MAP_PRIVATE | MAP_FIXED, fd ,offset);//map the file to memory
    if (map_start == MAP_FAILED) {
      perror("mmap failed");
      exit(1);
    }
  }
}
// 
int getFileSize(int fileDes){
  int size = lseek(fileDes, 0, SEEK_END);
  lseek(fileDes, 0, SEEK_SET);
  return size;
}

int main(int argc, char **argv) {
  void *map_start;
  if (argc < 2){
    printf("there is no file name in the arguments\n");//
    return 1;
  }
  int fileDes = openFile(argv[1]);// open the file
  int fileDesSize = getFileSize(fileDes);
  map_start = mmap(0, fileDesSize, PROT_READ, MAP_PRIVATE, fileDes, 0);// map the file to memory 
  if (map_start == MAP_FAILED) {
    printf("fail - mmap \n");
    return 1;
  }
  //foreach_phdr(map_start, &print_phdr_information, fileDes); //task 0 (+1ab)
  Elf32_Ehdr *elf_head = (Elf32_Ehdr *) map_start;
  foreach_phdr(map_start, &load_phdr, fileDes); //
  startup(argc-1, argv+1, (void *)(elf_head->e_entry));//this function is in task does the same as the command line
  close(fileDes);
  return 0;
}
