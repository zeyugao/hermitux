#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <err.h>

#include "br-elf.h"

/* Info about aarch64 instructions encoding:
 * https://static.docs.arm.com/ddi0596/a/DDI_0596_ARM_a64_instruction_set_architecture.pdf
 */

#define SYSCALL_INSTR       0xd4000001
#define REWRITE_MASK_B      0x14000000  /* for branch instructions */
#define REWRITE_MASK_BL     0x94000000  /* for branch and link */
#define RET_CODE            0xd65f03c0
#define PAGE_SIZE           4096

typedef struct {
    char binary_name[128];  /* input binary path */
    uint64_t code_vaddr; /* code segment start virtual address */
    uint64_t code_size;  /* code segment size */
    uint64_t file_offset; /* start offset in file */
} config;

void print_cfg(const config *cfg);

typedef struct {
    uint64_t addr;
    int whitelisted;
} scall;

int create_syscall_list(char *f, scall **list, int *len) {
    FILE* stream = fopen(f, "r");
    char line[64];
    scall *res = NULL;
    int elements = 0;

    while (fgets(line, 64, stream)) {
        uint64_t addr;
        char white[12];

        elements++;
        res = realloc(res, (elements) * sizeof(scall));
        if(!res) {
            fprintf(stderr, "cannot allocated memory\n");
            exit(-1);
        }

        char* tmp = strdup(line);
        sscanf(tmp, "0x%llx: %s\n", &addr, white);

        res[elements-1].addr = addr;
        res[elements-1].whitelisted = 0;
        if(!strcmp(white, "True"))
            res[elements-1].whitelisted = 1;

        free(tmp);
    }

    *list = res;
    *len = elements;
}

int main(int argc, char *argv[])
{
    uint64_t HANDLER_ADDR, vaddr, code_size, offset;
    config cfg;
    scall *syscall_list;
    int syscall_list_size;

    if(argc != 4) {
        fprintf(stderr, "Usage: %s <binary> <handler_addr> <syscall_list>\n",
                argv[0]);
        exit(-1);
    }

    create_syscall_list(argv[3], &syscall_list, &syscall_list_size);

    HANDLER_ADDR = (int)strtol(argv[2], NULL, 16);

    /* elf stuff */
    parse_elf(argv[1], &vaddr, &code_size, &offset);
    strcpy(cfg.binary_name, argv[1]);
    cfg.code_vaddr = vaddr;
    cfg.code_size = code_size;
    cfg.file_offset = offset;

    int fd = open(cfg.binary_name, O_RDWR);
    if(fd == -1)
        errx(EXIT_FAILURE, "cannot open %s\n", cfg.binary_name);

    uint32_t map_size = (cfg.code_size % PAGE_SIZE == 0) ?
        cfg.code_size : ((cfg.code_size / PAGE_SIZE) + 1) * PAGE_SIZE;
    void *map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
            cfg.file_offset);

    if(map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    uint32_t *ptr = map;
    int syscall_rewritten = 0;
    //while(ptr != (map + cfg.code_size)) {
    for(int i=0; i<syscall_list_size; i++) {
        ptr = map + syscall_list[i].addr - cfg.code_vaddr;
        uint64_t addr = ((void *)ptr-map)+cfg.code_vaddr;
        uint32_t instr = *ptr;

        /* Is it a SVC (syscall instruction)? */
        if(instr != SYSCALL_INSTR) {
            printf("Detected addr @%p is not a syscall! Probably the syscall "
                    "list does not corresponds to the binary. exiting\n", addr);
            exit(-1);
        }

        /* Can we safely rewrite the syscall? */
        if(syscall_list[i].whitelisted) {
            
            uint32_t instr_offset = (int32_t)addr - (int32_t)HANDLER_ADDR;
            instr_offset = instr_offset/4;
            instr_offset = ~instr_offset;
            instr_offset += 1;
            instr_offset &= 0x3FFFFFF;
            uint32_t new_instr = REWRITE_MASK_BL | instr_offset;

            *ptr = new_instr;
            syscall_rewritten++;


        } else if(*(ptr+1) == RET_CODE) {
            /* There is a ret right after the syscall instruction, we can
             * add a simple branch without overwriting the return address
             * in x30, we'll return from the syscall handler directly where
             * the function calling the syscall was supposed to return */

            /* We are doing a pc-relative jump to the handler. The handler
             * is in the kernel and will always be inferior to the
             * application pc */
            uint32_t instr_offset = (int32_t)addr - (int32_t)HANDLER_ADDR;

            /* B/BL instructions takes an immediate offset on 26 bits,
             * multiplied by 4 to find the actual address */
            instr_offset = instr_offset/4;

            /* We are doing a backward jump so negate the computed offset,
             * 2's complement and sign extension on the 26 lowest bits */
            instr_offset = ~instr_offset;
            instr_offset += 1;
            instr_offset &= 0x3FFFFFF;

            /* Add the opcode */
            uint32_t new_instr = REWRITE_MASK_B | instr_offset;

            *ptr = new_instr;
            syscall_rewritten++;
        } else if((*(ptr+1) >> 26 == REWRITE_MASK_BL >> 26) ||
                (*(ptr+2) >> 26 == REWRITE_MASK_BL >> 26) ||
                (*(ptr+3) >> 26 == REWRITE_MASK_BL >> 26) ||
                (*(ptr-1) >> 26 == REWRITE_MASK_BL >> 26) ||
                (*(ptr-2) >> 26 == REWRITE_MASK_BL >> 26) ||
                (*(ptr-3) >> 26 == REWRITE_MASK_BL >> 26)
                ) {

            /* There is a branch and link closeby, we can safely assure
             * that the compiler has alreayd taken care of saving the
             * return address in x30 so let's go a rewrite with a branch
             * and link */

            uint32_t instr_offset = (int32_t)addr - (int32_t)HANDLER_ADDR;
            instr_offset = instr_offset/4;
            instr_offset = ~instr_offset;
            instr_offset += 1;
            instr_offset &= 0x3FFFFFF;
            uint32_t new_instr = REWRITE_MASK_BL | instr_offset;

            *ptr = new_instr;
            syscall_rewritten++;
        }
    }

    close(fd);
    free(syscall_list);

    printf("Rewriting done, got %d/%d syscall invocations (%d\%)\n",
        syscall_rewritten, syscall_list_size,
        ((syscall_rewritten*100)/syscall_list_size));

    return 0;
}
