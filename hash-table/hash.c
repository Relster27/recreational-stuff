#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Implementation of Hash Table with Separate Chaining */

#define HASH_TABLE_SIZE (10ul)
#define MAGIC_PTR ((elem*)0xdeadbeefcafebabe)
#define EMPTY_PID ((u16)0xffff)
#define BUF_SIZE 64

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

typedef struct elem {
        char filename[BUF_SIZE];
        u16 pid;
        struct elem *chain;
} elem;

void insert(const char *filename, u16 pid);
void delete(const char *filename);
void lookup(const char *filename);
u32 hash_function(const char *filename);
__attribute__((constructor)) void init_table(void);
u32 strlenhandle(const char *filename);
u16 gen_rand(void);

elem hash_table[HASH_TABLE_SIZE];

int main(void)
{
        insert("test.sh", gen_rand());
        insert("test.sh2", gen_rand());
        insert("test.sh13", gen_rand());
        insert("test.sh22", gen_rand());
        
        delete("test.sh");
        delete("test.sh13");

        lookup("test.sh2");
        lookup("test.sh");

        return EXIT_SUCCESS;
}

void insert(const char *filename, u16 pid)
{
        u32 idx = hash_function(filename);
        // printf("proc: %s -- pid: %u -- idx: %d\n", filename, pid, idx);

        // Empty table state
        if (hash_table[idx].pid == EMPTY_PID) {
                u32 len = strlenhandle(filename);
                strncpy(hash_table[idx].filename, filename, len);
                hash_table[idx].filename[len] = '\0';
                hash_table[idx].pid = pid;
                hash_table[idx].chain = MAGIC_PTR;
                return;
        }

        // If collision occurs, then use chain technique
        elem *h = malloc(sizeof(elem));
        if (!h) {
                perror("malloc");
                exit(EXIT_FAILURE);
        }
        u32 len = strlenhandle(filename);
        strncpy(h->filename, filename, len);
        h->filename[len] = '\0';
        h->pid = pid;
        h->chain = MAGIC_PTR;

        elem *ptr = hash_table[idx].chain;
        if (ptr == MAGIC_PTR) {
                hash_table[idx].chain = h;
        } else {
                while (ptr->chain != MAGIC_PTR) {
                        ptr = ptr->chain;
                }
                ptr->chain = h;
        }

}

void delete(const char *filename)
{
        u32 idx = hash_function(filename);

        // Element is on the table (not on chain)
        elem *ptr = &hash_table[idx];
        if (strcmp(ptr->filename, filename) == 0) {
                // If no chain (single element)
                if (ptr->chain == MAGIC_PTR) {
                        memset(ptr->filename, 0, BUF_SIZE);
                        ptr->pid = EMPTY_PID;
                        // ptr->chain = MAGIC_PTR;
                        return;
                }
                // If there is element on the chain
                else {
                        elem *next = ptr->chain;
                        u32 len = strlenhandle(next->filename);
                        strncpy(ptr->filename, next->filename, len);
                        ptr->filename[len] = '\0';
                        ptr->pid = next->pid;
                        ptr->chain = next->chain;

                        memset(next->filename, 0, BUF_SIZE);
                        next->pid = EMPTY_PID;
                        next->chain = MAGIC_PTR;
                        free(next);
                        return;
                }        
        }


        // Element is on the chain
        elem *prev = &hash_table[idx];
        elem *next = prev->chain;
        while (strcmp(next->filename, filename) != 0) {
                prev = next;
                next = next->chain;
        }
        prev->chain = next->chain;
        memset(next->filename, 0 ,BUF_SIZE);
        next->pid = EMPTY_PID;
        next->chain = MAGIC_PTR;
        free(next);

}

void lookup(const char *filename)
{
        u32 idx = hash_function(filename);

        // If the table is empty at all
        elem *ptr = &hash_table[idx];
        if (ptr->pid == EMPTY_PID) {
not_found:
                printf("PID of %s not found!\n", filename);
                return;        
        } else {       
                while (strcmp(ptr->filename, filename) != 0) {
                        if (ptr->chain == MAGIC_PTR) { goto not_found; }
                        ptr = ptr->chain;   
                }
                printf("Proc: %s | PID: %u\n", filename, ptr->pid);
        }

}

u32 hash_function(const char *filename)
{
        /*      Hash formula:
                idx = sigma(for(ch : filename)) % HASH_TABLE_SIZE
        */
        u32 len = strlen(filename);
        u64 sigma = 0;
        for (u32 i = 0; i < len; i++) {
                sigma += filename[i];
        }
        return (sigma % HASH_TABLE_SIZE);
}

__attribute__((constructor)) void init_table(void)
{
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
        for (u8 i = 0; i < HASH_TABLE_SIZE; i++) {
                hash_table[i].pid = EMPTY_PID;
        }
}

u32 strlenhandle(const char *filename)
{
        u32 len = strlen(filename);
        if (len < BUF_SIZE) {
                return len;
        }
        
        return (BUF_SIZE - 1);
}

u16 gen_rand(void)
{
        u16 fd = open("/dev/random", O_RDONLY);
        if (fd < 0) {
                perror("open");
                exit(EXIT_FAILURE);
        }
        u16 val = 0x00;
        read(fd, &val, 2);
        return (u16)val;
}
