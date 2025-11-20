#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

/*
 *      Mechanism:
 *              - Init ring buffer.
 *              - New data inserted from tail.
 *              - If buffer is full:
 *                      - dequeue old head.
 *                      - increment tail by 1.
 *                      - overwrite the old head with the new inserted data from tail.
 *                      - increment head by 1.
 *              - Do cleanups.
 *
 *      Created on: November 6th, 2025.
 */

typedef unsigned char u8;
typedef unsigned short u16;

#define RING_BUFFER_SIZE 6      // <--- Tunable
#define NAME_SIZE 64
#define EMPTY_RBUF ((unsigned short)0xffffU)

#ifdef DEBUG_MODE
int ctr = 0;
#endif

// Dummy struct (for testing)
typedef struct user_data {
        int id;
        int grade;
        char name[NAME_SIZE];
} u_data;

/*
        @buffer: buffer for the actual data.
*/
typedef struct ringbuffer {
        struct user_data *buffer;
        u16 head_idx;
        u16 tail_idx;
#ifdef DEBUG_MODE
        void *head_ptr;
        void *tail_ptr;
#endif
        int magic;
} ringbuffer;

/* Helper */
__attribute__((constructor)) void setup(void);
void cleanup(ringbuffer **rbuf);
void err_chk(const char *msg);
void setval(u_data *stack, int id, int grade, char *name);

/* Main functionality */
ringbuffer *init_ringbuf();
void copy_to_ringbuf(u_data *rbuf, u_data *data);
void logmsg(ringbuffer *rbuf, u_data *buffer);
void enq(ringbuffer *rbuf, u_data *data);
void deq(ringbuffer *rbuf, u_data *data);

int main(void)
{
        ringbuffer *rbuf = init_ringbuf();
        u_data stack;

        /* Test data */
        // Will only copy 63 bytes of 'E' ended with null byte.
        setval(&stack, 0x61, 0x67, "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
        enq(rbuf, &stack);

        setval(&stack, 0x1337, 0x420, "FFFFFFFF");
        enq(rbuf, &stack);

        setval(&stack, 0x9051, 0x10c1, "GGGGGGGG");
        enq(rbuf, &stack);

        setval(&stack, 0x99, 0xb0b0, "HHHHHHHH");
        enq(rbuf, &stack);

        setval(&stack, 0x1010, 0xd00d, "IIIIIIII");
        enq(rbuf, &stack);

        setval(&stack, 0x2020, 0xd44d, "JJJJJJJJ");
        enq(rbuf, &stack);

        setval(&stack, 0x3030, 0xd33d, "KKKKKKKK");
        enq(rbuf, &stack);
        /* ========= */

        puts("\nx=================x");
        puts("Data on buffer");
        logmsg(rbuf, rbuf->buffer);

        puts("<EOF>");
        cleanup(&rbuf);
        getchar();
        return 0;
}

void deq(ringbuffer *rbuf, u_data *data)
{
        struct timespec ts;
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == -1) { err_chk("clock_gettime"); }

        printf("[%3ld.%06ld] [Buffer full, dequeuing] id: 0x%x , grade: 0x%x , name: %s\n", ts.tv_sec, ts.tv_nsec / 1000,
                        rbuf->buffer[rbuf->head_idx].id,
                        rbuf->buffer[rbuf->head_idx].grade,
                        rbuf->buffer[rbuf->head_idx].name);
        #ifdef DEBUG_MODE
                logmsg(rbuf, rbuf->buffer);
        #endif

        rbuf->head_idx = (rbuf->head_idx+1) % RING_BUFFER_SIZE;
        copy_to_ringbuf(&rbuf->buffer[rbuf->tail_idx], data);
        rbuf->tail_idx = (rbuf->tail_idx+1) % RING_BUFFER_SIZE;
}

void enq(ringbuffer *rbuf, u_data *data)
{
#ifdef DEBUG_MODE
        printf("ctr: %d\n", ++ctr);
#endif

        /* Empty buffer state */
        if (rbuf->head_idx == EMPTY_RBUF) {
                copy_to_ringbuf(&rbuf->buffer[rbuf->tail_idx], data);
                rbuf->head_idx = rbuf->tail_idx;
                rbuf->tail_idx = (rbuf->tail_idx+1) % RING_BUFFER_SIZE;

                #ifdef DEBUG_MODE
                        puts("Empty buffer");
                        printf("head idx: 0x%x\n", rbuf->head_idx);
                        printf("tail idx: 0x%x\n", rbuf->tail_idx);
                #endif
                return;
        }


        /* Full buffer state */
        if (rbuf->tail_idx == rbuf->head_idx) {
                #ifdef DEBUG_MODE
                        rbuf->head_ptr = &rbuf->buffer[rbuf->head_idx];
                        rbuf->tail_ptr = &rbuf->buffer[rbuf->tail_idx];
                        puts  ("========================");
                        printf("head idx: 0x%x\n", rbuf->head_idx);
                        printf("tail idx: 0x%x\n", rbuf->tail_idx);
                        printf("head ptr: %p\n", rbuf->head_ptr);
                        printf("tail ptr: %p\n", rbuf->tail_ptr);
                        puts  ("========================");
                #endif
                deq(rbuf, data);
                return;
        }


        /* Normal state */
        copy_to_ringbuf(&rbuf->buffer[rbuf->tail_idx], data);
        rbuf->tail_idx = (rbuf->tail_idx+1) % RING_BUFFER_SIZE;
}

void logmsg(ringbuffer *rbuf, u_data *buffer)
{
        struct timespec ts;
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == -1) { err_chk("clock_gettime"); }

        u16 traverse_idx = rbuf->head_idx;
        for (u8 i = 0; i < RING_BUFFER_SIZE; i++) {
                printf("[%3ld.%06ld] id: 0x%x , grade: 0x%x , name: %s\n", ts.tv_sec, ts.tv_nsec / 1000,
                        buffer[traverse_idx].id,
                        buffer[traverse_idx].grade,
                        buffer[traverse_idx].name);
                traverse_idx = (traverse_idx+1) % RING_BUFFER_SIZE;
        }
}

void copy_to_ringbuf(u_data *rbuf, u_data *data)
{
        rbuf->id = data->id;
        rbuf->grade = data->grade;
        strncpy(rbuf->name, data->name, NAME_SIZE-1);
        rbuf->name[NAME_SIZE-1] = '\0';
}


ringbuffer *init_ringbuf()
{
        // Ring buffer struct
        ringbuffer *rbuf = malloc (sizeof(ringbuffer));
        if (!rbuf) { err_chk("malloc"); }

        // Actual buffer for data
        rbuf->buffer = malloc(sizeof(u_data) * RING_BUFFER_SIZE);
        if (!rbuf->buffer) { err_chk("malloc"); }

        /*
                @head_idx: Intentionally set to 0xffff cause there's no element on ring buffer initially.
                @tail_idx: Set to 0 as it's the first index when data is being inserted.
        */
        rbuf->head_idx = EMPTY_RBUF;
        rbuf->tail_idx = 0;
#ifdef DEBUG_MODE
        rbuf->head_ptr = &rbuf->buffer[rbuf->head_idx];
        rbuf->tail_ptr = &rbuf->buffer[rbuf->tail_idx];
#endif
        rbuf->magic = 0xdeadbeef;
        return rbuf;
}

void setval(u_data *stack, int id, int grade, char *name)
{
        stack->id = id;
        stack->grade = grade;
        strncpy(stack->name, name, 63);
        stack->name[63] = '\0';
}

void err_chk(const char *msg)
{
        perror(msg);
        exit(EXIT_FAILURE);
}

void cleanup(ringbuffer **rbuf)
{
        free((*rbuf)->buffer);
        (*rbuf)->buffer = (u_data*)0x0000d00dd00d0000;
        free(*rbuf);
        *rbuf = (ringbuffer*)0x0000d00dd00d0000;
}

/* Ignore this */
__attribute__((constructor)) void setup(void)
{
        setbuf(stdin, NULL);
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
}
