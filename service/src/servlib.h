#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include <signal.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT 6666

#define MAX_CONCURR 32
#define TRUE 1
#define FALSE 0
#define SESS_TO 5
#define SOCK_TO 60
#define SECOND 1000000
#define SERV_TICK 50000
#define MAX_COMMANDS 64

#define OPNUM           sizeof(char)
#define BUFFER          0x40
#define CHUNK           BUFFER
#define DATASTORE       BUFFER*2
#define STORAGE         BUFFER*4
#define MAP_SIZE        0x10000
#define MAP_ADDRESS     0x666666660000
#define MINUID          0x1111111111111111
#define MAXUID          0x7fffffffffffffff

#define STORAGE_SIZE    MAX_CONCURR * STORAGE * BUFFER/16
#define PLAYGRND_SIZE   MAX_CONCURR * CHUNK

#define pack __attribute__((__packed__))

typedef struct pack storage {
    char status;
    char workdir[BUFFER/2 - sizeof(short)];
    char filename[BUFFER/2 - 1];
    short position;
    char temp_buffer[BUFFER];
    char datastore[DATASTORE];
} *pstorage;

typedef struct pack packet {
    char opnum;
    union{
        char b;
        struct {
            short sl;
            short sh;
        };
        struct{
            long ll;
            long lh;
        };
        struct {
            unsigned long ull;
            unsigned long ulh;
        };
        long long L;
        unsigned long long uL;
        char body[BUFFER-1];
    };
} *ppacket;

typedef struct session {
    unsigned int sess_id;
    unsigned int connfd;
    void* chunk;
    pstorage storage;
    ppacket recv_buffer;
    pthread_t thread;
    FILE* fd;
    unsigned long uid;
    unsigned int tid;
    unsigned int connection_timer;
    unsigned int action_counter;
    void (*encoder)(long key, char* buffer, int loops);
    void* next_session;
    void* prev_session;
    char is_free;
} *psession;

typedef struct instruction {
    char opcode[4];
    char opval[5];
    short hexval;
};

extern const char encoder_stub[27];
int reply(int fd, char* msg, size_t msg_size);
int chef_read(char* src_buffer, char* ret_buffer, short start, short size);
int chef_input_control(char* buffer);
extern void basic_encode(long key, char* buffer, char loopc);