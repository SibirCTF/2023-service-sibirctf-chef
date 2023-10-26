#include "servlib.h"

char storage_path[] = "storage/";
psession session_chain = NULL;
pthread_mutex_t session_mutex;
pthread_cond_t max_sessions_cond;
pthread_mutex_t max_sessions_lock;

void* playground;
void* last_free_pg_chunk;
void* playground_top;

void* session_store;
void* last_free_store_chunk;
void* session_store_top;

int current_connections = 0;

const char encoder_stub[27] = { 
    0x56, 0x57, 0x52, 0x51,
    0xe8, 0x11, 0x00, 0x00, 0x00, 
    0x66, 0x83, 0xc6, 0x02,
    0x80, 0xea, 0x02,
    0x80, 0xfa, 0x00,
    0x75, 0xef, 
    0x59, 0x5a, 0x5f, 0x5e, 
    0xc3, 0xc3
};

void do_cleanup(psession session){
    if (session->fd != NULL){
        fclose(session->fd);
    }
    memset(session->chunk, '\0', CHUNK);
    close(session->connfd);
    session->is_free = 1;
    session->storage->status = 0;
    pthread_mutex_lock(&max_sessions_lock);
    if (current_connections >= MAX_CONCURR)
        pthread_cond_signal(&max_sessions_cond);
    current_connections--;
    fprintf(stderr, "current connections %d\n", current_connections);
    pthread_mutex_unlock(&max_sessions_lock);
}

void segfault_handler(int signum){
    int curr_tid = gettid();
    psession sessions_node = session_chain;
    pthread_mutex_lock(&session_mutex);
    while (sessions_node != NULL && sessions_node->tid != curr_tid){
        sessions_node = sessions_node->prev_session;
    }
    if (sessions_node == NULL){
        fprintf(stderr, "Got unhandlable %s on thread %d, dying... (NULL)\n", strsignal(signum), gettid());
        raise(SIGSEGV);
    }
    if (sessions_node->tid != curr_tid){
        fprintf(stderr, "Got unhandlable %s on thread %d, dying... (threads unequal)\n", strsignal(signum), gettid());
        raise(SIGSEGV);
    }
    pthread_mutex_unlock(&session_mutex);
    fprintf(stderr, "Got %s on thread %d, bailing...\n", strsignal(signum), gettid());
    do_cleanup(sessions_node);
    pthread_exit(NULL);
}

void sigabort_handler(int signum){
    fprintf(stderr, "Got SIGABRT on thread %d, bailing...\n", gettid());
    pthread_exit(NULL);
}

void* connection_handler(psession session){

    signal(SIGSEGV, segfault_handler);
    signal(SIGILL, segfault_handler);
    signal(SIGABRT, sigabort_handler);
    signal(SIGPIPE, SIG_IGN);

    int exit = 0;
    char* delimiter = NULL;
    int activity_timer = 0;
    short start = 0;
    short offset = 0;

    session->tid = gettid();
    session->connection_timer = 0;
    session->action_counter = 0;
    session->fd = NULL;
    session->storage->position = 0;

    session->uid = 0;
    session->encoder = &basic_encode;

    while (TRUE){
        if (session->connection_timer > (SOCK_TO * (SECOND/SERV_TICK)) || activity_timer > (SESS_TO * (SECOND/SERV_TICK)) || session->action_counter > MAX_COMMANDS){
            reply(session->connfd, "ERR_CON_TIMEOUT", BUFFER/4);
            break;
        }
        if (exit) {
            reply(session->connfd, "CONN_TERMINATED", BUFFER/4);
            break;
        }
        int status = recv(session->connfd, session->recv_buffer, BUFFER, MSG_DONTWAIT);
        if (status <= 0){
            if (status == -1) {
                if (errno == 11){
                    usleep(SERV_TICK);
                    session->connection_timer++;
                    activity_timer++;
                    continue;
                }
                perror("recv");
            }
            break;
        }
        activity_timer = 0;
        switch(session->recv_buffer->opnum){
            case 0x01: // OPEN <filename>
                if (session->fd != NULL){
                    reply(session->connfd, "ERR_ALREADY_OPN", BUFFER/4);
                    break;
                }
                if (session->storage->workdir == NULL || strlen(session->storage->workdir) < 1) {
                    reply(session->connfd, "ERR_INVALID_DIR", BUFFER/4);
                    break;
                }
                offset = strlen(session->recv_buffer->body) + 1;
                memcpy(session->storage->filename, session->recv_buffer->body, offset);
                sprintf(session->storage->temp_buffer, "%s/%s", session->storage->workdir, session->storage->filename);
                offset = chef_input_control(session->storage->temp_buffer);
                if (access(session->storage->temp_buffer, F_OK) != 0){
                    if ((session->fd = fopen(session->storage->temp_buffer, "w")) != NULL)
                        fclose(session->fd);
                }
                session->fd = fopen(session->storage->temp_buffer, "r+");
                if (session->fd == NULL){
                    perror("fopen");
                    reply(session->connfd, "ERR_CREATE_FILE", BUFFER/4);
                    break;
                }
                reply(session->connfd, "OP_OPEN_SUCCESS", BUFFER/4);
                break;
            case 0x02: // DUMP <start><offset>
                if (session->fd == NULL){
                    reply(session->connfd, "ERR_FD_NOT_OPEN", BUFFER/4);
                    break;
                }
                if (session->storage->workdir == NULL) {
                    reply(session->connfd, "ERR_INVALID_DIR", BUFFER/4);
                    break;
                }
                if (ftell(session->fd) > DATASTORE*4){
                    reply(session->connfd, "ERR_NO_SPC_LEFT", BUFFER/4);
                    break;
                }
                start = session->recv_buffer->sl;
                offset = session->recv_buffer->sh;
                if (offset > DATASTORE){
                    reply(session->connfd, "ERR_OFFSET_OOBS", BUFFER/4);
                    break; 
                }
                fseek(session->fd, start, 0);
                if (fwrite(session->storage->datastore + session->storage->position, 1, offset, session->fd) <= 0){
                    reply(session->connfd, "ERR_DMP_TO_FILE", BUFFER/4);
                    break;
                }
                reply(session->connfd, "OP_DUMP_SUCCESS", BUFFER/4);
                break;
            case 0x03: // REST <start><offset>
                if (session->fd == NULL){
                    reply(session->connfd, "ERR_FD_NOT_OPEN", BUFFER/4);
                    break;
                }
                start = session->recv_buffer->sl;
                offset = session->recv_buffer->sh;
                if (offset > DATASTORE){
                    reply(session->connfd, "ERR_OFFSET_OOBS", BUFFER/4);
                    break; 
                }
                fseek(session->fd, start, 0);
                if (fread(session->storage->datastore + session->storage->position, 1, offset, session->fd) <= 0){
                    reply(session->connfd, "ERR_RESTOR_FILE", BUFFER/4);
                    break;
                }
                reply(session->connfd, "OP_REST_SUCCESS", BUFFER/4);
                break;
            case 0x04: // CLSE
                if (session->fd == NULL){
                    reply(session->connfd, "ERR_ALRD_CLOSED", BUFFER/4);
                    break;
                }
                fclose(session->fd);
                session->fd = NULL;
                reply(session->connfd, "OP_CLSE_SUCCESS", BUFFER/4);
                break;
            case 0x05: // WRTE <buffer>
                if (session->storage->position > DATASTORE){
                    reply(session->connfd, "ERR_BUFFER_FULL", BUFFER/4);
                    break; 
                }
                memcpy(session->storage->temp_buffer, session->recv_buffer->body, BUFFER);
                offset = chef_input_control(session->storage->temp_buffer);
                if (session->storage->position + offset > DATASTORE){
                    reply(session->connfd, "ERR_BUFFER_FULL", BUFFER/4);
                    break; 
                }
                memcpy(session->storage->datastore + session->storage->position, session->storage->temp_buffer, offset);
                session->storage->position += offset;
                reply(session->connfd, "OP_WRTE_SUCCESS", BUFFER/4);
                break;
            case 0x06: // READ <start><size>
                if (chef_read(session->storage->datastore, session->storage->temp_buffer, session->recv_buffer->sl, session->recv_buffer->sh)){
                    reply(session->connfd, "ERR_READ_STORAG", BUFFER/4);
                    break;
                }
                reply(session->connfd, session->storage->temp_buffer, BUFFER);
                break;
            case 0x07: // ENCD <offset>
                if (session->storage->position + BUFFER > DATASTORE){
                    reply(session->connfd, "ERR_OFFSET_OOBS", BUFFER/4);
                    break;
                }
                memcpy(session->storage->temp_buffer, session->storage->datastore + session->storage->position, BUFFER);
                session->encoder(session->uid | MINUID, session->storage->temp_buffer, (char)BUFFER);
                memcpy(session->storage->datastore + session->storage->position, session->storage->temp_buffer, BUFFER);
                reply(session->connfd, "OP_ENCD_SUCCESS", BUFFER/4);
                break;
            case 0x08: // SHFT <position>
                offset = session->recv_buffer->sl;
                if (offset > DATASTORE){
                    reply(session->connfd, "ERR_OFFSET_OOBS", BUFFER/4);
                    break; 
                }
                session->storage->position = offset;
                reply(session->connfd, "OP_SHFT_SUCCESS", BUFFER/4);
                break;
            case 0x09: // LIST <offset>
                if (session->storage->workdir == NULL) {
                    reply(session->connfd, "ERR_INVALID_DIR", BUFFER/4);
                    break;
                }
                start = session->recv_buffer->sl;
                get_listing(session->storage->workdir, start, session->storage->temp_buffer);
                reply(session->connfd, session->storage->temp_buffer, BUFFER);
                break;
            case 0x0a: ; // LOAD
                /*
                        <--- CHEF's finest data-cooking language --->
                    SYNTAX:
                        ADD xxxx; -> add xx to currently pointed word
                        XOR xxxx; -> xor currently pointed word with xxxx
                        SUB xxxx; -> sub xxxx from currently pointed word
                        SHF xxxx; -> move pointer forward xxxx bytes
                        SHB xxxx; -> move pointer backward xxxx bytes
                        CPY xxxx; -> copy currently pointed word
                        ADS xxxx; -> add stored word to a currently pointed one
                        XOS xxxx; -> xor stored word with a currently pointed one
                        SUS xxxx; -> sub stored word form a currently pointed one
                        END xxxx; -> end of algorithm
                */
                struct instruction insn = {0};
                void* asm_buffer = session->chunk;
                int asm_offset = sizeof(encoder_stub)-1;
                offset = 0;
                delimiter = NULL;
                char success = 1;
                memcpy(asm_buffer, encoder_stub, sizeof(encoder_stub));
                while (TRUE){
                    memset(&insn, '\0', sizeof(struct instruction));
                    delimiter = strchr(session->storage->datastore + offset, ';');
                    if (asm_offset >= BUFFER){
                        reply(session->connfd, "ERR_TOO_MNY_INS", BUFFER/4);
                        success = 0;
                        break;
                    }
                    if (delimiter == NULL){
                        if (offset == 0){
                            reply(session->connfd, "ERR_EMPTY_INSNS", BUFFER/4);
                            success = 0;
                        } else {
                            reply(session->connfd, "ERR_NO_END_INSN", BUFFER/4);
                            success = 0;
                        }
                        break;
                    }
                    if ((delimiter - (session->storage->datastore + offset)) > 9){
                        success = 0;
                        reply(session->connfd, "ERR_CORPTD_INSN", BUFFER/4);
                        break;
                    }
                    memcpy(insn.opcode, session->storage->datastore + offset, 3);
                    offset += 4;
                    memcpy(insn.opval, session->storage->datastore + offset, 4);
                    offset += 5;
                    if (strcmp(insn.opcode, "SHF") == 0) {
                        insn.hexval = strtol(insn.opval, NULL, 0x10);
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x81;
                        ((char*)asm_buffer)[asm_offset++] = 0xc6;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval & 0xff;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval >> 8;
                    }
                    else if (strcmp(insn.opcode, "SHB") == 0) {
                        insn.hexval = strtol(insn.opval, NULL, 0x10);
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x81;
                        ((char*)asm_buffer)[asm_offset++] = 0xee;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval & 0xff;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval >> 8;
                    }
                    else if (strcmp(insn.opcode, "ADD") == 0) {
                        insn.hexval = strtol(insn.opval, NULL, 0x10);
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x81;
                        ((char*)asm_buffer)[asm_offset++] = 0x06;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval & 0xff;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval >> 8;
                    }
                    else if (strcmp(insn.opcode, "XOR") == 0) {
                        insn.hexval = strtol(insn.opval, NULL, 0x10);
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x81;
                        ((char*)asm_buffer)[asm_offset++] = 0x36;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval & 0xff;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval >> 8;
                    }
                    else if (strcmp(insn.opcode, "SUB") == 0) {
                        insn.hexval = strtol(insn.opval, NULL, 0x10);
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x81;
                        ((char*)asm_buffer)[asm_offset++] = 0x2e;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval & 0xff;
                        ((char*)asm_buffer)[asm_offset++] = insn.hexval >> 8;
                    }
                    else if (strcmp(insn.opcode, "ADS") == 0) {
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x01;
                        ((char*)asm_buffer)[asm_offset++] = 0x0e;
                    }
                    else if (strcmp(insn.opcode, "SUS") == 0) {
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x29;
                        ((char*)asm_buffer)[asm_offset++] = 0x0e;
                    }
                    else if (strcmp(insn.opcode, "XOS") == 0) {
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x31;
                        ((char*)asm_buffer)[asm_offset++] = 0x0e;
                    }
                    else if (strcmp(insn.opcode, "CPY") == 0) {
                        ((char*)asm_buffer)[asm_offset++] = 0x66;
                        ((char*)asm_buffer)[asm_offset++] = 0x8b;
                        ((char*)asm_buffer)[asm_offset++] = 0x0e;
                    }
                    else if (strcmp(insn.opcode, "END") == 0) {
                        ((char*)asm_buffer)[asm_offset] = 0xc3;
                        break;
                    }
                    else {
                        success = 0;
                        reply(session->connfd, "ERR_INVL_OPCODE", BUFFER/4);
                        break;
                    }
                }
                if (success) {
                    session->encoder = asm_buffer;
                    reply(session->connfd, "OP_LOAD_SUCCESS", BUFFER/4);
                }
                break;
            case 0x0b: // SAVE
                sprintf(session->storage->temp_buffer, "%s/.savefile", session->storage->workdir);
                FILE* savefile = fopen(session->storage->temp_buffer, "w");
                if (savefile == NULL){
                    reply(session->connfd, "ERR_SAVE_CREATE", BUFFER/4);
                    break;
                }
                fwrite(session->chunk, 1, CHUNK, savefile);
                fclose(savefile);
                reply(session->connfd, "OP_SAVE_SUCCESS", BUFFER/4);
                break;
            case 0x0c: // AUTH <uid>
                session->uid = session->recv_buffer->ll;
                sprintf(session->storage->workdir, "%s%015lx", storage_path, session->uid);
                mkdir(session->storage->workdir, 0744);
                if (access(session->storage->workdir, F_OK) != 0) {
                    reply(session->connfd, "ERR_CREAT_FOLDR", BUFFER/4);
                    break;
                }
                sprintf(session->storage->temp_buffer, "%s/.savefile", session->storage->workdir);
                if (access(session->storage->temp_buffer, F_OK) == 0){
                    FILE* savefile = fopen(session->storage->temp_buffer, "r");
                    if (savefile != NULL){
                        if (fread(session->chunk, 1, CHUNK, savefile)){
                            session->encoder = session->chunk;
                            reply(session->connfd, "OP_LOAD_SUCCESS", BUFFER/4);
                        } else {
                            reply(session->connfd, "ERR_LOAD_SAVEST", BUFFER/4);
                        }
                        fclose(savefile);
                        break;
                    }
                }
                reply(session->connfd, "OP_AUTH_SUCCESS", BUFFER/4);
                break;
            case 0x0d: // HELL
                reply(session->connfd, "<-- A(we)S(o)M(e) CHEF v0.01 -->", BUFFER/2);
                break;
            case 0x0e: // DELE
                if (session->fd != NULL){
                    reply(session->connfd, "ERR_FILE_OPENED", BUFFER/4);
                    break;
                }
                if (session->storage->workdir == NULL) {
                    reply(session->connfd, "ERR_INVALID_DIR", BUFFER/4);
                    break;
                }
                sprintf(session->storage->temp_buffer, "%s/%s", session->storage->workdir, session->storage->filename);
                if (remove(session->storage->temp_buffer) < 0){
                    reply(session->connfd, "ERR_DELE_FAILED", BUFFER/4);
                    break;
                }
                reply(session->connfd, "OP_DELE_SUCCESS", BUFFER/4);
                break;
            case 0x0f: // TERM
                exit = 1;
                break;
            default:
                reply(session->connfd, "UNKNOWN_COMMAND", BUFFER/4);
                break;
        }
        memset(session->recv_buffer, '\0', BUFFER);
        memset(session->storage->temp_buffer, '\0', BUFFER);
        session->action_counter++;
    }
    do_cleanup(session);
}

void main() {

    playground = mmap(MAP_ADDRESS, MAP_SIZE, 0x3, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    last_free_pg_chunk = playground;
    playground_top = playground + PLAYGRND_SIZE;
    mprotect(playground, PLAYGRND_SIZE, 0x7);

    session_store = playground + STORAGE_SIZE;
    last_free_store_chunk = session_store;
    session_store_top = session_store + STORAGE_SIZE - STORAGE;

    fprintf(stderr, "%x, %x, %x\n", PLAYGRND_SIZE, STORAGE_SIZE, MAP_SIZE);
    fprintf(stderr, "%llx, %llx (%lx)\n", playground, session_store, STORAGE_SIZE);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1){
        fprintf(stderr, "failed to open socket\n");
        return;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, '\0', sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr("0.0.0.0");

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1){
        fprintf(stderr, "couldn't set server options: %s\n", strerror(errno));
        return;
    }

    if (bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) == -1) {
        fprintf(stderr, "failed to bind to port %d %d\n", PORT, errno);
        return;
    }

    int backlog = 16;
    if (listen(sockfd, backlog) != 0){
        fprintf(stderr, "failed to listen on socket: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_in cliaddr;
    memset(&cliaddr, '\0', sizeof(cliaddr));
    int cliaddr_size = sizeof(cliaddr);

    fprintf(stderr, "starting to listen on %d (%d)\n", PORT, gettid());
    if (access(storage_path, F_OK) != 0){
        mkdir(storage_path, 0744);
        fprintf(stderr, "%s dir created\n", storage_path);
    }

    int session_counter = 0;
    pthread_mutex_init(&session_mutex, NULL);
    pthread_mutex_init(&max_sessions_lock, NULL);
    pthread_cond_init(&max_sessions_cond, NULL);

    psession new_session = NULL;
    while (TRUE) {
        pthread_mutex_lock(&max_sessions_lock);
        if (current_connections >= MAX_CONCURR) {
            fprintf(stderr, "getting in queue {%d}\n", current_connections);
            pthread_cond_wait(&max_sessions_cond, &max_sessions_lock);
        }
        pthread_mutex_unlock(&max_sessions_lock);

        int connfd = accept(sockfd, (struct sockaddr*)&cliaddr, &cliaddr_size);
        if (connfd > 0) {
            fprintf(stderr, "Got connection from %s\n", inet_ntoa(cliaddr.sin_addr));
            if (last_free_pg_chunk >= playground_top){
                new_session = session_chain;
                while (new_session != NULL && new_session->is_free != 1){
                    new_session = new_session->prev_session;
                }
                if (new_session != NULL){
                    new_session->sess_id = session_counter;
                    new_session->connfd = connfd;
                    new_session->is_free = 0;
                    fprintf(stderr, "Reusing session %016llx, chunk %016llx, ", new_session, new_session->chunk);
                }
                else {
                    fprintf(stderr, "Shouldn't be there\n");
                    raise(SIGSEGV);
                }
            } else if ((last_free_pg_chunk + CHUNK) <= playground_top){
                new_session = malloc(sizeof(struct session));
                new_session->sess_id = session_counter;
                new_session->connfd = connfd;
                new_session->chunk = last_free_pg_chunk;
                new_session->is_free = 0;
                new_session->recv_buffer = malloc(BUFFER+1);
                memset(new_session->recv_buffer, '\0', BUFFER+1);
                last_free_pg_chunk += CHUNK;

                fprintf(stderr, "Created session %016llx, chunk %016llx, ", new_session, new_session->chunk);
                
                if (session_chain == NULL){
                    new_session->next_session = NULL;
                    new_session->prev_session = NULL;
                    session_chain = new_session;
                } else {
                    new_session->next_session = NULL;
                    session_chain->next_session = new_session;
                    new_session->prev_session = session_chain;
                    session_chain = new_session;
                }
            } 

            if (last_free_store_chunk > session_store_top){
                last_free_store_chunk = session_store;
                while (((pstorage)last_free_store_chunk)->status != 0 && last_free_store_chunk <= session_store_top){
                    last_free_store_chunk += STORAGE;
                }
            }
            new_session->storage = last_free_store_chunk;
            memset(new_session->storage, '\0', STORAGE);
            new_session->storage->status = 1;
            last_free_store_chunk += STORAGE;
            fprintf(stderr, "storage %016llx\n", new_session->storage);

            pthread_create(&(new_session->thread), NULL, connection_handler, new_session);
            pthread_detach(new_session->thread);
            pthread_mutex_lock(&max_sessions_lock);
            session_counter++;
            current_connections++;
            pthread_mutex_unlock(&max_sessions_lock);
        }
        new_session = NULL;
    }
    close(sockfd);
    return;
}