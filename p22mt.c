#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <signal.h>
#include <time.h>  // Para srand e rand()

#define CHARSET "0123456789abcdef"
#define NUM_CONSUMERS 8  // Número de consumidores
#define BLOCK_SIZE 32  // Tamanho do bloco de chaves
#define TARGET_HASH "032ddf76d2ad152cb5b391bfba3d24251a6548dc"  // Hash alvo

char base_str[65] = "403b3d4fcff56a92f335a0cf570e4xbxb17b2a6x867x86a84x0x8x3x3x3x7x3x";
int log_ativo = 0;  // 0: log desativado | 1: log ativado

#define LOG(fmt, ...) \
    do { \
        if (log_ativo) { \
            printf(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

unsigned long long totalChavesTestadas = 0;
unsigned char bintargethash[RIPEMD160_DIGEST_LENGTH];

volatile int found = 0;
volatile int producer_done = 0;

pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t prod_thread;
pthread_t cons_threads[NUM_CONSUMERS];  // Array de threads consumidoras

typedef struct {
    char keys[BLOCK_SIZE][65];
    int count;
} KeyBlock;

pthread_mutex_t block_mutex = PTHREAD_MUTEX_INITIALIZER;
KeyBlock block_queue[NUM_CONSUMERS];  // Cada consumidor possui seu próprio bloco

struct timespec start_time;

void happynation(const char *key) {
    FILE *file = fopen("happynationmt.txt", "a");
    if (file == NULL) {
        printf("Erro ao abrir o arquivo para escrita.\n");
        return;
    }

    fprintf(file, "%s\n", key);
    fflush(file);
    fclose(file);
    printf("Chave privada salva em 'happynationmt.txt'.\n");
}

// Função para obter o tempo atual em segundos
double get_time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

// Converte TARGET_HASH de hexadecimal para bytes
void hex_to_bytes(const char *hex_str, unsigned char *bytes) {
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        sscanf(&hex_str[i * 2], "%2hhx", &bytes[i]);
    }
}

void *producer(void *arg) {
    char *base_str = (char *)arg;
    char current_str[65];
    strcpy(current_str, base_str);

    int posicoes[65], totalPosicoes = 0;
    for (int i = 0; current_str[i] != '\0'; i++) {
        if (current_str[i] == 'x') {
            posicoes[totalPosicoes++] = i;
        }
    }

    srand(time(NULL));  // Inicializa o gerador de números pseudoaleatórios

    while (!found) {
        pthread_mutex_lock(&block_mutex);

        for (int consumer_id = 0; consumer_id < NUM_CONSUMERS; consumer_id++) {
            KeyBlock *block = &block_queue[consumer_id];
            block->count = 0;

            for (int j = 0; j < BLOCK_SIZE && !found; j++) {
                // Preenche posições marcadas com caracteres aleatórios
                for (int i = 0; i < totalPosicoes; i++) {
                    current_str[posicoes[i]] = CHARSET[rand() % strlen(CHARSET)];
                }

                strcpy(block->keys[block->count++], current_str);
            }

            LOG("[Producer] Bloco gerado para consumidor %d com %d chaves.\n", consumer_id, block->count);
        }

        pthread_mutex_unlock(&block_mutex);
        usleep(100);  // Evita busy-wait
    }

    producer_done = 1;
    return NULL;
}

void *consumer(void *arg) {
    int consumer_id = *(int *)arg;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char private_key[32], public_key[33], sha256_hash[32], ripemd160_hash[20];
    size_t public_key_len = 33;
    secp256k1_pubkey pubkey;

    while (!found) {
        pthread_mutex_lock(&block_mutex);
        KeyBlock *block = &block_queue[consumer_id];

        if (block->count == 0 && producer_done) {
            pthread_mutex_unlock(&block_mutex);
            break;
        }

        for (int i = 0; i < block->count && !found; i++) {
            const char *key = block->keys[i];
            pthread_mutex_unlock(&block_mutex);

            for (int j = 0; j < 32; j++) {
                sscanf(&key[j * 2], "%2hhx", &private_key[j]);
            }

            LOG("[Consumer %d] Verificando chave: %s\n", consumer_id, key);

            if (secp256k1_ec_pubkey_create(ctx, &pubkey, private_key) == 1) {
                secp256k1_ec_pubkey_serialize(ctx, public_key, &public_key_len, &pubkey, SECP256K1_EC_COMPRESSED);
                SHA256(public_key, public_key_len, sha256_hash);
                RIPEMD160(sha256_hash, 32, ripemd160_hash);

                pthread_mutex_lock(&count_mutex);
                totalChavesTestadas++;
                pthread_mutex_unlock(&count_mutex);

                if (memcmp(ripemd160_hash, bintargethash, RIPEMD160_DIGEST_LENGTH) == 0) {
                    printf("[Consumer %d] Hash encontrado! Chave privada: %s\n", consumer_id, key);
                    happynation(key);

                    struct timespec end_time;
                    clock_gettime(CLOCK_MONOTONIC, &end_time);
                    found = 1;
                    double elapsed_time = get_time_diff(start_time, end_time);
                    printf("Tempo total de execução: %.2f segundos\n", elapsed_time);
                    printf("Total de chaves testadas: %llu\n", totalChavesTestadas);
                    printf("Chaves por segundo: %.2f\n", totalChavesTestadas / elapsed_time);

                    exit(0);
                }
            }
            pthread_mutex_lock(&block_mutex);
        }

        block->count = 0;
        pthread_mutex_unlock(&block_mutex);
    }

    secp256k1_context_destroy(ctx);
    return NULL;
}

void handle_sigint(int sig) {
    found = 1;

    printf("[Main] Encerrando execução...\n");

    pthread_join(prod_thread, NULL);
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        pthread_join(cons_threads[i], NULL);
    }

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_time = get_time_diff(start_time, end_time);

    printf("Tempo total de execução: %.2f segundos\n", elapsed_time);
    printf("Total de chaves testadas: %llu\n", totalChavesTestadas);
    printf("Chaves por segundo: %.2f\n", totalChavesTestadas / elapsed_time);

    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--log") == 0) {
        log_ativo = 1;
        printf("[Main] Log ativado.\n");
    } else {
        printf("[Main] Log desativado. Use '--log' para ativar.\n");
    }

    signal(SIGINT, handle_sigint);
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    hex_to_bytes(TARGET_HASH, bintargethash);

    for (int i = 0; i < NUM_CONSUMERS; i++) {
        block_queue[i].count = 0;
    }

    int consumer_ids[NUM_CONSUMERS];

    pthread_create(&prod_thread, NULL, producer, base_str);
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        consumer_ids[i] = i;
        pthread_create(&cons_threads[i], NULL, consumer, &consumer_ids[i]);
    }

    pthread_join(prod_thread, NULL);
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        pthread_join(cons_threads[i], NULL);
    }

    printf("Execução concluída.\n");
    return 0;
}
