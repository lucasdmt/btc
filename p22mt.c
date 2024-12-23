#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <signal.h>
#include <time.h>  // Para clock_gettime

#define CHARSET "0123456789abcdef"
#define QUEUE_SIZE 50
#define NUM_CONSUMERS 8  // Número de consumidores
#define TARGET_HASH "032ddf76d2ad152cb5b391bfba3d24251a6548dc"  // Hash alvo
char base_str[65] = "403b3d4fcff56a92f335a0cf570e4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x";

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
    char keys[QUEUE_SIZE][65];
    int front, rear, count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty, not_full;
} KeyQueue;

KeyQueue queue;
struct timespec start_time;

void happynation(const char *key) {
    FILE *file = fopen("happynationmt.txt", "a");
    if (file == NULL) {
        printf("Erro ao abrir o arquivo para escrita.\n");
        return;  // Não encerra o programa, apenas retorna
    }

    fprintf(file, "%s\n", key);
    fflush(file);
    fclose(file);
    printf("Chave privada salva em 'happynationmt.txt'.\n");
}

void salvarEstado(const char *current_str, int *indicesCharset, int totalPosicoes) {
    static pthread_mutex_t salvar_mutex = PTHREAD_MUTEX_INITIALIZER;  // Mutex para proteger a função

    pthread_mutex_lock(&salvar_mutex);  // Garante exclusão mútua

    FILE *file = fopen("estado.txt", "w");
    if (file) {
        printf("[Producer] Salvando estado...\n");

        fprintf(file, "Chave atual: %s\n", current_str);
        printf("Chave atual: %s\n", current_str);

        // Salvando o progresso em cada posição
        fprintf(file, "Progresso por posição: ");
        for (int i = 0; i < totalPosicoes; i++) {
            fprintf(file, "%d ", indicesCharset[i]);
        }
        fprintf(file, "\n");

        // Salvando o total de chaves testadas
        pthread_mutex_lock(&count_mutex);  // Protege totalChavesTestadas
        //fprintf(file, "Total chaves testadas: %llu\n", totalChavesTestadas);
        fprintf(file, "Total chaves testadas: 0");
        pthread_mutex_unlock(&count_mutex);

        fflush(file);  // Garante gravação imediata
        fclose(file);
        printf("[Producer] Estado salvo em estado.txt\n");
    } else {
        printf("[Producer] Erro ao salvar o estado.\n");
    }

    pthread_mutex_unlock(&salvar_mutex);
}
int restaurarEstado(char *current_str, int *indicesCharset, int totalPosicoes, unsigned long long *totalChaves) {
    FILE *file = fopen("estado.txt", "r");
    if (!file) {
        printf("[RestaurarEstado] Nenhum estado salvo encontrado.\n");
        return 0; // Não conseguiu restaurar
    }

    char linha[256];
    int linha_atual = 0;

    while (fgets(linha, sizeof(linha), file)) {
        if (linha_atual == 0) {
            // Lê a chave atual
            sscanf(linha, "Chave atual: %s", current_str);
        } else if (linha_atual == 1) {
            // Lê os índices de progresso
            char *token = strtok(linha + strlen("Progresso por posição: "), " ");
            for (int i = 0; token && i < totalPosicoes; i++) {
                indicesCharset[i] = atoi(token);
                token = strtok(NULL, " ");
            }
        } else if (linha_atual == 2) {
            // Lê o total de chaves testadas
            sscanf(linha, "Total chaves testadas: %llu", totalChaves);
        }
        linha_atual++;
    }

    fclose(file);
    printf("[RestaurarEstado] Estado restaurado com sucesso.\n");
    return 1; // Estado restaurado com sucesso
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

void init_queue(KeyQueue *q) {
    q->front = q->rear = q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void enqueue(KeyQueue *q, const char *key) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == QUEUE_SIZE) {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }
    strcpy(q->keys[q->rear], key);
    q->rear = (q->rear + 1) % QUEUE_SIZE;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

int dequeue(KeyQueue *q, char *key) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !found) {  // Verifica se a fila está vazia e se o programa ainda não terminou
        if (producer_done) {
            pthread_mutex_unlock(&q->mutex);
            return 0;
        }
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }

    if (found && q->count == 0) {  // Se o programa terminou e a fila está vazia, retorna 0
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }

    strcpy(key, q->keys[q->front]);
    q->front = (q->front + 1) % QUEUE_SIZE;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return 1;
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

    int indicesCharset[65] = {0};

    // Tenta restaurar o estado
    unsigned long long localChavesTestadas = 0;
    if (restaurarEstado(current_str, indicesCharset, totalPosicoes, &localChavesTestadas)) {
        pthread_mutex_lock(&count_mutex);
        totalChavesTestadas = localChavesTestadas; // Atualiza o total global com o restaurado
        pthread_mutex_unlock(&count_mutex);
        printf("[Producer] Estado restaurado. Continuando do ponto salvo.\n");
    } else {
        printf("[Producer] Nenhum estado salvo encontrado. Iniciando do começo.\n");
    }

    int save_counter = 0;  // Variável para controlar a frequência do salvamento
    while (!found) {
        for (int i = 0; i < totalPosicoes; i++) {
            current_str[posicoes[i]] = CHARSET[indicesCharset[i]];
        }
        enqueue(&queue, current_str);

        // Salva o estado a cada X5000000 iterações (ajuste conforme necessário)
        save_counter++;
        if (save_counter >= 7000000) {
            salvarEstado(current_str, indicesCharset, totalPosicoes);
            save_counter = 0;  // Reinicia o contador
        }

        int carry = 1; // Começamos com "vai-um"
        for (int i = totalPosicoes - 1; i >= 0; i--) { // Percorre de trás para frente
            if (carry) { // Só incrementa se houver carry
                indicesCharset[i]++; // Incrementa a posição atual
                if (indicesCharset[i] == strlen(CHARSET)) { // Se estourar o limite
                    indicesCharset[i] = 0; // Reseta a posição
                    carry = 1; // Propaga o carry para a próxima posição
                } else {
                    carry = 0; // Não há mais carry, pode parar
                }
            }
        }   
    }
    producer_done = 1;
    pthread_cond_broadcast(&queue.not_empty);
    return NULL;
}

void *consumer(void *arg) {
    int consumer_id = *(int *)arg;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char private_key[32], public_key[33], sha256_hash[32], ripemd160_hash[20];
    size_t public_key_len = 33;
    secp256k1_pubkey pubkey;

    char key[65];

    while (1) {
        if (found && queue.count == 0) {
            // Se o trabalho foi encontrado e a fila está vazia, sai da thread
            break;
        }

        // Continuar consumindo itens até a fila estar vazia e todos os consumidores tiverem terminado
        if (!dequeue(&queue, key)) {
            break;
        }

        for (int i = 0; i < 32; i++) {
            sscanf(&key[i * 2], "%2hhx", &private_key[i]);
        }
        LOG("[Consumer %d] Verificando chave: %s Chave N %llu\n", consumer_id, key, totalChavesTestadas);
        //sleep(1);
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

                exit(0);  // Encerra imediatamente o programa após encontrar a chave
            }
        }
    }

    secp256k1_context_destroy(ctx);
    return NULL;
}

void handle_sigint(int sig) {
    found = 1;  // Sinaliza que o programa deve parar

    // Aguardar até que todas as threads consumidoras terminem de consumir
    printf("[Main] Esperando as threads terminarem...\n");

    // Espera todas as threads consumidoras terminarem
    pthread_join(prod_thread, NULL);  // Aguarda a thread produtora terminar
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        pthread_join(cons_threads[i], NULL);  // Aguarda as threads consumidoras terminarem
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
    // Checa se o log deve ser ativado
    if (argc > 1 && strcmp(argv[1], "--log") == 0) {
        log_ativo = 1;  // Ativa log
        printf("[Main] Log ativado.\n");
    } else {
        printf("[Main] Log desativado. Use '--log' para ativar.\n");
    }

    signal(SIGINT, handle_sigint);
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    hex_to_bytes(TARGET_HASH, bintargethash);
    init_queue(&queue);

    int consumer_ids[NUM_CONSUMERS];
    
    pthread_create(&prod_thread, NULL, producer, base_str);
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        consumer_ids[i] = i + 1;
        pthread_create(&cons_threads[i], NULL, consumer, &consumer_ids[i]);
    }

    pthread_join(prod_thread, NULL);
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        pthread_join(cons_threads[i], NULL);
    }

    printf("Execução concluída.\n");
    return 0;
}