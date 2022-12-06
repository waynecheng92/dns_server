/* COMP30023 project 2 
 * Student name: Cheng, Chun-Wen. Student ID: 1025323
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>
/******************************************************************/
// #define CACHE
#define PORT_NUM "8053"
#define LOG_FILE "dns_svr.log"
#define CACHE_NUM 5
/******************************************************************/

typedef struct {
	time_t arrive_time;
	time_t expire_time;
	unsigned char *pkt_msg;
	unsigned char len[2];
} cache_t;

/******************************************************************/

int earliest_record(cache_t *cache[]);
void print_time(FILE *fp_w);
int find_sec_num(unsigned char *pkt_msg);
void get_domain(char *domain_buffer, unsigned char *pkt_msg);
bool is_aaaa(unsigned char *pkt_msg);
unsigned char* read_msg(int pkt_len, int newsockfd);
int create_server_sock(int argc);
int create_client_sock(int argc, char** argv);
unsigned char* combine(unsigned char* head, unsigned char* msg, int len);
void print_recieve(FILE *fp, unsigned char *pkt_msg, unsigned char *len_buff, cache_t *cache[]);
void fix_pkt(unsigned char *pkt);
bool same_msg(unsigned char *msg1, unsigned char *msg2);
bool is_expired(cache_t *cache);
void fix_ttl(cache_t *cache, int index);
cache_t *search_cache(cache_t *cache[], unsigned char* msg);
void print_in_cache(FILE *fp, cache_t *cache);
cache_t *create_cache(unsigned char *msg, unsigned char len[], int time);
void print_and_replace(FILE *fp, cache_t *replace, cache_t *cache[], int index);
void update_cache(FILE* fp, unsigned char *msg, unsigned char len[], cache_t *cache[], int time);
