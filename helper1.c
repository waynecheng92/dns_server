/* COMP30023 project 2 
 * Student name: Cheng, Chun-Wen. Student ID: 1025323
 */

#include "helper1.h"
/******************************************************************/
// read the packet according to the length
unsigned char* read_msg(int pkt_len, int newsockfd) {
	unsigned char *pkt_msg = malloc(pkt_len);
	assert(pkt_msg);
	for (int i = 0 ; i < pkt_len ; i++) {
		read(newsockfd, pkt_msg + i, 1);
	}
	return pkt_msg;
}

// print time stamp to the file pointer
void print_time(FILE *fp_w) {
	time_t rawtime;
	struct tm *info;
	char buffer[80];
	time(&rawtime);
	info = localtime(&rawtime);
	strftime(buffer, 80, "%FT%T%z", info);
	fprintf(fp_w, "%s ", buffer);
	fflush(fp_w);
}


// return the number of section of domain name of the pkt_msg
int find_sec_num(unsigned char *pkt_msg) {
	int start_index = 12;
	int count = 0;
	int sec_len;
	// until reaches NULL
	while (pkt_msg[start_index] != 0) {
		sec_len = pkt_msg[start_index];
		start_index += (sec_len + 1);
		count++;
	}
	return count;
}

// assign the domain name of pkt_msg to domain_buffer
void get_domain(char *domain_buffer, unsigned char *pkt_msg) {
	int start_index = 12;
	int count = find_sec_num(pkt_msg);
	int sec_len;
	int n = 0;

	while (count) {
		sec_len = pkt_msg[start_index];
		for (int i = 0 ; i < sec_len ; i++) {
			domain_buffer[n] = pkt_msg[start_index + i + 1];
			n++;
		}
		// jump over the periods
		if (count != 1) {
			domain_buffer[n] = '.';
			n++;
		}
		start_index += sec_len + 1;
		count--;
	}
	domain_buffer[n] = '\0';
}

// check if pkt_msg is in AAAA format 
bool is_aaaa(unsigned char *pkt_msg) {
	int start_index = 12;
	int sec_len;
	while (pkt_msg[start_index] != 0) {
		sec_len = pkt_msg[start_index];
		start_index += (sec_len + 1);
	}
	if (pkt_msg[start_index + 1] == 0 && pkt_msg[start_index + 2] == 28) {
		return true;
	}
	else {
		return false;
	}
}

// create server socket
int create_server_sock(int argc) {
	int sockfd, re, s;
	struct addrinfo hints, *res;


	if (argc < 3) {
		fprintf(stderr, "ERROR, no port provided\n");
		exit(EXIT_FAILURE);
	}
	// Create address we're going to listen on (with given port number)
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;       // IPv4
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept
	// node (NULL means any interface), service (port), hints, res
	s = getaddrinfo(NULL, PORT_NUM, &hints, &res);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
	// Create socket
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Reuse port if possible
	re = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	// Bind address to the socket
	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(res);
	return sockfd;
}

// create client socket 
int create_client_sock(int argc, char** argv) {
	int sockfd, s;
	struct addrinfo hints, *servinfo, *rp;

	// Create address
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	// Get addrinfo of server. From man page:
	// The getaddrinfo() function combines the functionality provided by the
	// gethostbyname(3) and getservbyname(3) functions into a single interface
	s = getaddrinfo(argv[1], argv[2], &hints, &servinfo);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
	// Connect to first valid result
	// Why are there multiple results? see man page (search 'several reasons')
	// How to search? enter /, then text to search for, press n/N to navigate
	for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd == -1)
			continue;

		if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; // success

		close(sockfd);
	}
	if (rp == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo);

	return sockfd;
}

// conbine head and msg then return 
unsigned char* combine(unsigned char* head, unsigned char* msg, int len) {
	unsigned char *new_msg = malloc(len + 2);
	assert(new_msg);
	new_msg[0] = head[0];
	new_msg[1] = head[1];
	for (int i = 0 ; i < len ; i++) {
		new_msg[i + 2] = msg[i];
	}

	return new_msg;
}

// update cache and with newly arrived msg and print log on fp if msg is in AAAA form
void print_recieve(FILE *fp, unsigned char *pkt_msg, unsigned char *len_buff, cache_t *cache[]) {
	int start_index = 12;
	int sec_len;
	char domain[256];
	get_domain(domain, pkt_msg);
	while (pkt_msg[start_index] != 0) {
		sec_len = pkt_msg[start_index];
		start_index += (sec_len + 1);
	}
	start_index += 7;
	int ttl_index = start_index + 4;
	int time = 0;
	time += pkt_msg[ttl_index + 3];
	time += pkt_msg[ttl_index + 2] << 8;
	time += pkt_msg[ttl_index + 1] << 16;
	time += pkt_msg[ttl_index] << 24;
	update_cache(fp, pkt_msg, len_buff, cache, time);
	if (pkt_msg[start_index] == 0 && pkt_msg[start_index + 1] == 28) {
		start_index += 8;
		int len = pkt_msg[start_index] * 256;
		len += pkt_msg[start_index + 1];
		start_index += 2;
		char buffer[256];
		inet_ntop(AF_INET6, pkt_msg + start_index, buffer, 256);
		print_time(fp);
		fprintf(fp, "%s is at %s\n", domain, buffer);
		fflush(fp);
	}
}

// update the cache with the newly arrived msg
void update_cache(FILE* fp, unsigned char *msg, unsigned char len[], cache_t *cache[], int time) {
	if (!msg[6] && !msg[7]) {
		return;
	}
	cache_t *new = create_cache(msg, len, time);

	// replace if there exists an expired record 
	for (int i = 0 ; i < CACHE_NUM ; i++) {
		if (cache[i] != NULL && is_expired(cache[i])) {
			print_and_replace(fp, new, cache, i);
			return;
		}
	}
	// replace if there exists empty place in cache
	for (int i = 0 ; i < CACHE_NUM ; i++) {
		if (cache[i] == NULL) {
			cache[i] = new;
			return;
		}
	}

	// replace an earliest record if no record is expired
	int num = earliest_record(cache);
	print_and_replace(fp, new, cache, num);
}

// return the index of the earliest arrived cache record 
int earliest_record(cache_t *cache[]) {
	time_t earliest = cache[0]->arrive_time;
	int index = 0;
	for (int i = 0 ; i < CACHE_NUM ; i++) {
		if (cache[i] != NULL && cache[i]->arrive_time < earliest) {
			earliest = cache[i]->arrive_time;
			index = i;
		}
	}
	return index;
}

// print to fp to show the replacement then do the replacement
void print_and_replace(FILE *fp, cache_t *replace, cache_t *cache[], int index) {
	char old[256];
	char new[256];
	get_domain(old, cache[index]->pkt_msg);
	get_domain(new, replace->pkt_msg);
	fprintf(fp, "replacing %s by %s\n", old, new);
	fflush(fp);
	cache_t *temp = cache[index];
	cache[index] = replace;
	free(temp);
}

// store information of msg into cache_t variable then return
cache_t *create_cache(unsigned char *msg, unsigned char len[], int ttl) {
	time_t create_time;
	time_t exp_time;
	time(&create_time);
	exp_time = create_time + ttl;
	cache_t *new = (cache_t*)malloc(sizeof(*new));
	assert(new);
	new->pkt_msg = msg;
	new->len[0] = len[0];
	new->len[1] = len[1];
	new->arrive_time = create_time;
	new->expire_time = exp_time;
	return new;
}

// fix qr and rcode for pkt not in AAAA form
void fix_pkt(unsigned char *pkt) {
	int qr = 128;
	int rcode = 132;
	pkt[4] = (pkt[4] | qr);
	pkt[5] = (pkt[5] | rcode);
}

// return the msg in cache that matches msg and update its ID and TTL
cache_t *search_cache(cache_t *cache[], unsigned char* msg) {
	for (int i = 0 ; i < CACHE_NUM ; i++) {
		if (cache[i] != NULL && same_msg(msg, cache[i]->pkt_msg) && !is_expired(cache[i])) {
			cache[i]->pkt_msg[0] = msg[0];
			cache[i]->pkt_msg[1] = msg[1];
			int start_index = 12;
			int sec_len;
			while (cache[i]->pkt_msg[start_index] != 0) {
				sec_len = cache[i]->pkt_msg[start_index];
				start_index += (sec_len + 1);
			}
			start_index += 11;
			fix_ttl(cache[i], start_index);
			return cache[i];
		}
	}
	return NULL;
}

// deduct ttl of msg by time passed
void fix_ttl(cache_t *cache, int index) {
	time_t curr_time;
	time(&curr_time);
	int time_passed = curr_time - cache->arrive_time;

	int a, b, c, d;
	a = time_passed / (256 * 256 * 256);
	time_passed %= (256 * 256 * 256);
	b = time_passed / (256 * 256);
	time_passed %= (256 * 256);
	c = time_passed / 256;
	time_passed %= 256;
	d = time_passed;
	cache->pkt_msg[index] -= a;
	cache->pkt_msg[index + 1] -= b;
	cache->pkt_msg[index + 2] -= c;
	cache->pkt_msg[index + 3] -= d;
}

// return true if msg1 and msg2 are identical
bool same_msg(unsigned char *msg1, unsigned char *msg2) {
	int start_index = 12;
	while (msg1[start_index] != 0 && msg2[start_index] != 0) {
		if (msg1[start_index] != msg2[start_index]) {
			return false;
		}
		start_index++;
	}
	if (msg1[start_index] == 0 && msg2[start_index] == 0) {
		return true;
	}
	return false;
}

// return true if the cache is expired
bool is_expired(cache_t *cache) {
	time_t curr_time;

	time(&curr_time);
	// if current time is larger than expire time then its expired 
	if (curr_time - cache->expire_time > 0) {
		return true;
	}
	return false;
}

// print information about cache to fp
void print_in_cache(FILE *fp, cache_t *cache) {
	time_t arr_time = cache->arrive_time;
	time_t exp_time = cache->expire_time;
	struct tm *a_time;
	struct tm *e_time;
	char arrive_time[128];
	char expire_time[128];
	char domain[256];

	a_time = localtime(&arr_time);
	e_time = localtime(&exp_time);
	strftime(arrive_time, 128, "%FT%T%z", a_time);
	strftime(expire_time, 128, "%FT%T%z", e_time);
	get_domain(domain, cache->pkt_msg);
	fprintf(fp, "%s %s expires at %s\n", arrive_time, domain, expire_time);
	fflush(fp);
}
