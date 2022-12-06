/* COMP30023 project 2 
 * Student name: Cheng, Chun-Wen. Student ID: 1025323
 */

#include "helper1.h"
/******************************************************************/
int main(int argc, char** argv) {
	int sockfd, newsockfd;
	char domain_name[256];
	unsigned char *pkt_msg;
	socklen_t client_addr_size;
	struct sockaddr_storage client_addr;

	FILE *fp_w = fopen(LOG_FILE, "w");
	cache_t **cache;
	cache = (cache_t**)malloc(sizeof(*cache) * CACHE_NUM);
	assert(cache);
	for (int i = 0 ; i < CACHE_NUM ; i++) {
		cache[i] = NULL;
	}

	sockfd = create_server_sock(argc);
	// Listen on socket - means we're ready to accept connections,
	// incoming connection requests will be queued, man 3 listen
	if (listen(sockfd, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	while (1) {
		// Accept a connection - blocks until a connection is ready to be accepted
		// Get back a new file descriptor to communicate on
		client_addr_size = sizeof client_addr;
		newsockfd =
			accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
		if (newsockfd < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		
		unsigned char ch[2];
		read(newsockfd, ch, 1);
		read(newsockfd, ch + 1, 1);
		int sock_len = ch[0] << 8;
		sock_len += ch[1];
		pkt_msg = read_msg(sock_len, newsockfd);
		get_domain(domain_name, pkt_msg);
		print_time(fp_w);
		fprintf(fp_w, "requested %s\n", domain_name);
		fflush(fp_w);

		// check if pkt_msg is in AAAA format
		if (is_aaaa(pkt_msg)) {
			cache_t *in_cache = NULL;
			in_cache = search_cache(cache, pkt_msg);
			// if pkt_msg is already in cache 
			if (in_cache != NULL) {
				// update cache 
				update_cache(fp_w, in_cache->pkt_msg, in_cache->len, cache, 
					in_cache->expire_time - in_cache->arrive_time);
				// print log 
				print_in_cache(fp_w, in_cache);
				int length = (in_cache->len[0] << 8) + in_cache->len[1];
				// retreive msg 
				unsigned char *ini_pkt_msg = combine(ch, in_cache->pkt_msg, length);
				free(pkt_msg);
				// send retreived msg back to lowstream server
				write(newsockfd, ini_pkt_msg, length + 2);
				free(ini_pkt_msg);
			} else {
				// retreive pkt_msg 
				unsigned char *ini_pkt_msg = combine(ch, pkt_msg, sock_len);
				free(pkt_msg);
				// create client socket
				int c_sockfd = create_client_sock(argc, argv);
				// write to upstream server
				write(c_sockfd, ini_pkt_msg, sock_len + 2);
				free(ini_pkt_msg);
				// read length
				unsigned char len[2];
				read(c_sockfd, len, 1);
				read(c_sockfd, len + 1, 1);
				int new_sock_len = len[0] << 8;
				new_sock_len += len[1];		// length of new socket 
				unsigned char *new_pkt_msg; 
				new_pkt_msg = read_msg(new_sock_len, c_sockfd);
				close(c_sockfd);
				char domain_name_2[256];
				get_domain(domain_name_2, new_pkt_msg);
				// update cache and print log
				print_recieve(fp_w, new_pkt_msg, len, cache);
				// retreive new_pkt_msg
				unsigned char *reply_pkt_msg = combine(len, new_pkt_msg, new_sock_len);
				free(new_pkt_msg);
				// send back to lowstream server
				write(newsockfd, reply_pkt_msg, new_sock_len + 2);
				free(reply_pkt_msg);
			}
		// if not in AAAA form
		} else {
			// retreive pkt_msg
			unsigned char *ori_pkt_msg = combine(ch, pkt_msg, sock_len);
			fix_pkt(ori_pkt_msg);
			// send back to lowstream
			write(newsockfd, ori_pkt_msg, sock_len + 2);
			print_time(fp_w);
			fprintf(fp_w, "unimplemented request\n");
			fflush(fp_w);
			free(ori_pkt_msg);
		}
	}
	// free cache records 
	for (int i = 0 ; i < CACHE_NUM ; i++) {
		if (cache[i] != NULL) {
			free(cache[i]);
		}
	}
	free(cache);
	fclose(fp_w);
	close(sockfd);
	close(newsockfd);
	return 0;
}
