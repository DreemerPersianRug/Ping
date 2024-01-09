#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define DEFAULT_COLOR "\033[00m"

#define ERROR "\n[Error]: "
#define WARNING "\n[Warning]: "
#define SUCCESS "\n[Successfully]: "

#define PING_DATA_SIZE 64
#define TIMESTAMP_MODE CLOCK_REALTIME_COARSE
#define MAX_WAIT_TIME 5
#define MAX_NO_PACKETS 3

struct package {
    struct icmp header;
    char data[PING_DATA_SIZE];   
};

struct package_ip {
    struct ip ip_header;
    package ping_pkg;
};

long timestamp() {
    struct timespec time;
    clock_gettime(TIMESTAMP_MODE, &time);
    long time_ms = time.tv_sec * 1000 + (time.tv_nsec / 1.0e6);
    return time_ms;
}

unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned int sum = 0;
    unsigned short answer;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += static_cast<unsigned char>(*buf);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

static void prepare_icmp_pkg(package *ping_pkg) {
    unsigned int packet_size = sizeof(package);
    memset(ping_pkg, 0, packet_size);
    srand(time(NULL));
    const short random_id = rand();
    ping_pkg -> header.icmp_hun.ih_idseq.icd_id = random_id; 
    ping_pkg -> header.icmp_type = ICMP_ECHO;                
    ping_pkg -> header.icmp_hun.ih_idseq.icd_seq = 0;        
    ping_pkg -> header.icmp_cksum = calculate_checksum(reinterpret_cast<unsigned short*>(ping_pkg), packet_size);
}

int ping(const char* ip, const unsigned long timeout, unsigned long* time) {
    if (ip == NULL || timeout == 0) {
        std::cout << RED << ERROR << DEFAULT_COLOR 
            << "Uncorrect IP: " << ip << " or null timeout!" << std::endl;
        return -1;
    }

    package ping_pkg;
    prepare_icmp_pkg(&ping_pkg);
    const short reply_id = ping_pkg.header.icmp_hun.ih_idseq.icd_id;

    struct sockaddr_in to_addr;
    to_addr.sin_family = AF_INET;
    if (!inet_aton(ip, (struct in_addr*)&to_addr.sin_addr.s_addr)) {
        std::cout << RED << ERROR << DEFAULT_COLOR 
            << "Inet_Aton error!" << std::endl;
        return -1;
    }

    if (!strcmp(ip, "255.255.255.255") || to_addr.sin_addr.s_addr == 0xFFFFFFFF) {
        std::cout << RED << ERROR << DEFAULT_COLOR 
            << "The IP address is broadcast!" << std::endl;        
        return -1;
    }

    const int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        std::cout << RED << ERROR << DEFAULT_COLOR
            << "Establishing socket error!" << std::endl;
        return -1;
    }

    const unsigned long start_time = timestamp();
    const socklen_t socklen = sizeof(struct sockaddr_in);
    if (sendto(sock, &ping_pkg, sizeof(ping_pkg), 0, (struct sockaddr*)&to_addr, socklen) <= 0) {
        close(sock);
        std::cout << RED << ERROR << DEFAULT_COLOR
            << "Error sending packet!" << std::endl;
        return -1;
    }

    int result = -1;
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    while(true) {
        fd_set rfd;
        FD_ZERO(&rfd);
        FD_SET(sock, &rfd);

        int n = select(sock + 1, &rfd, 0, 0, &tv);
        if (n == 0) {
            result = 1;
            break;
        }
        if (n < 0) {
            break;
        }
        const unsigned long elapsed_time = (timestamp() - start_time);
        if (elapsed_time > timeout) {
            result = 1;
            break;
        } else {
            const int new_timeout = timeout - elapsed_time;
            tv.tv_sec = new_timeout / 1000;
            tv.tv_usec = (new_timeout % 1000) * 1000;
        }

        if (FD_ISSET(sock, &rfd)) {
            package_ip ip_pkg;
            struct sockaddr_in from_addr;
            socklen_t socklen = sizeof(struct sockaddr_in);
            if (recvfrom(sock, &ip_pkg, sizeof(package), 0, (struct sockaddr*)&from_addr, &socklen) <= 0) {
                break;
            }
            if (to_addr.sin_addr.s_addr == from_addr.sin_addr.s_addr
                    && reply_id == ip_pkg.ping_pkg.header.icmp_hun.ih_idseq.icd_id) {
                if (time != NULL) {
                    *time = elapsed_time;
                }
                result = 0;
                break;
            }
        }
    }
    close(sock);
    return result;
}

int main(int argc, char** argv) {
	if(argc < 3) {
	    std::cout << RED << ERROR << DEFAULT_COLOR
            << "Please use the following syntax: " << BLUE << "./ping " << GREEN 
            << "<host> " << MAGENTA << "<timeout>" << std::endl;
		return -1;
	}

	const unsigned long timeout = atoi(argv[2]);
	const char* const host = argv[1];
	unsigned long time = 0;

    while(true) {
        const int result = ping(host, timeout, &time);

        if (result == -1) {
            std::cout << RED << ERROR << DEFAULT_COLOR
                << "Host is not available!" << std::endl;
            return -1;
        } else if (result == 1) {
            std::cout << YELLOW << WARNING << DEFAULT_COLOR
                << "Timeout!" << std::endl;
        } else {
            std::cout << GREEN << SUCCESS << DEFAULT_COLOR
                << "Ping host = " << host << ", Timeout = " << timeout << "." << std::endl
                << "Time = " << time << "." << std::endl;
        }
        sleep(1);
    }
    return 0;
}