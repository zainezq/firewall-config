#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define BUFFERLENGTH 256
#define CHUNK_SIZE 1024

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
};


int main(int argc, char *argv[])
{

    if (argc < 4) {
       fprintf (stderr, "Usage %s <serverHost> <serverPort> <requestType> <ipaddress> <port>\n", argv[0]);
       exit(1);
    }

    char *serverHost = argv[1];
    char *serverPort = argv[2];
    char *requestType = argv[3];

    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;
    char request[BUFFERLENGTH];

       /* Obtain address(es) matching host/port */
   /* code taken from the manual page for getaddrinfo */
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
	exit(EXIT_FAILURE);
    }


    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */
    
    for (rp = result; rp != NULL; rp = rp->ai_next) {
	sockfd = socket(rp->ai_family, rp->ai_socktype,
			rp->ai_protocol);
	if (sockfd == -1)
	    continue;

	if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
	    break;                  /* Success */

	close(sockfd);
    }

    if (rp == NULL) {               /* No address succeeded */
	fprintf(stderr, "Could not connect\n");
	exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);           /* No longer needed */

    /* prepare message */
    bzero (request, BUFFERLENGTH);

    if (strcmp(requestType, "A") == 0) {
        // Add a rule
        if (argc !=6) {
            fprintf(stderr, "Invalid argument count for request type A\n");
            close(sockfd);
            exit(1);
        }
        snprintf(request, BUFFERLENGTH, "A %s %s", argv[4], argv[5]);

        
    } else if (strcmp(requestType, "C") == 0) {
        // Check IP address and port
        if (argc != 6) {
            fprintf(stderr, "Invalid argument count for request type C\n");
            close(sockfd);
            exit(1);
        }
        snprintf(request, BUFFERLENGTH, "C %s %s", argv[4], argv[5]);


    } else if (strcmp(requestType, "D") == 0) {
        // Delete a rule
        if (argc != 6) {
            fprintf(stderr, "Invalid argument count for request type D\n");
            close(sockfd);
            exit(1);
        }
        snprintf(request, BUFFERLENGTH, "D %s %s", argv[4], argv[5]);


    } else if (strcmp(requestType, "L") == 0) {
        // List rules
        if (argc != 4) {
            fprintf(stderr, "Invalid argument count for request type D\n");
            close(sockfd);
            exit(1);
        }
        snprintf(request, BUFFERLENGTH, "L");
    } else {
        fprintf(stderr, "Invalid request type\n");
        close(sockfd);
        exit(1);

    }

    /* send message */
    n = write(sockfd, request, strlen(request));

    if (n < 0)
        error("ERROR writing to socket");
    bzero(request, BUFFERLENGTH);

    /* wait for reply */
    char *responseBuffer = malloc(CHUNK_SIZE);
    if (responseBuffer == NULL)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    size_t bufferSize = CHUNK_SIZE;

    size_t totalBytesRead = 0;
    ssize_t bytesRead;

    do
    {
        bytesRead = read(sockfd, responseBuffer + totalBytesRead, CHUNK_SIZE - 1);
        if (bytesRead < 0)
        {
            error("ERROR reading from socket");
        }
        else if (bytesRead > 0)
        {
            totalBytesRead += bytesRead;

            // Check if more memory is needed
            if (totalBytesRead + CHUNK_SIZE > bufferSize)
            {
                bufferSize += CHUNK_SIZE;
                responseBuffer = realloc(responseBuffer, bufferSize);
                if (responseBuffer == NULL)
                {
                    fprintf(stderr, "Failed to reallocate memory\n");
                    exit(EXIT_FAILURE);
                }
            }
        }
    } while (bytesRead > 0);

    // Null-terminate the received data
    responseBuffer[totalBytesRead] = '\0';

    // Process the response
    if (totalBytesRead > 0) {
    printf("%s\n", responseBuffer);
} else {
    // The list is empty, no need to print anything
}

    // Free the allocated memory
    free(responseBuffer);

    close(sockfd);
    return 0;
}
