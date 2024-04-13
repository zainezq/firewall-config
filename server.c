#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#define BUFFERLENGTH 256
#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

int asprintf(char **strp, const char *fmt, ...); 

/* displays error messages from system calls */
void error(char * msg) {
   perror(msg);
   exit(1);
};

struct threadArgs_t {
   int newsockfd;
   int threadIndex;
};

struct firewallRule_t {
    int ipaddr1[4];
    int ipaddr2[4];
    int port1;
    int port2;
    int *matchedIPs; // Dynamic array to store matched IP addresses
    int *matchedPorts; // Dynamic array to store matched ports
    int numMatches; // Number of matched queries
};


struct firewallRules_t {
   struct firewallRule_t * rule;
   struct firewallRules_t * next;
};


char * parseIPaddress(int * ipaddr, char * text, bool checkFile) {
   char * oldPos, * newPos;
   long int addr;
   int i;

   oldPos = text;
   for (i = 0; i < 4; i++) {
      if (oldPos == NULL || * oldPos < '0' || * oldPos > '9') {

         return NULL;
      }

      addr = strtol(oldPos, & newPos, 10);
      if (newPos == oldPos) {

         return NULL;
      }

      if ((addr < 0) || addr > 255) {
         ipaddr[0] = -1;
         return NULL;
      }

      if (i < 3) {
         if ((newPos == NULL) || ( * newPos != '.')) {
            ipaddr[0] = -1;
            return NULL;
         } else newPos++;

      } else if ((newPos == NULL) || (( * newPos != ' ') && ( * newPos != '-') && checkFile) || (!checkFile && ( * newPos != '\0'))) {
         ipaddr[0] = -1;
         return NULL;
      }

      ipaddr[i] = addr;
      oldPos = newPos;

   }
   return newPos;

}


char * parsePort(int * port, char * text) {
   char * newPos;

   if ((text == NULL) || ( * text < '0') || ( * text > '9')) {
      return NULL;
   }
   * port = strtol(text, & newPos, 10);
   if (newPos == text) {
      * port = -1;
      return NULL;
   }
   if (( * port < 0) || ( * port > 65535)) {
      * port = -1;
      return NULL;
   }
   return newPos;
}

int compareIPAddresses(const int *ipaddr1, const int *ipaddr2) {
    if (ipaddr1 == NULL || ipaddr2 == NULL) {
        return -1; // Indicates an error or invalid pointers
    }
    for (int i = 0; i < 4; i++) {
        if (ipaddr1[i] > ipaddr2[i]) {
            return 1;
        } else if (ipaddr1[i] < ipaddr2[i]) {
            return -1;
        }
    }
    return 0; // IP addresses are equal
}



struct firewallRule_t *readRule(char *line) {
    

    struct firewallRule_t *newRule = malloc(sizeof(struct firewallRule_t));

    if (newRule == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    newRule->matchedIPs = NULL;
    newRule->matchedPorts = NULL;
    newRule->numMatches = 0;

    char *pos = parseIPaddress(newRule->ipaddr1, line, true);

    if (pos == NULL || newRule->ipaddr1[0] == -1) {
        printf("IP address 1 is invalid\n");
        free(newRule);
        return NULL;
    }

    if (*pos == '-') {
        pos = parseIPaddress(newRule->ipaddr2, pos + 1, true);

        if (pos == NULL || newRule->ipaddr2[0] == -1) {
            printf("IP address 2 is invalid\n");
            free(newRule);
            return NULL;
        }

        if (compareIPAddresses(newRule->ipaddr1, newRule->ipaddr2) != -1) {
            printf("IP addresses are not in a valid range\n");
            free(newRule);
            return NULL;
        }
    } else {
        newRule->ipaddr2[0] = -1;
    }

    if (*pos != ' ') {
        printf("Expected a space character\n");
        free(newRule);
        return NULL;
    } else {
        pos++;
    }

    pos = parsePort(&(newRule->port1), pos);

    if (pos == NULL || newRule->port1 == -1) {
        printf("Port 1 is invalid\n");
        free(newRule);
        return NULL;
    }

    if (*pos == '\n' || *pos == '\0') {
        newRule->port2 = -1;
        return newRule;
    }

    if (*pos != '-') {
        printf("Expected a dash character\n");
        free(newRule);
        return NULL;
    }

    pos++;
    pos = parsePort(&(newRule->port2), pos);

    if (pos == NULL || newRule->port2 == -1) {
        printf("Port 2 is invalid\n");
        free(newRule);
        return NULL;
    }

    if (newRule->port2 <= newRule->port1) {
        printf("Port range is not valid\n");
        free(newRule);
        return NULL;
    }

    if (*pos == '\n' || *pos == '\0') {
        printf("Rule parsing reached the end of the string\n");
        return newRule;
    }

    printf("Rule parsing didn't reach the end of the string\n");
    free(newRule);
    return NULL;
}



/* this method is used to print to the server side.
void printLinkedList(struct firewallRules_t *list) {
    struct firewallRules_t *current = list;

    while (current != NULL) {
        printf("Rule: %d.%d.%d.%d", current->rule->ipaddr1[0], current->rule->ipaddr1[1],
               current->rule->ipaddr1[2], current->rule->ipaddr1[3]);

        if (current->rule->ipaddr2[0] != -1) {
            printf("-%d.%d.%d.%d", current->rule->ipaddr2[0], current->rule->ipaddr2[1],
                   current->rule->ipaddr2[2], current->rule->ipaddr2[3]);
        }

        printf(" %d", current->rule->port1);

        if (current->rule->port2 != -1) {
            printf("-%d", current->rule->port2);
        }

        printf("\n");

        // Check if there are matched queries before printing
        if (current->rule->numMatches > 0) {
            for (int i = 0; i < current->rule->numMatches; i++) {
                printf("Query: %d.%d.%d.%d %d\n", current->rule->matchedIPs[i * 4],
                       current->rule->matchedIPs[i * 4 + 1], current->rule->matchedIPs[i * 4 + 2],
                       current->rule->matchedIPs[i * 4 + 3], current->rule->matchedPorts[i]);
            }
        }

        current = current->next;
    }
}

*/ 

struct firewallRules_t * rulesList = NULL; // Initialize as an empty list
int isExecuted = 0;
int returnValue = 0; /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */

/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t {
   pthread_t pthreadInfo;
   pthread_attr_t attributes;
   int status;
};
struct threadInfo_t * serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock = PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;



void sendLinkedList(int newsockfd, struct firewallRules_t *list) {
    struct firewallRules_t *current = list;
    if (current == NULL) {
        return;  // No need to print anything
    }
    char *responseBuffer = malloc(BUFFERLENGTH);
    if (responseBuffer == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        exit(1);
    }
    size_t bufferSize = BUFFERLENGTH;
    responseBuffer[0] = '\0';
    while (current != NULL) {
        // Calculate the length needed for the string
        size_t len = snprintf(NULL, 0, "Rule: %d.%d.%d.%d", current->rule->ipaddr1[0], current->rule->ipaddr1[1],
                              current->rule->ipaddr1[2], current->rule->ipaddr1[3]);

        if (current->rule->ipaddr2[0] != -1) {
            len += snprintf(NULL, 0, "-%d.%d.%d.%d", current->rule->ipaddr2[0], current->rule->ipaddr2[1],
                            current->rule->ipaddr2[2], current->rule->ipaddr2[3]);
        }

        len += snprintf(NULL, 0, " %d", current->rule->port1);

        if (current->rule->port2 != -1) {
            len += snprintf(NULL, 0, "-%d", current->rule->port2);
        }

        // Check if there are matched queries before printing
        if (current->rule->numMatches > 0) {
            for (int i = 0; i < current->rule->numMatches; i++) {
                len += snprintf(NULL, 0, "Query: %d.%d.%d.%d %d\n", current->rule->matchedIPs[i * 4],
                                current->rule->matchedIPs[i * 4 + 1], current->rule->matchedIPs[i * 4 + 2],
                                current->rule->matchedIPs[i * 4 + 3], current->rule->matchedPorts[i]);
            }
        }

        // Allocate memory for the string
        char *toSend = malloc(len + 1); // Add 1 for the null terminator

        // Concatenate the strings
        snprintf(toSend, len + 1, "Rule: %d.%d.%d.%d", current->rule->ipaddr1[0], current->rule->ipaddr1[1],
                 current->rule->ipaddr1[2], current->rule->ipaddr1[3]);

        if (current->rule->ipaddr2[0] != -1) {
            snprintf(toSend + strlen(toSend), len + 1, "-%d.%d.%d.%d", current->rule->ipaddr2[0], current->rule->ipaddr2[1],
                     current->rule->ipaddr2[2], current->rule->ipaddr2[3]);
        }

        snprintf(toSend + strlen(toSend), len + 1, " %d", current->rule->port1);

        if (current->rule->port2 != -1) {
            snprintf(toSend + strlen(toSend), len + 1, "-%d", current->rule->port2);
        }

        // Check if there are matched queries before printing
        if (current->rule->numMatches > 0) {
            
            for (int i = 0; i < current->rule->numMatches; i++) {
                strcat(toSend, "\n");

                snprintf(toSend + strlen(toSend), len + 1, "Query: %d.%d.%d.%d %d", current->rule->matchedIPs[i * 4],
                         current->rule->matchedIPs[i * 4 + 1], current->rule->matchedIPs[i * 4 + 2],
                         current->rule->matchedIPs[i * 4 + 3], current->rule->matchedPorts[i]);
            }
        }
        // Check if reallocation is needed
        size_t requiredSize = strlen(responseBuffer) + strlen(toSend) + 2; // +2 for newline and null terminator
        if (bufferSize < requiredSize) {
            // Resize the buffer
            size_t newSize = bufferSize + 1024; // Increase by a fixed amount
            responseBuffer = realloc(responseBuffer, newSize);
            if (responseBuffer == NULL) {
                fprintf(stderr, "Failed to reallocate memory\n");
                exit(1);
            }
            bufferSize = newSize;
        }


        // Concatenate to the response buffer with a newline
        strcat(responseBuffer, toSend);

        // Update buffer size
        bufferSize += strlen(toSend) + 1;  // +1 for the newline character

        // Free the allocated memory
        free(toSend);
        if (current->next != NULL) {
            strcat(responseBuffer, "\n");
        }

        current = current->next;
    }


    // Send the data to the client
    write(newsockfd, responseBuffer, strlen(responseBuffer));

    // Free the final allocated memory
    free(responseBuffer);
}




// Function to validate IP address and port
int validatePortandIP(const char *ip) {
    char *position;
    for(int i=0; ip[i] != '\0'; i++ ){
      if(ip[i] == '-'){
         return 0; //inavlid
      }

    }
   return 1;

}


void freeRule(struct firewallRule_t * rule) {
   if (rule != NULL) {
      free(rule -> ipaddr1);
      free(rule -> ipaddr2);
      free(rule);
      
   }
}

int compareRules(const struct firewallRule_t *rule1, const struct firewallRule_t *rule2) { //for delete
    if (rule1 == NULL || rule2 == NULL) {
        printf("Debug: rule1 or rule2 is NULL\n");
        return 0;
    }

    // Compare IP addresses
    int ipComparison = compareIPAddresses(rule1->ipaddr1, rule2->ipaddr1);
    if (ipComparison != 0) {
        return ipComparison;
    }

    // Compare port ranges
    if (rule1->port1 < rule2->port1) {
            
        return -1;
    } else if (rule1->port1 > rule2->port1) {

        return 1;
    } else {
        // If port1 values are equal, compare port2
        if (rule1->port2 < rule2->port2) {

            return -1;
        } else if (rule1->port2 > rule2->port2) {

            return 1;
        }
    }

    return 0; // Rules are equal in all respects
}

int compareRulesforCheck(struct firewallRule_t *rule1, struct firewallRule_t *rule2) { //for check
    for (int i = 0; i < 4; i++) {
        if (rule1->ipaddr1[i] != -1 && rule1->ipaddr1[i] != rule2->ipaddr1[i]) {
            return -1;  // IP address doesn't match
        }
    }

    // Check if the port is within the range (inclusive)
    if (rule1->port1 != -1 && (rule1->port1 > rule2->port1 || rule1->port2 < rule2->port1)) {
        return -1;  // Port doesn't match
    }

    return 0;  // All fields match
}





void * processRequest(void * args) {
   struct threadArgs_t * threadArgs;
   char buffer[BUFFERLENGTH];
   int n;
   //int tmp;

   threadArgs = (struct threadArgs_t * ) args;
   bzero(buffer, BUFFERLENGTH);
   n = read(threadArgs -> newsockfd, buffer, BUFFERLENGTH - 1);
   if (n < 0)
   error("ERROR reading from socket");
   printf("Received request: %s\n", buffer);

   char requestType = buffer[0]; // Extract the first character
   char requestParams[BUFFERLENGTH - 2]; // Leave space for the letter and a space
   strcpy(requestParams, buffer + 2);

   // Handle different request types
   if (requestType == 'A') {
        pthread_mutex_lock(&threadEndLock);

      printf("Received request to add a rule\n");
      printf("Request parameters: %s\n", requestParams);

      // Use the readRule function to parse the rule

      struct firewallRule_t * newRule = readRule(requestParams);
      if (newRule == NULL) {
         fprintf(stderr, "Invalid rule format, exiting\n");
         exit(1);
      }
      else{
      // to print out the parsed rule
      /*
      printf("Parsed rule:\n");
      printf("IP Address 1: %d.%d.%d.%d\n", newRule -> ipaddr1[0], newRule -> ipaddr1[1], newRule -> ipaddr1[2], newRule -> ipaddr1[3]);
      if (newRule -> ipaddr2[0] != -1) {
         printf("IP Address 2: %d.%d.%d.%d\n", newRule -> ipaddr2[0], newRule -> ipaddr2[1], newRule -> ipaddr2[2], newRule -> ipaddr2[3]);
      }
      printf("Port 1: %d\n", newRule -> port1);
      if (newRule -> port2 != -1) {
         printf("Port 2: %d\n", newRule -> port2);
      }
      */

      struct firewallRules_t * newRuleNode = (struct firewallRules_t * ) malloc(sizeof(struct firewallRules_t));
      if (newRuleNode == NULL) {
         fprintf(stderr, "Memory allocation failed\n");
         exit(1);
      }
      newRuleNode -> rule = (struct firewallRule_t * ) malloc(sizeof(struct firewallRule_t));
      if (newRuleNode -> rule == NULL) {
         fprintf(stderr, "Memory allocation failed\n");
         exit(1);
      }

      newRuleNode->rule->matchedIPs = NULL; // Initialise to NULL
      newRuleNode->rule->matchedPorts = NULL; // Initialise to NULL
      newRuleNode->rule->numMatches = 0; // Initialise to 0

      memcpy(newRuleNode -> rule, newRule, sizeof(struct firewallRule_t));
      newRuleNode -> next = rulesList;
      rulesList = newRuleNode;

      free(newRule);
      const char * response = "Rule added";
      write(threadArgs -> newsockfd, response, strlen(response));
      }
          pthread_mutex_unlock(&threadEndLock);

   } 


else if (requestType == 'C') {
        pthread_mutex_lock(&threadEndLock);

    printf("Received request to check connection\n");
    printf("Request parameters: %s\n", requestParams);

    // Parse the client request to get the IP address and port
    if (validatePortandIP(requestParams) != 1) {
        const char *response = "Illegal IP address or port specified";
        write(threadArgs->newsockfd, response, strlen(response));
    } else {
        struct firewallRule_t *CRule = readRule(requestParams);
        if (CRule == NULL) {
            fprintf(stderr, "Illegal IP address or port specified\n");
            const char *response = "Illegal IP address or port specified";
            write(threadArgs->newsockfd, response, strlen(response));
        } else {
            int connectionAccepted = 0;

            // Iterate through the list of rules
            struct firewallRules_t *current = rulesList;
            while (current != NULL) {
                if(((compareRulesforCheck(current -> rule, CRule))&&(compareRules(current ->rule, CRule))) == 0){
                    const char *response = "Connection accepted";
                    write(threadArgs->newsockfd, response, strlen(response));
                    connectionAccepted = 1;
                    
                    // Increment the size of matchedIPs and matchedPorts arrays
                    int nextIndex = current->rule->numMatches; // Get the next available index

                    // Resize the arrays
                    current->rule->matchedIPs = realloc(current->rule->matchedIPs, (nextIndex + 1) * sizeof(int) * 4);
                    current->rule->matchedPorts = realloc(current->rule->matchedPorts, (nextIndex + 1) * sizeof(int));


                    if (current->rule->matchedIPs != NULL && current->rule->matchedPorts != NULL) {

                        // Add the IP address and port to the arrays
                        

                        // Split and store the IP address into matchedIPs
                        current->rule->matchedIPs[nextIndex * 4] = CRule->ipaddr1[0];
                        current->rule->matchedIPs[nextIndex * 4 + 1] = CRule->ipaddr1[1];
                        current->rule->matchedIPs[nextIndex * 4 + 2] = CRule->ipaddr1[2];
                        current->rule->matchedIPs[nextIndex * 4 + 3] = CRule->ipaddr1[3];

                        // Store the port in matchedPorts
                        current->rule->matchedPorts[nextIndex] = CRule->port1;

                        // Increment the number of matched queries for this rule
                        current->rule->numMatches++;
                    } else {
                        // Handle realloc failure
                        fprintf(stderr, "Failed to reallocate memory\n");
                        exit(1);
                    }

                    break;
                }

                current = current->next;
            }

            // Free the previously allocated memory for CRule
            free(CRule->matchedIPs);
            free(CRule->matchedPorts);
            free(CRule);

            // Free the previously allocated memory outside the loop if necessary
            if (connectionAccepted == 0) {
                const char *response = "Connection rejected";
                free(CRule);
                write(threadArgs->newsockfd, response, strlen(response));
            }
        }
    }
        pthread_mutex_unlock(&threadEndLock);

}



else if (requestType == 'D') {
        pthread_mutex_lock(&threadEndLock);

    printf("Received request to delete a rule\n");
    printf("Request parameters: %s\n", requestParams);

    // Parse the client request and create a rule structure
    struct firewallRule_t *deleteRule = readRule(requestParams);

    if (deleteRule == NULL) {
        const char *response = "Rule invalid";
        write(threadArgs->newsockfd, response, strlen(response));
    } else {
        // Initialize pointers
        struct firewallRules_t *current = rulesList;
        struct firewallRules_t *prev = NULL;

        // Start the iteration
        int ruleFound = 0; // Flag to indicate if the rule is found
        while (current != NULL) {
            // Examine the content of the current node
            if (compareRules(current->rule, deleteRule) == 0) {
                // Found a matching rule to delete
                ruleFound = 1;
                if (prev != NULL) {
                    // Update the next pointer of the previous node
                    prev->next = current->next;
                } else {
                    // If the first node matches, update the list pointer
                    rulesList = current->next;
                }

                // Free memory of the rule in the current node
                freeRule(current->rule);
                free(current->rule->matchedIPs);
                free(current->rule->matchedPorts);

                // Free memory of the current node itself
                free(current);
                if (deleteRule != NULL) {
                free(deleteRule);
                    }   

                ruleFound = 1; // Rule found and deleted
                break;
            }

            // Move to the next node
            prev = current;
            current = current->next;
        }

        if (ruleFound) {
            const char *response = "Rule deleted";
            write(threadArgs->newsockfd, response, strlen(response));
        } else {
            const char *response = "Rule not found";
            free(deleteRule);
            write(threadArgs->newsockfd, response, strlen(response));
        }
    }
        pthread_mutex_unlock(&threadEndLock);

}



else if (requestType == 'L') {
        pthread_mutex_lock(&threadEndLock);

    printf("Received request to list rules\n");
   //printLinkedList(rulesList);
   sendLinkedList(threadArgs -> newsockfd, rulesList);
       pthread_mutex_unlock(&threadEndLock);

}

   
   else {
      const char *response = "Illegal request";
      write(threadArgs->newsockfd, response, strlen(response));
   }


      serverThreads[threadArgs -> threadIndex].status = THREAD_FINISHED;
   pthread_cond_signal( & threadCond);

   close(threadArgs -> newsockfd); /* important to avoid memory leak */
   free(threadArgs);
   pthread_exit( & returnValue);
}


int findThreadIndex() {
   int i, tmp;

   for (i = 0; i < noOfThreads; i++) {
      if (serverThreads[i].status == THREAD_AVAILABLE) {
         serverThreads[i].status = THREAD_IN_USE;
         return i;
      }
   }
    /* no available thread found; need to allocate more threads */
   pthread_rwlock_wrlock( & threadLock);
   serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
   noOfThreads = noOfThreads + THREADS_ALLOCATED;
   pthread_rwlock_unlock( & threadLock);
   if (serverThreads == NULL) {
      fprintf(stderr, "Memory allocation failed\n");
      exit(1);
   }
   /* initialise thread status */
   for (tmp = i + 1; tmp < noOfThreads; tmp++) {
      serverThreads[tmp].status = THREAD_AVAILABLE;
   }
   serverThreads[i].status = THREAD_IN_USE;
   return i;
}

void * waitForThreads(void * args) {
   int i, res;
   while (1) {
      pthread_mutex_lock( & threadEndLock);
      pthread_cond_wait( & threadCond, & threadEndLock);
      pthread_mutex_unlock( & threadEndLock);

      pthread_rwlock_rdlock( & threadLock);
      for (i = 0; i < noOfThreads; i++) {
         if (serverThreads[i].status == THREAD_FINISHED) {
            res = pthread_join(serverThreads[i].pthreadInfo, NULL);
            if (res != 0) {
               fprintf(stderr, "thread joining failed, exiting\n");
               exit(1);
            }
            serverThreads[i].status = THREAD_AVAILABLE;
         }
      }
      pthread_rwlock_unlock( & threadLock);
   }
}



int main(int argc, char * argv[]) {

   socklen_t clilen;
   int sockfd, portno;
   struct sockaddr_in6 serv_addr, cli_addr;
   int result;
   pthread_t waitInfo;
   pthread_attr_t waitAttributes;

   if (argc < 2) {
      fprintf(stderr, "ERROR, no port provided\n");
      exit(1);
   }

   printf("server is starting... \n");

   /* create socket */
   sockfd = socket(AF_INET6, SOCK_STREAM, 0);
   if (sockfd < 0)
      error("ERROR opening socket");
   bzero((char * ) & serv_addr, sizeof(serv_addr));
   portno = atoi(argv[1]);
   serv_addr.sin6_family = AF_INET6;
   serv_addr.sin6_addr = in6addr_any;
   serv_addr.sin6_port = htons(portno);

   /* bind it */
   if (bind(sockfd, (struct sockaddr * ) & serv_addr,
         sizeof(serv_addr)) < 0)
      error("ERROR on binding");

   /* ready to accept connections */
   listen(sockfd, 5);
   clilen = sizeof(cli_addr);

   /* create separate thread for waiting  for other threads to finish */
   if (pthread_attr_init( & waitAttributes)) {
      fprintf(stderr, "Creating initial thread attributes failed!\n");
      exit(1);
   }

   result = pthread_create( & waitInfo, & waitAttributes, waitForThreads, NULL);
   if (result != 0) {
      fprintf(stderr, "Initial Thread creation failed!\n");
      exit(1);
   }

   /* now wait in an endless loop for connections and process them */
   while (1) {

      struct threadArgs_t * threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
      int threadIndex;

      threadArgs = malloc(sizeof(struct threadArgs_t));
      if (!threadArgs) {
         fprintf(stderr, "Memory allocation failed!\n");
         exit(1);
      }

      /* waiting for connections */
      threadArgs -> newsockfd = accept(sockfd,
         (struct sockaddr * ) & cli_addr, &
         clilen);
      if (threadArgs -> newsockfd < 0)
         error("ERROR on accept");

      /* create thread for processing of connection */
      threadIndex = findThreadIndex();
      threadArgs -> threadIndex = threadIndex;
      if (pthread_attr_init( & (serverThreads[threadIndex].attributes))) {
         fprintf(stderr, "Creating thread attributes failed!\n");
         exit(1);
      }

      result = pthread_create( & (serverThreads[threadIndex].pthreadInfo), & (serverThreads[threadIndex].attributes), processRequest, (void * ) threadArgs);
      if (result != 0) {
         fprintf(stderr, "Thread creation failed!\n");
         exit(1);
      }
    
   }


}