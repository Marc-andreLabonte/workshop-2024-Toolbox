#include <stdio.h> 
#include <dlfcn.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write(), close()
#include <string.h>
#define MAX 2048
#define PORT 8080 
#define SA struct sockaddr 


// From some software which shall not be named, load your own code in there ..
void (*http_auth)(char *, char *, char *) = (void (*)(char *, char *, char *)) 0x1021398;
const char *error503 = "503 Server Error\r\n";
char * parse_request(char *);


char *parse_request(char *request) {
    char *querystring = strstr(request, "\r\n\r\n");
    return querystring;
}
// Function designed for chat between client and server. 
void ugly_http_server(int connfd) 
{ 
    char buff[MAX]; 
    char *querystring;
    int n; 
    // infinite loop for chat 
    for (;;) { 
        bzero(buff, MAX); 
   
        // read the message from client and copy it in buffer 
        read(connfd, buff, sizeof(buff)); 
        // print buffer which contains the client contents 
        //printf("From client: %s\t To client : ", buff); 
        querystring = parse_request(buff);
        if (querystring != NULL) {
            printf("needed a printf: %s", querystring);
            http_auth(buff, NULL, querystring);
        } else {
            bzero(buff, MAX); 
            write(connfd, error503, sizeof(error503)); 
        }
   
        //FIXME, send 200 OK!
        //write(connfd, buff, sizeof(buff)); 
   
        // if msg contains "Exit" then server exit and chat ended. 
        if (strncmp("exit", buff, 4) == 0) { 
            printf("Server Exit...\n"); 
            break; 
        } 
    } 
} 
   
// Driver function 
int main() 
{ 
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, cli; 


    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 

    // set reuse or otherwise get stuck on time_wait
    const int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        herror("setsockopt(SO_REUSEADDR) failed");

    bzero(&servaddr, sizeof(servaddr)); 
   
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
   
    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully binded..\n"); 
   
    // Now server is ready to listen and verification 
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        exit(0); 
    } 
    else
        printf("Server listening..\n"); 
    len = sizeof(cli); 
   
    // Accept the data packet from client and verification 
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("server accept failed...\n"); 
        exit(0); 
    } 
    else
        printf("server accept the client...\n"); 
   
    // Function for chatting between client and server 
    ugly_http_server(connfd); 
   
    // After chatting close the socket 
    close(sockfd); 
}

