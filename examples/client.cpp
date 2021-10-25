/*
    This is an example of a client program implementing Secure_Socket. 
    In the same folder you will find its server-side counterpart.

    @Authors:
        Razvan Raducu
        Ricardo J. Rodriguez

*/

#include "../src/Secure_Socket.hpp"

int main(){
    int port = 12345;
    std::string IP = "127.0.0.1";
    
    /* Create the server-side Secure Socket. If no IV is specified, a random one will be generated */
    Secure_Socket* socket = new Secure_Socket(port, IP, CLIENT_SECURE_SOCKET); //init_vector, key_len and socket_type have default values

    /* Example of predefined IV */
    //unsigned char init_vector[] = "EXAMPLE_INITIALIZATION_VECTOR_LARGE_ENOUGH";
    //Secure_Socket* socket = new Secure_Socket(port, IP, CLIENT_SECURE_SOCKET, init_vector); //key_len and socket_type have default values

    unsigned char buffer[100];
    int bytes_received = socket->secure_recv(buffer, 100, 0);
    printf("[+] Received from the server: %s\n[+] A total amount of %d bytes!\n", buffer, bytes_received);

    unsigned char plaintext[] = "I'm the client. Sending you back a response!";
    int plaintext_len = strlen((char*)plaintext) + 1;
    socket->secure_send(plaintext, plaintext_len, 0);

    bytes_received = socket->secure_recv(buffer, 100, 0);
    printf("[+] Received from the server: %s\n[+] A total amount of %d bytes!\n", buffer, bytes_received);

    free(socket);
}