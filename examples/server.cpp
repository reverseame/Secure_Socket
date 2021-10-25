/*
    This is an example of a server program implementing Secure_Socket. 
    In the same folder you will find its client-side counterpart.

    @Authors:
        Razvan Raducu
        Ricardo J. Rodriguez

*/

#include "../src/Secure_Socket.hpp"

int main(){
    int port = 12345;
    std::string IP = "127.0.0.1";

    /* Open a server-side socket to wait for incoming connections.
    On the server side the path of both public and private RSA key files must be specified
    The NULL parameter corresponds to the IV (it is ignored on the server side) */
    Secure_Socket* socket = new Secure_Socket(port, IP, SERVER_SECURE_SOCKET, NULL, "./private_unencrypted.pem", "./public.pem"); 

    /* Whenever the server receives an incoming communications from the clients, the hybrid 
    encription is internally set up. Communication can now be carried on*/


    /* Secure socket sends and receives bytes (or unsigned char)). You can use
    vector or any other data structure capable of handling unsigned char. */
    std::vector<unsigned char> message;

    /* Strings must be converted to unsigned char* */
    std::string plaintext = "Hey, I'm the server and I'm sending you some info!";
    int message_len = plaintext.length()+1;
    message.resize(message_len);
    strcpy((char *)message.data(), plaintext.c_str());
    socket->secure_send(message.data(), message_len, 0);

    unsigned char buffer[100];
    int bytes_received = socket->secure_recv(buffer, 100, 0);
    printf("[+] Received from the client: %s\n[+] A total amount of %d bytes!\n", buffer, bytes_received);

    /* Or you can declare your string as unsigned char */
    unsigned char plaintext_2[] = "That's all for today! See you next time.";
    message_len = strlen((char*) plaintext_2)+1;
    socket->secure_send(plaintext_2, message_len, 0);


    free(socket);
}
