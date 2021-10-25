/*  
 About: License
    
    This file is part of Secure_Socket <https://github.com/RazviOverflow/SecureSocket>.

    Secure_Socket is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Secure_Socket is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Secure_Socket.  If not, see <https://www.gnu.org/licenses/>.

 About: Authors
        - Razvan Raducu  (University of Zaragoza)  
        - Ricardo J. Rodriguez  (University of Zaragoza)

 About: Code
        Secure_Socket's code can be found in <its public repository: https://github.com/RazviOverflow/SecureSocket>

*/

#ifndef _SECURE_SOCKET_H_
#define _SECURE_SOCKET_H_

#include <cstddef>
#include <string>
#include <sys/types.h>
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
#include <winsock2.h>
#include <ws2tcpip.h>
#include <rijndael.h>
#include <rsa.h>
#include <aes.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <modes.h>
#include <hex.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#endif


#include "Key.hpp"

/**
 * Constant: SERVER_SECURE_SOCKET
 * Global constant representing the server secure socket type. It is equal to 0.
 */
extern const int SERVER_SECURE_SOCKET; 

/**
 * Constant: CLIENT_SECURE_SOCKET
 * Global constant representing the client secure socket type. It is equal to 1.
 */
extern const int CLIENT_SECURE_SOCKET;

/**
 * Constant: INT_SIZE
 * Global constant defining a fixed size for the int type. It is equal to sizeof(int32_t) (that is, 4).
 */
extern const int INT_SIZE;

//Forward declaring Key so it can be referenced.
class Key;

/**
 * Title: Secure_Socket 
 *  Class used to create, use, manage and close the secure socket. The secure 
 *  channel (hybrid encryption) is created automatically. Once the
 *  socket is created, the communication can be carried on and the bytes sent
 * will be automatically encrypted while the bytes received will be automatically
 * decrypted.
 * 
 *  
 */
class Secure_Socket{
    public:
        /**
         * 
         * Constructor: Secure_Socket
         *  Default constructor to create the Secure_Socket object.
         * 
         * Parameters:
         * 
         *  port - The port to listen or connect to.
         *  IP - The IP to listen or connect to.
         *  socket_type - The type (server or client) of socket to create. 
         *  IV - The AES Initialization Vector (IV) to use. Default value is NULL.
         * If the IV is NULL, a random one will be generated and used, otherwise
         * the specified one will be used.
         *  RSA_private_key_path - The path of the private RSA key in .PEM format.
         *  RSA_public_key_path - The path of the public RSA key in .PEM format.
         *  key_len - The length of the AES key. Default value: 32.
         *  
         * Returns:
         * 
         *  Reference (pointer) to the secure socket object.
         */ 
        Secure_Socket(int port, std::string IP, int socket_type = SERVER_SECURE_SOCKET, unsigned char* IV = NULL, std::string RSA_private_key_path = "", std::string RSA_public_key_path = "", int key_len = 32);

        /**
         * Destructor: ~Secure_Socket
         *  The destructor will clean up (free) all allocated memory and close
         * the socket.
         */
        ~Secure_Socket();

        /**
         * Function: secure_send
         * Sends data over the secure socket. Sends _len_ bytes from _buffer_.
         * Overwrites the contents of _buffer_ with the encrypted bytes.
         * 
         * Parameters:
         * 
         *  buffer - Buffer from which the bytes will be sent. Will be 
         * overwritten with the result of the encryption.
         *  len - Length of the buffer or number of bytes to send.
         *  flags - Socket's flags. It is formed by ORing one or more values specified <here https://man7.org/linux/man-pages/man2/recv.2.html>.
         * 
         * Returns:
         *  The number of bytes sent.
         */
        ssize_t secure_send(unsigned char* buffer, size_t len, int flags = 0);

        /**
         * Function: secure_recv
         * Receives data from the secure socket. Receives _len_ bytes into _buffer_.
         * Overwrites the contents of _buffer_ with the decrypted bytes.
         * 
         * Parameters:
         * 
         * buffer - Buffer where the bytes will be received into. The result of
         * decrypting them will be stored in this buffer. 
         * len - Length of the buffer or number of bytes to receive.
         * flags - Socket's flags. It is formed by ORing one or more values 
         * specified <here https://man7.org/linux/man-pages/man2/recv.2.html>.
         * 
         * Returns:
         *  The number of bytes received (before decrypting the message).
         */
        ssize_t secure_recv(unsigned char* buffer, size_t len, int flags = 0);

        /**
         * Function: secure_close
         * Closes the socket.
         * 
         * Returns:
         *  Zero on success.  On error, -1 is returned, and errno is set to
         *  indicate the error.
         */
        int secure_close();

        /**
         * Function: is_alive
         * Determines if the connection is still alive.
         * 
         * Returns:
         *  True if the connection is still alive, otherwise False.
         */
        bool is_alive();

        /**
         * Title: Private
         */
    private:
        /**
         * Function: generate_AES_key
         * Generates the AES key object used to secure the communication.
         * 
         * Parameters:
         * IV - The Initialization Vector (IV) to use. If none is specified,
         * i.e., it's value is NULL, a random one will be generated.
         * key_len - The length of the key, in bytes. Default value: 32.
         * 
         * Property:
         * Private.
         * 
         * Returns:
         *  Reference (pointer) to the Key object.
         */
        Key generate_AES_key(unsigned char* IV, int key_len = 32);

        /**
         * Function: encrypt_AES
         * Uses the Key object to AES-encrypt the first _buffer_len bytes
         * from _buffer_. Overwrites the contents of _buffer_ with the
         * encrypted bytes.
         * 
         * Parameters:
         * buffer - Buffer of bytes to encrypt. Will be overwritten with
         * the result of the encryption. 
         * buffer_len - Length of the buffer, or number of bytes to encrypt.
         * 
         * Property:
         * Private.
         * 
         * Returns:
         *  The length of the encrypted byte sequence.
         */
        size_t encrypt_AES(unsigned char* buffer, size_t buffer_len);

        /**
         * Function:
         * Uses the Key object to AES-decrypt the first _buffer_len bytes
         * from _buffer_. Overwrites the contents of _buffer_ with the
         * decrypted bytes.
         * 
         * Parameters:
         * buffer - Buffer of bytes to decrypt. Will be overwritten with
         * the result of the decryption. 
         * buffer_len - Length of the buffer, or number of bytes to encrypt.
         * 
         * Property:
         * Private.
         * 
         * Returns:
         *  The length of the decrypted byte sequence.
         */
        size_t decrypt_AES(unsigned char* buffer, size_t buffer_len);

        /**
         * Variable: IP_
         * The IP to listen or to connect to.
         * 
         * Property:
         * Private.
         */
        std::string IP_; 

        /**
         * Variable: port_
         * The port to listen or to connect to.
         * 
         * Property:
         * Private.
         */
        int port_; 

        /**
         * Variable: socket_
         * The socket number (file descriptor).
         * 
         * Property:
         * Private.
         */
        int socket_; 

        /**
         * Variable: key_
         * The AES Key object.
         * 
         * Property:
         * Private.
         * 
         * See Also:
         * <Key>
         */
        Key* key_; 
};

#endif // _SECURE_SOCKET_H_