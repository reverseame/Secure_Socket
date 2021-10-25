/*
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

	@Authors:
		Razvan Raducu (University of Zaragoza)
		Ricardo J. Rodriguez (University of Zaragoza)

*/

#include "Secure_Socket.hpp"

#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
#include <io.h> // Windows alternative to unistd.h
#include <pem.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <cryptopp/pem.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

const int SERVER_SECURE_SOCKET = 0;
const int CLIENT_SECURE_SOCKET = 1;
const int INT_SIZE = sizeof(int32_t);

Secure_Socket::Secure_Socket(int port, std::string IP, int socket_type, unsigned char* IV, std::string RSA_private_key_path, std::string RSA_public_key_path, int key_len) {

	int protocol = 0; // IPv4
	int opt = 1;

	if (socket_type == SERVER_SECURE_SOCKET) {

		int server_fd;

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		/************************/
		/* WINDOWS ENVIRONMENTS */
		/************************/

		/* Creation of socket */
		/* The documentation states it clear, WSAStrartup must be called before using any other Winsock functions
		https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
		*/
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;
		/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
		wVersionRequested = MAKEWORD(2, 2);

		err = WSAStartup(wVersionRequested, &wsaData);
		if (err != 0) {
			/* Tell the user that we could not find a usable */
			/* Winsock DLL.                                  */
			fprintf(stderr, "[!] WSAStartup failed! Error: %ld ABORTING [!]\n", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		// https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-socket-for-the-server
		struct addrinfo *address = NULL, hints;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;
		// Resolve the local address and port to be used by the server
		int result = getaddrinfo(NULL, std::to_string(port).c_str(), &hints, &address);
		if (result != 0) {
			fprintf(stderr, "[!] getaddrinfo failed! Error: %d ABORTING [!]\n", result);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (server_fd == INVALID_SOCKET) {
			fprintf(stderr, "[!] Socket creation failed! Error: %ld ABORTING [!]\n", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		if ((setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&opt), sizeof(opt))) != 0) {
			fprintf(stderr, "[!] Setting socket options (setsockopt) failed! Error: %ld ABORTING [!]\n", WSAGetLastError());
			exit(EXIT_FAILURE);
		}

		/* Attaching socket to PORT port and ADDRESS IP */
		struct sockaddr_in connection_address;
		connection_address.sin_family = AF_INET;
		inet_pton(AF_INET, IP.c_str(), &connection_address.sin_addr);
		connection_address.sin_port = htons(port);
		if ((bind(server_fd, (struct sockaddr*)&connection_address, sizeof(connection_address))) == SOCKET_ERROR) {
			fprintf(stderr, "[!] Error binding socket! Error: %ld ABORTING [!]\n", WSAGetLastError());
			freeaddrinfo(address);
			closesocket(server_fd);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		/* Waiting for incoming connections */
		if (listen(server_fd, SOMAXCONN) == SOCKET_ERROR) {
			fprintf(stderr, "[!] Error while listening to incoming connections! Error: %ld ABORTING [!]\n", WSAGetLastError());
			closesocket(server_fd);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		/* Accepting incoming connections */
		if ((socket_ = accept(server_fd, NULL, NULL)) == INVALID_SOCKET) {
			fprintf(stderr, "[!] Error while accepting incoming connections! Error: %ld ABORTING [!]\n", WSAGetLastError());
			closesocket(server_fd);
			WSACleanup();
			exit(EXIT_FAILURE);
		}

#else
		/*********************/
		/* UNIX ENVIRONMENTS */
		/*********************/


		/* Creation of socket */
		struct sockaddr_in address;
		int addrlen = sizeof(address);

		server_fd = socket(AF_INET, SOCK_STREAM, protocol);

		if (server_fd == -1) {
			perror("[!] Socket creation failed! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		if ((setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) != 0) {
			perror("[!] Setting socket options (setsockopt) failed! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* Populating struct sockaddr_in */
		address.sin_family = AF_INET;
		inet_pton(AF_INET, IP.c_str(), &address.sin_addr);
		// To convert it back to string: inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
		address.sin_port = htons(port);

		/* Attaching socket to PORT port and ADDRESS IP */
		if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
			perror("[!] Error binding socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* Waiting for incoming connections */
		if (listen(server_fd, SOMAXCONN) != 0) {
			perror("[!] Error while listening to incoming connections! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* Accepting incoming connections */
		if ((socket_ = accept(server_fd, (struct sockaddr*)&address, (socklen_t *)&addrlen)) < 0) {
			perror("[!] Error while accepting incoming connections! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif


		/* Read RSA keys */
		CryptoPP::RSA::PrivateKey RSA_private_key;
		CryptoPP::RSA::PublicKey RSA_public_key;
		std::string rsa_privkey_string, rsa_pubkey_string;

		// Private key
		try {
			CryptoPP::FileSource private_input_file(RSA_private_key_path.c_str(), true, new CryptoPP::StringSink(rsa_privkey_string));
			CryptoPP::StringSource private_input_string(rsa_privkey_string, true);
			CryptoPP::PEM_Load(private_input_string, RSA_private_key);
		}
		catch(...) {
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
			closesocket(server_fd);
			WSACleanup();
#endif
            perror("[!] Error while reading RSA private key file! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}


		// Public key
		try{
			CryptoPP::FileSource public_input_file(RSA_public_key_path.c_str(), true, new CryptoPP::StringSink(rsa_pubkey_string));
			CryptoPP::StringSource public_input_string(rsa_pubkey_string, true);
			CryptoPP::PEM_Load(public_input_string, RSA_public_key);
		}
		catch (...) {
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
			closesocket(server_fd);
			WSACleanup();
#endif
            perror("[!] Error while reading RSA public key file! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* Send RSA public Key */
		// First send how long RSA public key is
		int RSA_pubkey_length = htonl(rsa_pubkey_string.length());

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (send(socket_, reinterpret_cast<char*>(&RSA_pubkey_length), INT_SIZE, 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (send(socket_, &RSA_pubkey_length, INT_SIZE, 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		// Then send the RSA public key
		if (send(socket_, rsa_pubkey_string.c_str(), rsa_pubkey_string.length(), 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* Receive RSA-encrypted AES key */
		int encrypted_aes_key_length;
		// First receive how long the RSA-encrypted AES key will be
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (recv(socket_, reinterpret_cast<char*>(&encrypted_aes_key_length), INT_SIZE, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (recv(socket_, &encrypted_aes_key_length, INT_SIZE, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		encrypted_aes_key_length = ntohl(encrypted_aes_key_length);

		// Then receive the RSA-encrypted AES key 
		std::vector<unsigned char> buffer;
		buffer.resize(encrypted_aes_key_length);

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (recv(socket_, reinterpret_cast<char*>(&buffer[0]), encrypted_aes_key_length, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (recv(socket_, &buffer[0], encrypted_aes_key_length, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif


		/* Decrypt RSA-encrypted AES key */
		std::string aes_encrypted_key(reinterpret_cast<const char*>(buffer.data()), buffer.size()), aes_key_decrypted;
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor rsa_decryption(RSA_private_key);
		CryptoPP::StringSource ss1(aes_encrypted_key, true, new CryptoPP::PK_DecryptorFilter(rng, rsa_decryption, new CryptoPP::StringSink(aes_key_decrypted)));
		CryptoPP::SecByteBlock AES_key(reinterpret_cast<const CryptoPP::byte*>(aes_key_decrypted.c_str()), aes_key_decrypted.length());

		/* Receive RSA-encrypted AES IV */
		// First receive the RSA-Encrypted AES_IV length
		int encrypted_aes_iv_length;
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (recv(socket_, reinterpret_cast<char*>(&encrypted_aes_iv_length), INT_SIZE, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (recv(socket_, &encrypted_aes_iv_length, INT_SIZE, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		encrypted_aes_iv_length = ntohl(encrypted_aes_iv_length);

		// Then receive the RSA-encrypted AES_IV
		buffer.resize(encrypted_aes_iv_length);
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (recv(socket_, reinterpret_cast<char*>(&buffer[0]), encrypted_aes_iv_length, 0) < 0) {
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (recv(socket_, &buffer[0], encrypted_aes_iv_length, 0) < 0) {
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		/* Decrypt AES IV*/
		std::string aes_encrypted_iv(reinterpret_cast<const char*>(buffer.data()), buffer.size()), aes_iv_decrypted;
		CryptoPP::StringSource ss2(aes_encrypted_iv, true, new CryptoPP::PK_DecryptorFilter(rng, rsa_decryption, new CryptoPP::StringSink(aes_iv_decrypted)));
		CryptoPP::SecByteBlock AES_iv(reinterpret_cast<const CryptoPP::byte*>(aes_iv_decrypted.c_str()), aes_iv_decrypted.length());

		/* Create Key object with AES parameters */
		key_ = new Key(AES_iv, AES_key, key_len);

		/* The communication can now be carried on */

	} else if (socket_type == CLIENT_SECURE_SOCKET) {


#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER

		/************************/
		/* WINDOWS ENVIRONMENTS */
		/************************/

		/* Creation of socket */	
		/* The documentation states it clear, WSAStrartup must be called before using any other Winsock functions
		https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
		*/
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;
			/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
		wVersionRequested = MAKEWORD(2, 2);
		err = WSAStartup(wVersionRequested, &wsaData);
		if (err != 0) {
				/* Tell the user that we could not find a usable */
				/* Winsock DLL.                                  */
			fprintf(stderr, "[!] WSAStartup failed! Error: %ld ABORTING [!]\n", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}


		// https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-socket-for-the-server
		struct addrinfo *address = NULL, hints;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		// Resolve the local address and port to be used by the server
		int result = getaddrinfo(NULL, std::to_string(port).c_str(), &hints, &address);
		if (result != 0) {
			fprintf(stderr, "[!] getaddrinfo failed! Error: %d ABORTING [!]\n", result);
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		if ((socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
			fprintf(stderr, "[!] Socket creation failed! Error: %ld ABORTING [!]\n", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		/* Populating struct sockaddr_in */
		struct sockaddr_in connection_address;
		connection_address.sin_family = AF_INET;
		inet_pton(AF_INET, IP.c_str(), &connection_address.sin_addr);
		connection_address.sin_port = htons(port);

		/* Establishing connection to the specified socket */
		if (connect(socket_, (struct sockaddr*)&connection_address, sizeof(connection_address)) == SOCKET_ERROR) {
			fprintf(stderr, "[!]  Error while connecting to the specified socket! Error: %ld ABORTING [!]\n", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}
#else

		/*********************/
		/* UNIX ENVIRONMENTS */
		/*********************/

		/* Creation of socket */
		struct sockaddr_in address;
		if ((socket_ = socket(AF_INET, SOCK_STREAM, protocol)) == -1) {
			perror("[!] Socket creation failed! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
		/* Populating struct sockaddr_in */
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		inet_pton(AF_INET, IP.c_str(), &address.sin_addr);

		/* Establishing connection to the specified socket */
		if (connect(socket_, (struct sockaddr *)&address, sizeof(address)) != 0) {
			perror("[!] Error while connecting to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}		
#endif

		/* Generate AES key and create Key object with AES parameters */
		key_ = new Key(Secure_Socket::generate_AES_key(IV, key_len));

		/* Receive RSA public key */
		// First receive how long the RSA-encrypted AES key will be
		int RSA_pubkey_length;
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (recv(socket_, reinterpret_cast<char*>(&RSA_pubkey_length), INT_SIZE, MSG_WAITALL) < 0) { // read only key_len bytes from the socket
			fprintf(stderr, "[!] Error while reading data from the specified socket! Error: %ld ABORTING [!]\n", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}
#else
		if (recv(socket_, &RSA_pubkey_length, INT_SIZE, 0) < 0) { // read only key_len bytes from the socket
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		RSA_pubkey_length = ntohl(RSA_pubkey_length);
				// Then receive the key itself
		std::vector<char> buffer;
		buffer.resize(RSA_pubkey_length);

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (recv(socket_, reinterpret_cast<char*>(&buffer[0]), RSA_pubkey_length, 0) < 0) {
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

#else
		if (recv(socket_, &buffer[0], RSA_pubkey_length, 0) < 0) {
			perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		/* Encrypt AES key with RSA key and send it */
		CryptoPP::RSA::PublicKey RSA_public_key;
		CryptoPP::StringSource public_input_string(buffer.data(), true);
		CryptoPP::PEM_Load(public_input_string, RSA_public_key);

		// More RSA encryption schemes at https://www.cryptopp.com/wiki/RSA_Encryption_Schemes
		CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encryption(RSA_public_key);
		CryptoPP::AutoSeededRandomPool rng;
		std::string encrypted_aes_key;
		std::string aes_key_str(reinterpret_cast<const char*>(key_->get_key().data()), key_->get_key().size());
		CryptoPP::StringSource ss1(aes_key_str, true, new CryptoPP::PK_EncryptorFilter(rng, rsa_encryption, new CryptoPP::StringSink(encrypted_aes_key)));

		// Send encrypted AES key length first:
		int cipher_length_net = htonl(encrypted_aes_key.length());

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (send(socket_, reinterpret_cast<char*>(&cipher_length_net), INT_SIZE, 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (send(socket_, &cipher_length_net, INT_SIZE, 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		// Send encrypted AES key:
		if (send(socket_, encrypted_aes_key.c_str(), encrypted_aes_key.length(), 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* Encrypt AES IV with RSA key and send it (if there is an IV) */
		std::string encrypted_aes_iv;
		std::string aes_iv_str(reinterpret_cast<const char*>(key_->get_IV().data()), key_->get_IV().size());
		CryptoPP::StringSource ss2(aes_iv_str, true, new CryptoPP::PK_EncryptorFilter(rng, rsa_encryption, new CryptoPP::StringSink(encrypted_aes_iv)));

		// First send RSA-Encrypted AES_IV length
		cipher_length_net = htonl(encrypted_aes_iv.length());

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		if (send(socket_, reinterpret_cast<char*>(&cipher_length_net), INT_SIZE, 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#else
		if (send(socket_, &cipher_length_net, INT_SIZE, 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}
#endif

		// Then send the RSA-Encrypted AES_IV
		if (send(socket_, encrypted_aes_iv.c_str(), encrypted_aes_iv.length(), 0) < 0) {
			perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
			exit(EXIT_FAILURE);
		}

		/* The communication can now be carried on */

	}
	else {
		throw "[!] Unknown secure socket type!";
		exit(EXIT_FAILURE);
	}

}

Secure_Socket::~Secure_Socket() {
	free(key_);
	close(socket_);
}

ssize_t Secure_Socket::secure_send(unsigned char* buffer, size_t len, int flags) {

	ssize_t bytes_sent;

	/* Encrypt data */
	int cipher_text_len = Secure_Socket::encrypt_AES(buffer, len);
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
	if ((bytes_sent = send(socket_, reinterpret_cast<const char*>(buffer), cipher_text_len, flags)) < 0) {
		perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
		exit(EXIT_FAILURE);
	}
#else
	if ((bytes_sent = send(socket_, buffer, cipher_text_len, flags)) < 0) {
		perror("[!] Error while sending data to the specified socket! ABORTING [!]\n");
		exit(EXIT_FAILURE);
	}
#endif


	return bytes_sent;
}

ssize_t Secure_Socket::secure_recv(unsigned char* buffer, size_t len, int flags) {

	ssize_t bytes_read;

#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
	if ((bytes_read = recv(socket_, reinterpret_cast<char*>(buffer), len, flags)) < 0) {
		perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
		exit(EXIT_FAILURE);
	}
#else
	if ((bytes_read = recv(socket_, buffer, len, flags)) < 0) {
		perror("[!] Error while reading data from the specified socket! ABORTING [!]\n");
		exit(EXIT_FAILURE);
	}
#endif


	/*Decrypt data*/
	Secure_Socket::decrypt_AES(buffer, bytes_read);

	return bytes_read;
}


int Secure_Socket::secure_close() {
	return close(socket_);
}


bool Secure_Socket::is_alive() {

	int error;
	socklen_t len = sizeof(error);
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
	int retval = getsockopt(socket_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len);
#else
	int retval = getsockopt(socket_, SOL_SOCKET, SO_ERROR, &error, &len);
#endif



	if (retval != 0) {
		perror("[!] Error getting socket options! [!]\n");
		return false;
	}

	if (error != 0) {
		perror("[!] Error reading socket! [!]\n");
		return false;
	}

	if (retval == 0) {
		const int len = 1;
		unsigned char buffer[len];
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
		int read_bytes = recv(socket_, reinterpret_cast<char*>(buffer), len, MSG_PEEK);
#else
		int read_bytes = recv(socket_, buffer, len, MSG_PEEK);
#endif

		if (read_bytes <= 0) {
			return false;
		}
	}

	return true;

}


Key Secure_Socket::generate_AES_key(unsigned char* IV, int key_len) {

	/* Generating random Key */
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::SecByteBlock AES_key(key_len);
	rng.GenerateBlock(AES_key, AES_key.size());

	/* Creating IV*/
	CryptoPP::SecByteBlock AES_iv(CryptoPP::AES::BLOCKSIZE);
	if (IV != NULL) {
				/* User-specified IV*/
		AES_iv = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(IV), CryptoPP::AES::BLOCKSIZE);
	}
	else {
		/* Random IV*/
		rng.GenerateBlock(AES_iv, CryptoPP::AES::BLOCKSIZE);
	}

	return Key(AES_iv, AES_key, key_len);
}



size_t Secure_Socket::encrypt_AES(unsigned char* buffer, size_t buffer_len) {

	CryptoPP::SecByteBlock key = key_->get_key();
	CryptoPP::SecByteBlock iv = key_->get_IV();

	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption ctrEncryption(key, key_->get_key_len(), iv);
	std::vector<unsigned char> cipher_text;

	/* Padding */
	cipher_text.resize(buffer_len + CryptoPP::AES::BLOCKSIZE);
	CryptoPP::ArraySink cs(&cipher_text[0], cipher_text.size());

	CryptoPP::ArraySource(buffer, buffer_len, true, new CryptoPP::StreamTransformationFilter(ctrEncryption, new CryptoPP::Redirector(cs)));

	/* Resize again */
	cipher_text.resize(cs.TotalPutLength());
	buffer_len = cipher_text.size();

	for (int i = 0; i < buffer_len; i++) {
		buffer[i] = cipher_text.data()[i];
	}
	return buffer_len;

}

size_t Secure_Socket::decrypt_AES(unsigned char* buffer, size_t buffer_len) {

	CryptoPP::SecByteBlock key = key_->get_key();
	CryptoPP::SecByteBlock iv = key_->get_IV();

	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption ctrDecryption(key, key_->get_key_len(), iv);
	std::vector<unsigned char> plain_text;

	/* Padding */
	plain_text.resize(buffer_len);
	CryptoPP::ArraySink rs(&plain_text[0], plain_text.size());

	CryptoPP::ArraySource(buffer, buffer_len, true, new CryptoPP::StreamTransformationFilter(ctrDecryption, new CryptoPP::Redirector(rs)));

	/* Resize again */
	plain_text.resize(rs.TotalPutLength());
	buffer_len = plain_text.size();

	for (int i = 0; i < buffer_len; i++) {
		buffer[i] = plain_text.data()[i];
	}

	return buffer_len;
}