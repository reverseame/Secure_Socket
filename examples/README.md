## Compilation

Client example:
```
$ g++ client.cpp ../src/Secure_Socket.cpp --std=c++11 -l cryptopp -o client.out
```
Server example:
```
$ g++ server.cpp ../src/Secure_Socket.cpp --std=c++11 -l cryptopp -o server.out
```