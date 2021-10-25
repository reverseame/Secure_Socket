# Secure Socket
Sockets implementing hybrid encryption using Crypto++. Developed and tested under Linux.

## Requirements

* [Crypto++](https://github.com/weidai11/cryptopp) 8.5 (version available as of July 21, 2021)
* [Crypto++ PEM Pack](https://www.cryptopp.com/wiki/PEM_Pack) 8.2.0 (version available as of July 21, 2021)

## Installation

## Unix

### Requirements

1. Download Crypto++. 
2. Download Crypto++ PEM Pack (Documentation [here](https://github.com/noloader/cryptopp-pem)).
3. Move to Crypto++'s directory:
```
$ cd cryptopp_dir
```
4. Extract (uncompress) Crypto++ PEM Pack:
```
$ 7z x cryptopp_pem.zip
```
5. Install both the library and PEM Pack:
```
$ make -j 4
$ make test
$ sudo make install
```	

- More intstructions about Crypto++'s installation can be found [here](https://github.com/weidai11/cryptopp/blob/master/Install.txt).
- More instructions about Crypto++ PEM Pack's installation can be found [here](https://github.com/noloader/cryptopp-pem).

### Secure_Socket

To use **Secure_Socket** copy the files included in the [src](/src) folder of this repo in your project's source and header files directory. Once both _.cpp_ and _.hpp_ files are in their corresponding directories, in order to use the library simply `#include "Secure_Socket.hpp"` in your files. 

## Windows

In order to use Secure_Socket in your Windows-based environment you must follow these steps:  
_(All these steps were done using Microsoft Visual Studio 2017 version 15.9.38)_

### Crypto++ installation

1. Download Crypto++.
2. Download Cryptopp-PEM. I recommend cloning the repository rather than downloading the release since the repository itself is updated whereas the release is not. 
3. Unzip the contents of Cryptopp-PEM in the same folder as Crypto++'s headers and sources.
4. Look for a file called `cryptlib.vcxproj`.
5. Open it in Microsoft Visual Studio.
6. In the `Solution Explorer` window you should see 4 projects: `cryptdll`, `cryptest`, `cryptlib` and `dlltest`. Each one of the is detailed [here](https://www.cryptopp.com/wiki/Visual_Studio). In short, `cryptlib` allows you to build Crypto++ as a **STATIC** library and, on the other hand, `cryptdll` builds it as a **DYNAMIC** library (linked).
7. Select the project you want to build (for example, cryptlib).
8. Open the dropdown menu.
9. Right click `Header Files` -> Add -> Existing Item and select `pem.h` and `pem_common.h`.
10. Right click `Source Files` -> Add -> Existing Item and select `pem_common.cpp`, `pem_read.cpp` and `.pem_write.cpp`
11. Manually add `#include "pch.h"` at the beginning of `pem_common.cpp`, `pem_read.cpp` and `.pem_write.cpp` (right over `#include "cryptlib.h")`.
12. Select the target you desire to build the library for : *Win32* or *x64 and *Debug*, *DLL-Import Debug*, *DLL-Import Release* or *Release*.
13. Right-click on the project you want to build (either `cryptdll` or `cryptlib`) and select build.32
14. The output files will be generated after the building process in the same path as the `cryptlib.vcxproj` file. Visual Studio will print the output path in its console anyways. 

### Including Crypto++ in your project.

After successfully building Crypto++ in your Windows environment, the time to use it has come. 

1. Open your project in Microsoft Visual Studio. 
2. Right-click on your project -> Properties. 
3. Open the C/C++ drop-down menu -> General.
	1. Include the Crypto++ path (directory of .cpp and .h files) in the `Additional Include Directories` field. 
4. Open the Linker drop-down menu -> Input.
	1. Include `cryptlib.lib` and `Ws2_32.lib` in the `Additional Dependencies` field.
5. Open the Linker drop-down menu -> General.
  1. Include the path of the compiled Crypto++ and Cryptopp-PEM library (path of `cryptlib.lib`, usually something like ...\x64\Output\Release)

### Cloning this project into Visual Studio

In order to include this repository as a project into Microsot Visual Studio you can clone it straight from Github. You will need the Github Extension for Microsoft Visual Studio. Intructions on how to install it can be found [here](https://social.technet.microsoft.com/wiki/contents/articles/38935.visual-studio-2017-install-and-use-github-extension.aspx).
Once you cloned the repository, you must define the tasks so as to be able to build the project. To do so:
<!---
1. Right click on the root folder of the project -> Configure tasks.
2. This will generate a file named `tasks.vs.json` in the .vs folder.
3. You now must define the tasks. More instructions about this process can be found [here](https://social.technet.microsoft.com/wiki/contents/articles/38935.visual-studio-2017-install-and-use-github-extension.aspx). I defined the following tasks:
```
{
  "version": "0.2.1",
  "tasks": [
    {
      "taskName": "build_Secure_Socket_client",
      "appliesTo": "/",
      "type": "launch",
      "command": "g++",
      "args": [
        "examples/client.cpp",
        "src/Secure_Socket.cpp",
        "--std=c++11",
        "-o",
        "client"
      ]
    },
    {
      "taskName": "build_Secure_Socket_server",
      "appliesTo": "/",
      "type": "launch",
      "command": "g++",
      "args": [
        "examples/server.cpp",
        "src/Secure_Socket.cpp",
        "--std=c++11",
        "-o",
        "server"
      ]
    }
  ]
}
```
-->
1. If you need to define properties for your project, you may notice that the "Properties" option is missing. In fact, you may not even be able to switch to "Solution explorer", remaining stuck in the "Folder view" perspective. This happens because there are no solution-related files in the project. In order to fix this I created a new project (File -> New -> Project From Existing Code) specifying as source path the directory where the repo was cloned.
2. You should be able to define the libraries, as specified in the previos section __Including Crypto++ in your project__.


#### Troubleshooting

* If you get an error like `error MSB8036: The Windows SDK version X.X was not found.` when trying to build the library, you can either change your project's properties (instructions [here](https://docs.microsoft.com/en-us/visualstudio/msbuild/errors/msb8036?view=vs-2019)) or download the specified Windows SDK from [here](https://developer.microsoft.com/en-us/windows/downloads/sdk-archive/).
* If you get one or more errors with codes like `LNK2019`, `LNK2001` or `LNK1120` when building your application, make sure you included the right library (absolute path) in the `Additional Dependencies` field of Linker -> Input menu.
* If you get an error like `1>LINK : fatal error LNK1104: cannot open file 'C:\Users\User\Desktop\cryptopp-master\cryptopp-master\x64\Output\Release.obj'`, you must... more info [here](https://stackoverflow.com/questions/43126243/why-fatal-error-lnk1104-cannot-open-file-cryptlib-lib-occur-when-i-compile-a).
* If you get an error like `error C2039: 'toupper': is not a member of 'std'` or `error C2039: 'isspace': is not a member of 'std'` or any other variant, it is because, despite what Microsoft says in the [docs](https://docs.microsoft.com/en-us/cpp/standard-library/cctype?view=msvc-160), it seems like cctype does not include std. The solution is to manually change every `std::toupper()` call to `::toupper()` and every `std::isspace()` to `::isspace()`, as stated [here](https://github.com/noloader/cryptopp-pem/issues/10). This is not necessary anymore, as  it is stated in the issue previously linked.
* If you are using the library and get an error like `[!] Error binding socket! Error: 10049 ABORTING [!]` it is because, somehow, it cannot connect to the specified IP. It happened to us when using `localhost`. Changing it to `127.0.0.1` worked.

## Compilation (Unix)

_Change paths accordingly_

Client example:
```
$ g++ client.cpp Secure_Socket.cpp --std=c++11 -l cryptopp -o client.out
```
Server example:
```
$ g++ server.cpp Secure_Socket.cpp --std=c++11 -l cryptopp -o server.out
```

## Generate RSA keys (Unix)
```
$ openssl genrsa -des3 -out private.pem 2048

$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem

$ openssl rsa -in private.pem -out private_unencrypted.pem -outform PEM
```

## Useful links
* Cryptopp repo - [https://github.com/weidai11/cryptopp](https://github.com/weidai11/cryptopp)
* Cryptopp-PEM repo - [https://github.com/noloader/cryptopp-pem](https://github.com/noloader/cryptopp-pem)
* Cryptopp-PEM issue - [https://github.com/noloader/cryptopp-pem/issues/10](https://github.com/noloader/cryptopp-pem/issues/10)
* Cryptopp main wiki - [https://www.cryptopp.com/wiki/Main_Page](https://www.cryptopp.com/wiki/Main_Page)
* Cryptopp Visual Studio wiki - [https://www.cryptopp.com/wiki/Visual_Studio](https://www.cryptopp.com/wiki/Visual_Studio)
* Cryptopp PEM Pack wiki - [https://www.cryptopp.com/wiki/PEM_Pack](https://www.cryptopp.com/wiki/PEM_Pack)

## Authors:

Designed by Ricardo J. Rodriguez (University of Zaragoza) and Razvan Raducu (University of Zaragoza).  
Implemented by Razvan Raducu.  

## License:

Secure_Socket is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Secure_Socket is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## TODO

* Unit tests.