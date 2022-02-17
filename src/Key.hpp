/*
 About: License
    
    This file is part of Secure_Socket <https://github.com/RazviOverflow/SecureSocket>.

    Secure_Socket is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Secure_Socket is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

 About: Authors
        - Razvan Raducu  (University of Zaragoza)  
        - Ricardo J. Rodriguez  (University of Zaragoza)

 About: Code
        Secure_Socket's code can be found in <its public repository: https://github.com/RazviOverflow/SecureSocket>

*/

#ifndef _KEY_H_
#define _KEY_H_
#if defined __WIN32__ || defined _WIN32 || defined WIN32 || defined MSC_VER
#include <secblock.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <cryptopp/secblock.h>
#endif

/**
 * Title: Key
 * Class whose main purpose is to manage the AES key once generated, as well as 
 * its parameters.  
 * 
 */
class Key{
    public:

        /**
         * Constructor: Key
         *  Default constructor to create the Key object.
         * 
         * Parameters:
         *  IV - The Initialization Vector (IV).
         *  key - The key itself.
         *  key_len - Key's length. Default value: 32.
         * 
         * Returns:
         *  Reference (pointer) to the Key object.
         */
        Key(CryptoPP::SecByteBlock IV, CryptoPP::SecByteBlock key, int key_len = 32){

            IV_ = IV;
            key_ = key;
            key_len_ = key_len;

        };

        /**
         * Function: get_IV
         *  Returns the Initalization Vector (IV).
         * 
         * Returns:
         *  IV_
         */
        CryptoPP::SecByteBlock get_IV(){
            return IV_;
        };

        /**
         * Function: get_key
         *  Returns the key itself.
         *  
         * Returns:
         *  key_
         */
        CryptoPP::SecByteBlock get_key(){
            return key_;
        };

        /**
         * Function: get_key_len
         *  Returns key's length.
         * 
         * Returns:
         *  key_len_
         */
        int get_key_len(){
            return key_len_;
        };


        /**
         * Title: Private
         */
    private:
         /**
         * Variable: IV_
         *  The Initialization Vector (IV).
         * 
         * Property:
         *  Private.
         */
        CryptoPP::SecByteBlock IV_;

         /**
         * Variable: key__
         *  The AES key itself.
         * 
         * Property:
         *  Private.
         */
        CryptoPP::SecByteBlock key_; /**<  */

         /**
         * Variable: key_len_
         *  Key's len. Default value: 32.
         * 
         * Property:
         *  Private.
         */
        int key_len_; /**<  */
};
#endif // _KEY_H_