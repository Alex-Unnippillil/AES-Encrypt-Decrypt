#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

std::string encryptAES(const std::string& message, const std::string& key) {
    byte iv[AES::BLOCKSIZE] = { 0 }; // Initialization vector
    byte encryptedMessage[AES::BLOCKSIZE];

    // Encryptor
    CBC_Mode<AES>::Encryption encryptor((const byte*)key.c_str(), key.length(), iv);

    // Encryption
    StringSource(message, true,
        new StreamTransformationFilter(encryptor,
            new ArraySink(encryptedMessage, AES::BLOCKSIZE)
        )
    );

    std::string encodedMessage;
    StringSource(encryptedMessage, AES::BLOCKSIZE, true,
        new HexEncoder(new StringSink(encodedMessage))
    );

    return encodedMessage;
}

std::string decryptAES(const std::string& encryptedMessage, const std::string& key) {
    byte iv[AES::BLOCKSIZE] = { 0 }; // Initialization vector
    byte decryptedMessage[AES::BLOCKSIZE];

    // Decryptor
    CBC_Mode<AES>::Decryption decryptor((const byte*)key.c_str(), key.length(), iv);

    // Decryption
    StringSource(encryptedMessage, true,
        new HexDecoder(
            new StreamTransformationFilter(decryptor,
                new ArraySink(decryptedMessage, AES::BLOCKSIZE)
            )
        )
    );

    std::string decryptedString((char*)decryptedMessage, AES::BLOCKSIZE);
    return decryptedString;
}

int main() {
    std::string message = "Hello, world!";
    std::string key = "mysecretkey";

    std::string encryptedMessage = encryptAES(message, key);
    std::cout << "Encrypted message: " << encryptedMessage << std::endl;

    std::string decryptedMessage = decryptAES(encryptedMessage, key);
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;

    return 0;
}
