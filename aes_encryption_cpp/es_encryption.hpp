#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <string>
#include <map>
#include <stdexcept>
#include <fstream>
#include <memory>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>


/// \brief Encrypts data and files using AES CBC/CFB, 128/192/256 bits.
/// \details The encryption and authentication keys
///   are derived from the supplied key or password using HKDF / PBKDF2.
///   The key can be set either with `setMasterKey` or with `randomKeyGen`.
///   Encrypted data format: salt[16] + iv[16] + ciphertext[n] + mac[32].
///   Ciphertext authenticity is verified with HMAC SHA256.
/// \note Requires cryptopp https://www.cryptopp.com/
class AesEncryption
{
public:
    /// \brief The number of KDF iterations (applies to password-based keys).
    unsigned int keyIterations = 20000;
    /// \brief accepts and returns Base64 encoded data.
    bool base64 = true;
    /// \brief Identifies encryption mode.
    static const enum { CBC = 10, CFB = 20 } Mode;
    /// \brief Identifies encryption method.
    static const enum { ENCRYPT = 1, DECRYPT = 2 } Method;

    /// \brief Creates a new AesEncryption object.
    /// \param mode The AES mode (CBC, CFB).
    /// \param size The key size (128, 192, 256).
    /// \throw runtime_error When the mode is not supported or size is invalid.
    AesEncryption(std::string mode = "CBC", unsigned int size = 128);

    /// \brief Encrypts data using the supplied password.
    /// \param data The plaintext.
    /// \param password The password.
    CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock password);

    /// \brief Encrypts data using the supplied password.
    CryptoPP::SecByteBlock encrypt(std::string data, std::string password);

    /// \brief Encrypts data using the supplied password.
    CryptoPP::SecByteBlock encrypt(
        const unsigned char* data, size_t dataSize, 
        const unsigned char* password, size_t passwordSize
    );

    /// \brief Encrypts data using the master key.
    /// \param data The plaintext
    CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock data);

    /// \brief Encrypts data using the master key.
    CryptoPP::SecByteBlock encrypt(std::string data);

    /// \brief Encrypts data using the master key.
    CryptoPP::SecByteBlock encrypt(const unsigned char* data, size_t dataSize);

    /// \brief Decrypts data using the supplied password.
    /// \param data The plaintext.
    /// \param password The password.
    CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock password);

    /// \brief Decrypts data using the supplied password.
    CryptoPP::SecByteBlock decrypt(std::string data, std::string password);

    /// \brief Decrypts data using the supplied password.
    CryptoPP::SecByteBlock decrypt(
        const unsigned char* data, size_t dataSize, 
        const unsigned char* password, size_t passwordSize
    );

    /// \brief Decrypts data using the master key.
    CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock data);

    /// \brief Decrypts data using the master key.
    CryptoPP::SecByteBlock decrypt(std::string data);

    /// \brief Decrypts data using the master key.
    CryptoPP::SecByteBlock decrypt(const unsigned char* data, size_t dataSize);

    /// \brief Encrypts files using the supplied password.
    /// \param path The file path.
    /// \param password The password.
    std::string encryptFile(std::string path, CryptoPP::SecByteBlock password);

    /// \brief Encrypts files using the supplied password.
    std::string encryptFile(std::string path, std::string password);

    /// \brief Encrypts files using the master key.
    /// \param path The file path.
    std::string encryptFile(std::string path);

    /// \brief Decrypts files using the supplied password.
    /// \param path The file path.
    /// \param password The password.
    std::string decryptFile(std::string path, CryptoPP::SecByteBlock password);

    /// \brief Decrypts files using the supplied password.
    std::string decryptFile(std::string path, std::string password);

    /// \brief Decrypts files using the master key.
    /// \param path The file path.
    std::string decryptFile(std::string path);

    /// \brief Sets a new master key, from which the encryption and authentication keys will be derived.
    /// \param key The new master key. Must have the same size as the AES key size.
    /// \param raw Optional, accepts a raw key (not base64-encoded).
    void setMasterKey(CryptoPP::SecByteBlock key, bool raw = false);

    /// \brief Sets a new master key, from which the encryption and authentication keys will be derived.
    void setMasterKey(std::string key, bool raw = false);

    /// \brief Returns the master key (or empty bytes if the key is not set).
    /// \param raw Optional, return the key as raw bytes (not base64-encoded).
    CryptoPP::SecByteBlock getMasterKey(bool raw = false);

    /// \brief Generates a new random key.
    /// \param keyLen Optional, the key size.
    /// \param raw Optional, return the key as raw bytes (not base64-encoded).
    CryptoPP::SecByteBlock randomKeyGen(size_t keyLen = 32, bool raw = false);
protected:
    /// \brief Handles exceptions (prints the error message by default).
    /// \param exception The exception object.
    void errorHandler(const std::exception& exception);
private:
    /// \brief Holds the supported AES modes.
    const std::map<std::string, unsigned int> modes = {
        { "CBC", AesEncryption::CBC }, { "CFB", AesEncryption::CFB }
    };
    /// \brief Holds the AES key sizes.
    const int sizes[3] = { 128, 192, 256 };
    /// \brief The salt size in bytes.
    static const int saltLen = 16;
    /// \brief The IV size in bytes.
    static const int ivLen = 16;
    /// \brief The MAC size in bytes.
    static const int macLen = 32;
    /// \brief The HMAC key size in bytes.
    static const int macKeyLen = 32;

    /// \brief The selected AES mode.
    std::string mode;
    /// \brief The key size in bytes.
    size_t keyLen;
    /// \brief The master key.
    CryptoPP::SecByteBlock masterKey;

    /// \brief Creates random bytes; used for IV, salt and key generation.
    CryptoPP::SecByteBlock randomBytes(size_t size);

    /// \brief Derives encryption and authentication keys from a key or password.
    void keys(
        CryptoPP::SecByteBlock password, const CryptoPP::byte* salt,
        CryptoPP::SecByteBlock& aesKey, CryptoPP::SecByteBlock& macKey
    );

    /// \brief Creates a SymmetricCipher object; used for encryption / decryption.
    /// \param mode The encryption mode (ENCRYPT / DECRYPT).
    std::shared_ptr<CryptoPP::SymmetricCipher> cipher(
        CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, unsigned int mode);

    /// \brief Computes the MAC of ciphertext; used for authentication.
    CryptoPP::SecByteBlock sign(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock key);

    /// \brief Verifies the authenticity of ciphertext.
    /// \throw AesEncryptionError when the MAC is invalid.
    void verify(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key);

    /// \brief Computes the MAC of ciphertext; used for authentication.
    CryptoPP::SecByteBlock signFile(std::string path, CryptoPP::SecByteBlock key);

    /// \brief Verifies the authenticity of ciphertext.
    /// \throw AesEncryptionError when the MAC is invalid.
    void verifyFile(std::string path, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key);

    /// \brief Checks if encrypted data have the minimum expected size.
    /// \throw AesEncryptionError when the size is invalid.
    void checkSize(unsigned int dataLen);
};


/// \brief AesEncryptionError exception.
class AesEncryptionError : public std::exception
{
public:
    explicit AesEncryptionError(const std::string& message);
    virtual ~AesEncryptionError() throw () {}
    virtual const char* what() const throw ();
protected:
    std::string msg;
};


/// \brief Holds SymmetricCipher objects and creates the required cipher.
class Ciphers {
public:
    /// \brief SymmetricCipher object (base class).
    typedef std::shared_ptr<CryptoPP::SymmetricCipher> Cipher;
    /// \brief Creates a new SymmetricCipher object.
    /// \throw AesEncryptionError if the cipher is not available.
    static Ciphers::Cipher getCipher(unsigned int, unsigned int);
    /// \brief Sets the key and IV (and feedback in CFB) parameters.
    static void setValues(
        Ciphers::Cipher, unsigned int, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock
    );
private:
    static std::map<unsigned int, Ciphers::Cipher> ciphers;
};


/// \brief Base64 encodes / decodes data.
class Base64
{
public:
    /// \brief Encodes data.
    static CryptoPP::SecByteBlock encode(const CryptoPP::byte*, size_t);
    /// \brief Decodes data.
    static CryptoPP::SecByteBlock decode(const CryptoPP::byte*, size_t, bool);
private:
    /// \brief Checks if encoded data have the expected format.
    static void checkEncoded(const CryptoPP::byte*, size_t);
};


/// \brief Reads a file and returns chunks of data.
class FileChunks
{
public:
    /// \param path The file path.
    /// \param start the starting position.
    /// \param end the ending position (file size - end).
    /// \throw AesEncryptionError when the file is not accessible.
    FileChunks(std::string path, size_t start = 0, size_t end = 0);
    /// \brief Reads file data.
    /// \param data The buffer (the buffer size size must be equal to FileChunks::chunkSize).
    size_t read(CryptoPP::byte* data);
    /// \brief Checks if thera are more data to read.
    bool hasData();
    /// \brief Returns the size of a file.
    /// \throw AesEncryptionError when the file is not accessible.
    static size_t fileSize(std::string path);
    /// \brief The size of data chunks. 
    static const size_t chunkSize = 1024;
private:
    /// \brief The file object.
    std::ifstream file;
    /// \brief The position in the file.
    size_t pos = 0;
    /// \brief The end position.
    size_t end = 0;
};


#endif // !AES_ENCRYPTION_H
