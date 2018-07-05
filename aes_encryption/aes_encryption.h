#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <string>
#include <map>
#include <stdexcept>
#include <fstream>
#include <memory>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>


/// \brief Encrypts data and files using AES CBC/CFB, 128/192/256 bits
/// \note Requires cryptopp https://www.cryptopp.com/
class AesEncryption
{
public:
	/// \brief the number of KDF iterations
	size_t keyIterations = 20000;
	/// \brief accept/return Base64 encoded data
	bool base64 = true;
	/// \brief identifies encryption mode
	static const enum { CBC = 1, CFB = 2, ENCRYPT = 1, DECRYPT = 2 } Mode;

	/// \brief The constructor
	/// \param mode the AES mode (CBC, CFB)
	/// \param size the key size (128, 192, 256)
	/// \throw exception when the mode is not supported or size is invalid
	AesEncryption(std::string mode = "CBC", int size = 128);

	/// \brief Encrypts data with the supplied password
	/// \param data the data for encryption
	/// \param size data size
	/// \param password the password to use for encryption
	CryptoPP::SecByteBlock encrypt(const unsigned char* data, int size, std::string password);

	/// \brief Encrypts data with the supplied password
	CryptoPP::SecByteBlock encrypt(std::string data, std::string password);

	/// \brief Decrypts data with the supplied password
	/// \param data the data for decryption
	/// \param size data size
	/// \param password the password to use for decryption
	CryptoPP::SecByteBlock decrypt(const unsigned char* data, int size, std::string password);

	/// \brief Decrypts data with the supplied password
	CryptoPP::SecByteBlock decrypt(std::string data, std::string password);

	/// \brief Encrypts files with the supplied password
	/// \param path the file path
	/// \param password the password to use for encryption
	std::string encryptFile(std::string path, std::string password);

	/// \brief Decrypts files with the supplied password
	/// \param path the file path
	/// \param password the password to use for decryption
	std::string decryptFile(std::string path, std::string password);
private:
	/// \brief Holds the supported AES modes
	const std::map<std::string, int> modes = {
		{ "CBC", AesEncryption::CBC }, { "CFB", AesEncryption::CFB }
	};
	/// \brief Holds the valid key sizes
	const int sizes[3] = { 128, 192, 256 };
	/// \brief The salt size in bytes
	static const int saltLen = 16;
	/// \brief The IV size in bytes
	static const int ivLen = 16;
	/// \brief The MAC size in bytes
	static const int macLen = 32;
	/// \brief The selected AES mode
	std::string mode;
	/// \brief The key size in bytes
	int keyLen;

	/// \brief Creates random bytes, used for IV and salt generation
	/// \param size the number of bytes
	CryptoPP::SecByteBlock randomBytes(size_t size);

	/// \brief Creates a pair of keys from the password and salt
	/// \param password the password
	/// \param salt the salt
	void keys(
		std::string password, const CryptoPP::byte* salt, 
		CryptoPP::SecByteBlock& aesKey, CryptoPP::SecByteBlock& macKey
	);
	/// \brief Creates a SymmetricCipher object for encryption / decryption
	/// \param key the encryption key
	/// \param iv the IV
	/// \param mode the mode (ENCRYPT / DECRYPT)
	std::shared_ptr<CryptoPP::SymmetricCipher> cipher(
		CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, int mode
	);

	/// \brief Computes the MAC of data
	/// \param data the data
	/// \param key the authentication key
	CryptoPP::SecByteBlock sign(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock key);

	/// \brief Verifies that the MAC is valid
	/// \param data the data
	/// \param mac the MAC to check
	/// \param key the authentication key
	/// \throw AesEncryptionError when the MAC is invalid
	void verify(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key);

	/// \brief Computes the MAC of a file
	/// \param path the file path
	/// \param key the authentication key
	CryptoPP::SecByteBlock signFile(std::string path, CryptoPP::SecByteBlock key);

	/// \brief Verifies that the MAC of a file is valid
	/// \param path the file path
	/// \param mac the MAC to check
	/// \param key the authentication key
	/// \throw AesEncryptionError when the MAC is invalid
	void verifyFile(std::string path, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key);

	/// \brief Handles exceptions (prints the error message by default)
	/// \param exception the exception object
	void errorHandler(const std::exception& exception);

	/// \brief Checks if encrypted data have the minimum expected size
	/// \param dataLen the size of data
	/// \throw AesEncryptionError when size is invalid
	void checkSize(int dataLen);
};


/// \brief Throws AesEncryptionError exceptions
class AesEncryptionError : public std::exception
{
public:
	explicit AesEncryptionError(const std::string& message);
	virtual ~AesEncryptionError() throw () {}
	virtual const char* what() const throw ();
protected:
	std::string msg;
};


/// \brief Holds SymmetricCipher objects and creates the required cipher
class Ciphers {
public:
	/// \brief SymmetricCipher object (base class)
	typedef std::shared_ptr<CryptoPP::SymmetricCipher> Cipher;
	/// \brief creates a SymmetricCipher object for encryption
	/// \throw AesEncryptionError if the cipher is not available
	static Ciphers::Cipher getCipher(int, int);
	/// \brief sets the key and IV (and feedback in CFB) parameters
	static void setValues(
		Ciphers::Cipher, int, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock
	);
private:
	static std::map<int, Ciphers::Cipher> ciphers;
};


/// \brief Base64 encodes / decodes data
class Base64
{
public:
	/// \brief Base64 encodes data
	static CryptoPP::SecByteBlock encode(const CryptoPP::byte*, size_t);
	/// \brief Base64 decodes data
	static CryptoPP::SecByteBlock decode(const CryptoPP::byte*, size_t, bool);
private:
	/// \brief Checks if encoded data have the right format
	static void checkEncoded(const CryptoPP::byte*, size_t);
};


/// \brief Reads a file in chunks; used for larger files
class FileChunks
{
public:
	/// \param path the file path
	/// \param start the starting position
	/// \param end the ending position (file size - end)
	/// \throw AesEncryptionError when the file is not accessible
	FileChunks(std::string path, size_t start = 0, size_t end = 0);
	/// \brief reads file data
	/// \param data array, size must be equal to FileChunks::chunkSize
	size_t read(CryptoPP::byte* data);
	/// \brief chwcks if thera are more data to read
	bool hasData();
	/// \brief returns the size of a file
	/// \throw AesEncryptionError when the file is not accessible
	static size_t fileSize(std::string path);
	/// \brief the size of data chunks 
	static const size_t chunkSize = 1024;
private:
	/// \brief the file object
	std::ifstream file;
	/// \brief counts the read data
	size_t counter = 0;
	/// \brief the end position
	size_t end = 0;
};


#endif // !AES_ENCRYPTION_H

