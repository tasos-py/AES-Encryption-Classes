#include "aes_encryption.h"

#include <iostream>
#include <regex>

#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hmac.h>
#include <cryptopp/base64.h>


AesEncryption::AesEncryption(std::string mode, int size)
{
	std::transform(mode.begin(), mode.end(), mode.begin(), ::toupper);
	if (this->modes.count(mode) == 0) {
		throw std::runtime_error((mode + " mode is not supported").c_str());
	}
	if (std::find(std::begin(sizes), std::end(sizes), size) == std::end(sizes)) {
		throw std::runtime_error("Invalid key size");
	}
	this->mode = mode;
	this->keyLen = size / 8;
}

CryptoPP::SecByteBlock AesEncryption::encrypt(const unsigned char* data, int size, std::string password)
{
	try {
		CryptoPP::SecByteBlock salt = this->randomBytes(AesEncryption::saltLen);
		CryptoPP::SecByteBlock iv = this->randomBytes(AesEncryption::ivLen);

		CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->keyLen);
		this->keys(password, salt, aesKey, macKey);
		
		Ciphers::Cipher cipher = this->cipher(aesKey, iv, AesEncryption::ENCRYPT);
		CryptoPP::StreamTransformationFilter stf(*cipher, NULL);
		stf.Put(data, size);
		stf.MessageEnd();

		CryptoPP::SecByteBlock ciphertext(stf.MaxRetrievable());
		stf.Get(ciphertext, ciphertext.size());

		CryptoPP::SecByteBlock mac = this->sign(iv + ciphertext, macKey);
		CryptoPP::SecByteBlock encrypted = salt + iv + ciphertext + mac;
		if (this->base64) {
			encrypted = Base64::encode(encrypted.data(), encrypted.size());
		}
		return encrypted;
	}
	catch (const CryptoPP::Exception& e) {
		this->errorHandler(e);
	}
	return CryptoPP::SecByteBlock(0);
}

CryptoPP::SecByteBlock AesEncryption::encrypt(std::string data, std::string password) 
{
	return this->encrypt((unsigned char*)data.data(), data.size(), password);
}

CryptoPP::SecByteBlock AesEncryption::decrypt(const unsigned char* data, int size, std::string password)
{
	try {
		CryptoPP::SecByteBlock decoded(data, size);
		if (this->base64) 
			decoded = Base64::decode(data, size, true);
		this->checkSize(decoded.size());

		CryptoPP::SecByteBlock salt(decoded.data(), AesEncryption::saltLen);
		CryptoPP::SecByteBlock iv(decoded.data() + AesEncryption::saltLen, AesEncryption::ivLen);
		CryptoPP::SecByteBlock ciphertext(
			decoded.data() + AesEncryption::saltLen + AesEncryption::ivLen,
			decoded.size() - AesEncryption::saltLen - AesEncryption::ivLen - AesEncryption::macLen
		);
		CryptoPP::SecByteBlock mac(
			decoded.data() + AesEncryption::saltLen + AesEncryption::ivLen + ciphertext.size(),
			AesEncryption::macLen
		);

		CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->keyLen);
		this->keys(password, salt, aesKey, macKey);
		this->verify(iv + ciphertext, mac, macKey);

		Ciphers::Cipher cipher = this->cipher(aesKey, iv, AesEncryption::DECRYPT);
		CryptoPP::StreamTransformationFilter stf(*cipher.get(), NULL);

		stf.Put(ciphertext.data(), ciphertext.size());
		stf.MessageEnd();

		CryptoPP::SecByteBlock plaintext(stf.MaxRetrievable());
		stf.Get(plaintext.data(), plaintext.size());
		return plaintext;
	}
	catch (const CryptoPP::Exception& e) {
		this->errorHandler(e);
	}
	catch (const AesEncryptionError& e) {
		this->errorHandler(e);
	}
	return CryptoPP::SecByteBlock(0);
}

CryptoPP::SecByteBlock AesEncryption::decrypt(std::string data, std::string password)
{
	return this->decrypt((unsigned char*)data.data(), data.size(), password);
}

std::string AesEncryption::encryptFile(std::string path, std::string password)
{
	try {
		std::string newPath = path + ".enc";
		CryptoPP::SecByteBlock salt = this->randomBytes(AesEncryption::saltLen);
		CryptoPP::SecByteBlock iv = this->randomBytes(AesEncryption::ivLen);

		CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->keyLen);
		this->keys(password, salt, aesKey, macKey);

		std::ofstream ofs(newPath, std::ios::binary | std::ios::trunc);
		if(ofs.fail())
			throw AesEncryptionError("Can't write file " + newPath);

		Ciphers::Cipher cipher = this->cipher(aesKey, iv, AesEncryption::ENCRYPT);
		CryptoPP::StreamTransformationFilter stf(*cipher, NULL);

		CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, this->keyLen);
		FileChunks ifs(path);
		CryptoPP::byte chunk[FileChunks::chunkSize];

		hmac.Update(iv.data(), iv.size());
		ofs.write((char*)salt.data(), AesEncryption::saltLen);
		ofs.write((char*)iv.data(), AesEncryption::ivLen);

		while (ifs.hasData()) {
			size_t chunkSize = ifs.read(chunk);
			stf.Put(chunk, chunkSize);

			CryptoPP::SecByteBlock ciphertext(stf.MaxRetrievable());
			stf.Get(ciphertext, ciphertext.size());

			ofs.write((char*)ciphertext.data(), ciphertext.size());
			hmac.Update(ciphertext, ciphertext.size());
		}
		stf.MessageEnd();

		CryptoPP::SecByteBlock ciphertext(stf.MaxRetrievable());
		stf.Get(ciphertext, ciphertext.size());

		ofs.write((char*)ciphertext.data(), ciphertext.size());
		hmac.Update(ciphertext, ciphertext.size());

		CryptoPP::byte mac[AesEncryption::macLen];
		hmac.Final(mac);
		ofs.write((char*)mac, AesEncryption::macLen);
		ofs.close();

		return newPath;
	}
	catch (const CryptoPP::Exception& e) {
		this->errorHandler(e);
	}
	catch (const AesEncryptionError& e) {
		this->errorHandler(e);
	}
	return "";
}

std::string AesEncryption::decryptFile(std::string path, std::string password)
{
	try {
		std::string newPath = std::regex_replace(path, std::regex(".enc$"), ".dec");
		int fsize = FileChunks::fileSize(path);
		this->checkSize(fsize);

		std::ifstream ifs(path, std::ios::binary);
		if (ifs.fail())
			throw AesEncryptionError("Can't read file " + path);

		CryptoPP::SecByteBlock salt(AesEncryption::saltLen);
		CryptoPP::SecByteBlock iv(AesEncryption::ivLen);
		CryptoPP::SecByteBlock mac(AesEncryption::macLen);

		ifs.read((char*)salt.data(), AesEncryption::saltLen);
		ifs.read((char*)iv.data(), AesEncryption::ivLen);
		ifs.seekg(fsize - AesEncryption::macLen, ifs.beg);
		ifs.read((char*)mac.data(), AesEncryption::macLen);
		ifs.close();

		CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->keyLen);
		this->keys(password, salt, aesKey, macKey);
		this->verifyFile(path, mac, macKey);

		Ciphers::Cipher cipher = this->cipher(aesKey, iv, DECRYPT);
		CryptoPP::StreamTransformationFilter stf(*cipher, NULL);

		FileChunks fc(path, saltLen + ivLen, macLen);
		CryptoPP::byte chunk[FileChunks::chunkSize];

		std::ofstream ofs(newPath, std::ios::binary | std::ios::trunc);
		if (ofs.fail())
			throw AesEncryptionError("Can't write file " + newPath);

		while (fc.hasData()) {
			size_t chunkSize = fc.read(chunk);
			stf.Put(chunk, chunkSize);

			CryptoPP::SecByteBlock ciphertext(stf.MaxRetrievable());
			stf.Get(ciphertext, ciphertext.size());
			ofs.write((char*)ciphertext.data(), ciphertext.size());
		}
		stf.MessageEnd();

		CryptoPP::SecByteBlock ciphertext(stf.MaxRetrievable());
		stf.Get(ciphertext, ciphertext.size());
		ofs.write((char*)ciphertext.data(), ciphertext.size());

		return newPath;
	}
	catch (const CryptoPP::Exception& e) {
		this->errorHandler(e);
	}
	catch (const AesEncryptionError& e) {
		this->errorHandler(e);
	}
	return "";
}

CryptoPP::SecByteBlock AesEncryption::randomBytes(size_t size)
{
	CryptoPP::SecByteBlock rb(size);
	CryptoPP::AutoSeededRandomPool prng;

	prng.GenerateBlock(rb, size);
	return rb;
}

void AesEncryption::keys(std::string password, const CryptoPP::byte* salt, 
	CryptoPP::SecByteBlock& aesKey, CryptoPP::SecByteBlock& macKey) 
{
	CryptoPP::SecByteBlock key(this->keyLen * 2);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;

	pbkdf2.DeriveKey(
		key.data(), key.size(), 0x00, (CryptoPP::byte*)password.data(), password.size(),
		salt, this->saltLen, this->keyIterations
	);
	aesKey.Assign(key.begin(), this->keyLen);
	macKey.Assign(key.begin() + this->keyLen, this->keyLen);
}

std::shared_ptr<CryptoPP::SymmetricCipher> AesEncryption::cipher(
	CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, int encMode)
{
	int aesMode = this->modes.at(this->mode);
	Ciphers::Cipher cipher = Ciphers::getCipher(aesMode, encMode);

	Ciphers::setValues(cipher, aesMode, key, iv);
	return cipher;
}

CryptoPP::SecByteBlock AesEncryption::sign(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock key)
{
	CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, this->keyLen);
	CryptoPP::SecByteBlock mac(AesEncryption::macLen);

	hmac.Update(data, data.size());
	hmac.Final(mac);
	return mac;
}

void AesEncryption::verify(
	CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key)
{
	CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, this->keyLen);

	hmac.Update(data.data(), data.size());
	if (!hmac.Verify(mac)) 
		throw AesEncryptionError("MAC check failed");
}

CryptoPP::SecByteBlock AesEncryption::signFile(std::string path, CryptoPP::SecByteBlock key)
{
	CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, this->keyLen);
	FileChunks fc(path, AesEncryption::saltLen);
	CryptoPP::byte chunk[FileChunks::chunkSize];

	while (fc.hasData()) {
		size_t chunkSize = fc.read(chunk);
		hmac.Update(chunk, chunkSize);
	}
	CryptoPP::byte mac[AesEncryption::macLen];
	hmac.Final(mac);

	return CryptoPP::SecByteBlock(mac, AesEncryption::macLen);
}

void AesEncryption::verifyFile(std::string path, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key) 
{
	CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, this->keyLen);
	FileChunks fc(path, AesEncryption::saltLen, AesEncryption::macLen);
	CryptoPP::byte chunk[FileChunks::chunkSize];

	while (fc.hasData()) {
		size_t chunkSize = fc.read(chunk);
		hmac.Update(chunk, chunkSize);
	}
	if (!hmac.Verify(mac)) 
		throw AesEncryptionError("MAC check failed");
}

void AesEncryption::errorHandler(const std::exception& exception)
{
	std::cout << exception.what() << std::endl;
}

void AesEncryption::checkSize(int dataLen)
{
	int simLen = this->saltLen + this->ivLen + this->macLen;
	int minLen = (this->mode == "CBC") ? CryptoPP::AES::BLOCKSIZE : 0;

	if (dataLen < simLen + minLen) {
		throw AesEncryptionError("Invalid data size");
	}
	if (this->mode == "CBC" && (dataLen - simLen) % CryptoPP::AES::BLOCKSIZE != 0) {
		throw AesEncryptionError("Invalid data size");
	}
}

// AesEncryptionError methods //

AesEncryptionError::AesEncryptionError(const std::string& message)
{
	msg = message;
}

const char* AesEncryptionError::what() const throw ()
{
	return msg.c_str();
}

// Ciphers methods //

Ciphers::Cipher Ciphers::getCipher(int aesMode, int encMode)
{
	int key = aesMode * 10 + encMode;
	if (Ciphers::ciphers.find(key) == Ciphers::ciphers.end()) {
		throw AesEncryptionError("Invalid mode or method");
	}
	Ciphers::Cipher cipher = Ciphers::ciphers.at(key);
	return cipher;
}

void Ciphers::setValues(
	Ciphers::Cipher cipher, int mode, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv)
{
	CryptoPP::ConstByteArrayParameter IV(iv);
	CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::IV(), IV);

	if (mode == AesEncryption::CFB) {
		params(CryptoPP::Name::FeedbackSize(), 1);
	}
	cipher->SetKey(key, key.size(), params);
}

std::map<int, Ciphers::Cipher> Ciphers::ciphers = {
	{ 11, Ciphers::Cipher(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption()) },
	{ 12, Ciphers::Cipher(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption()) },
	{ 21, Ciphers::Cipher(new CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption()) },
	{ 22, Ciphers::Cipher(new CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption()) }
};

// Base64 methods //

CryptoPP::SecByteBlock Base64::encode(const CryptoPP::byte* data, size_t size)
{
	CryptoPP::Base64Encoder encoder;
	encoder.Put(data, size);
	encoder.MessageEnd();

	CryptoPP::SecByteBlock encoded(encoder.MaxRetrievable());
	encoder.Get(encoded.data(), encoded.size());
	return encoded;
}

CryptoPP::SecByteBlock Base64::decode(const CryptoPP::byte* data, size_t size, bool check)
{
	if (check) 
		Base64::checkEncoded(data, size);
	
	CryptoPP::Base64Decoder decoder;
	decoder.Put(data, size);
	decoder.MessageEnd();

	CryptoPP::SecByteBlock decoded(decoder.MaxRetrievable());
	decoder.Get(decoded.data(), decoded.size());
	return decoded;
}

void Base64::checkEncoded(const CryptoPP::byte* data, size_t size)
{
	std::string validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n";
	size_t cleanSize = size;

	for (size_t i = 0; i < size; i++) {
		cleanSize -= (size_t)(data[i] == '\n');

		if (validChars.find(data[i]) == std::string::npos) 
			throw AesEncryptionError("Invalid base64 format");
	}
	if (cleanSize % 4 != 0)
		throw AesEncryptionError("Invalid base64 format");
}

// FileChunks methods //

FileChunks::FileChunks(std::string path, size_t start, size_t end)
{
	this->file = std::ifstream(path, std::ios::binary);
	if (this->file.fail()) {
		throw AesEncryptionError("Can't read file " + path);
	}
	this->counter = start;
	this->end = FileChunks::fileSize(path) - end;
	this->file.seekg(start, this->file.beg);
}

size_t FileChunks::read(CryptoPP::byte* data)
{
	int count = (end - counter > chunkSize) ? chunkSize : end - counter;

	this->file.read((char*)data, chunkSize);
	int read = this->file.gcount();
	this->counter += read;

	if (!this->hasData()) {
		this->file.close();
	}
	return (read < count) ? read : count;
}

bool FileChunks::hasData()
{
	return (counter < end && !this->file.eof());
}

size_t FileChunks::fileSize(std::string path)
{
	std::ifstream ifs(path, std::ios::binary);
	if (ifs.fail()) {
		throw AesEncryptionError("Can't open file " + path);
	}
	ifs.seekg(0, std::ios::end);
	size_t size = ifs.tellg();
	ifs.close();

	return size;
}



