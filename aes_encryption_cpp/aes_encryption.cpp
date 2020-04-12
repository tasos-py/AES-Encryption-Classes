#include "aes_encryption.hpp"

#include <iostream>
#include <regex>

#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/base64.h>


AesEncryption::AesEncryption(std::string mode, unsigned int size)
{
    std::transform(mode.begin(), mode.end(), mode.begin(), ::toupper);

    if (this->modes.count(mode) == 0) {
        throw std::runtime_error((mode + " is not supported!").c_str());
    }
    if (std::find(std::begin(sizes), std::end(sizes), size) == std::end(sizes)) {
        throw std::runtime_error("Invalid key size!");
    }
    this->mode = mode;
    this->keyLen = size / 8;
}

CryptoPP::SecByteBlock AesEncryption::encrypt(
    CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock password)
{
    try {
        CryptoPP::SecByteBlock salt = this->randomBytes(saltLen);
        CryptoPP::SecByteBlock iv = this->randomBytes(ivLen);

        CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->macKeyLen);
        this->keys(password, salt, aesKey, macKey);

        Ciphers::Cipher cipher = this->cipher(aesKey, iv, AesEncryption::ENCRYPT);
        CryptoPP::StreamTransformationFilter stf(*cipher, NULL);
        stf.Put(data.data(), data.size());
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
    catch (const AesEncryptionError& e) {
        this->errorHandler(e);
    }
    return CryptoPP::SecByteBlock(0);
}

CryptoPP::SecByteBlock AesEncryption::encrypt(
    const unsigned char* data, size_t dataSize, const unsigned char* password, size_t passwordSize)
{
    CryptoPP::SecByteBlock _data(data, dataSize), _password(password, passwordSize);
    return this->encrypt(_data, _password);
}

CryptoPP::SecByteBlock AesEncryption::encrypt(std::string data, std::string password)
{
    CryptoPP::SecByteBlock _data((unsigned char*)data.data(), data.size());
    CryptoPP::SecByteBlock _password((unsigned char*)password.data(), password.size());
    return this->encrypt(_data, _password);
}

CryptoPP::SecByteBlock AesEncryption::encrypt(CryptoPP::SecByteBlock data)
{
    return this->encrypt(data, CryptoPP::SecByteBlock(0));
}

CryptoPP::SecByteBlock AesEncryption::encrypt(const unsigned char* data, size_t dataSize)
{
    return this->encrypt(CryptoPP::SecByteBlock(data, dataSize), CryptoPP::SecByteBlock(0));
}

CryptoPP::SecByteBlock AesEncryption::encrypt(std::string data)
{
    CryptoPP::SecByteBlock _data((unsigned char*)data.data(), data.size());
    return this->encrypt(_data, CryptoPP::SecByteBlock(0));
}

CryptoPP::SecByteBlock AesEncryption::decrypt(
    CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock password)
{
    try {
        if (this->base64) {
            data = Base64::decode(data.data(), data.size(), true);
        }
        this->checkSize(data.size());

        CryptoPP::SecByteBlock salt(data.data(), saltLen);
        CryptoPP::SecByteBlock iv(data.data() + saltLen, ivLen);
        CryptoPP::SecByteBlock ciphertext(
            data.data() + saltLen + ivLen, data.size() - saltLen - ivLen - macLen
        );
        CryptoPP::SecByteBlock mac(
            data.data() + saltLen + ivLen + ciphertext.size(), macLen
        );

        CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->macKeyLen);
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

CryptoPP::SecByteBlock AesEncryption::decrypt(
    const unsigned char* data, size_t dataSize, const unsigned char* password, size_t passwordSize)
{
    CryptoPP::SecByteBlock _data(data, dataSize), _password(password, passwordSize);
    return this->decrypt(_data, _password);
}

CryptoPP::SecByteBlock AesEncryption::decrypt(std::string data, std::string password)
{
    CryptoPP::SecByteBlock _data((unsigned char*)data.data(), data.size());
    CryptoPP::SecByteBlock _password((unsigned char*)password.data(), password.size());
    return this->decrypt(_data, _password);
}

CryptoPP::SecByteBlock AesEncryption::decrypt(CryptoPP::SecByteBlock data)
{
    return this->decrypt(data, CryptoPP::SecByteBlock(0));
}

CryptoPP::SecByteBlock AesEncryption::decrypt(const unsigned char* data, size_t dataSize)
{
    return this->decrypt(CryptoPP::SecByteBlock(data, dataSize), CryptoPP::SecByteBlock(0));
}

CryptoPP::SecByteBlock AesEncryption::decrypt(std::string data)
{
    CryptoPP::SecByteBlock _data((unsigned char*)data.data(), data.size());
    return this->decrypt(_data, CryptoPP::SecByteBlock(0));
}

std::string AesEncryption::encryptFile(std::string path, CryptoPP::SecByteBlock password)
{
    try {
        CryptoPP::SecByteBlock salt = this->randomBytes(saltLen);
        CryptoPP::SecByteBlock iv = this->randomBytes(ivLen);

        CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->macKeyLen);
        this->keys(password, salt, aesKey, macKey);

        std::string newPath = path + ".enc";
        std::ofstream ofs(newPath, std::ios::binary | std::ios::trunc);
        if (ofs.fail()) {
            throw AesEncryptionError("Can't write file " + newPath);
        }
        Ciphers::Cipher cipher = this->cipher(aesKey, iv, AesEncryption::ENCRYPT);
        CryptoPP::StreamTransformationFilter stf(*cipher, NULL);
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(macKey, this->macKeyLen);

        FileChunks ifs(path);
        CryptoPP::byte chunk[FileChunks::chunkSize];

        hmac.Update(iv.data(), iv.size());
        ofs.write((char*)salt.data(), saltLen);
        ofs.write((char*)iv.data(), ivLen);

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

        CryptoPP::byte mac[macLen];
        hmac.Final(mac);
        ofs.write((char*)mac, macLen);
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

std::string AesEncryption::encryptFile(std::string path, std::string password)
{
    CryptoPP::SecByteBlock _password((unsigned char*)password.data(), password.size());
    return this->encryptFile(path, _password);
}

std::string AesEncryption::encryptFile(std::string path)
{
    return this->encryptFile(path, CryptoPP::SecByteBlock(0));
}

std::string AesEncryption::decryptFile(std::string path, CryptoPP::SecByteBlock password)
{
    try {
        int fsize = FileChunks::fileSize(path);
        this->checkSize(fsize);

        std::ifstream ifs(path, std::ios::binary);
        if (ifs.fail())
            throw AesEncryptionError("Can't read file " + path);

        CryptoPP::SecByteBlock salt(saltLen);
        CryptoPP::SecByteBlock iv(ivLen);
        CryptoPP::SecByteBlock mac(macLen);

        ifs.read((char*)salt.data(), saltLen);
        ifs.read((char*)iv.data(), ivLen);
        ifs.seekg(fsize - macLen, ifs.beg);
        ifs.read((char*)mac.data(), macLen);
        ifs.close();

        CryptoPP::SecByteBlock aesKey(this->keyLen), macKey(this->macKeyLen);
        this->keys(password, salt, aesKey, macKey);
        this->verifyFile(path, mac, macKey);

        Ciphers::Cipher cipher = this->cipher(aesKey, iv, DECRYPT);
        CryptoPP::StreamTransformationFilter stf(*cipher, NULL);

        FileChunks fc(path, saltLen + ivLen, macLen);
        CryptoPP::byte chunk[FileChunks::chunkSize];
        std::string newPath = std::regex_replace(path, std::regex(".enc$"), ".dec");

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

std::string AesEncryption::decryptFile(std::string path, std::string password)
{
    CryptoPP::SecByteBlock _password((unsigned char*)password.data(), password.size());
    return this->decryptFile(path, _password);
}

std::string AesEncryption::decryptFile(std::string path)
{
    return this->decryptFile(path, CryptoPP::SecByteBlock(0));
}

void AesEncryption::setMasterKey(CryptoPP::SecByteBlock key, bool raw)
{
    try {
        if (!raw) {
            key = Base64::decode(key.data(), key.size(), true);
        }
        this->masterKey = key;
    }
    catch (const AesEncryptionError& e) {
        this->errorHandler(e);
    }
}

void AesEncryption::setMasterKey(std::string key, bool raw)
{
    CryptoPP::SecByteBlock _key((unsigned char*)key.data(), key.size());
    return this->setMasterKey(_key, raw);
}

CryptoPP::SecByteBlock AesEncryption::getMasterKey(bool raw)
{
    if (this->masterKey.empty()) {
        this->errorHandler(AesEncryptionError("The key is not set!"));
    }
    else if (!raw) {
        return Base64::encode(this->masterKey.data(), this->masterKey.size());
    }
    return this->masterKey;
}

CryptoPP::SecByteBlock AesEncryption::randomKeyGen(size_t keyLen, bool raw)
{
    this->masterKey = this->randomBytes(keyLen);
    if (!raw) {
        return Base64::encode(this->masterKey.data(), this->masterKey.size());
    }
    return this->masterKey;
}

void AesEncryption::keys(CryptoPP::SecByteBlock password, const CryptoPP::byte* salt,
    CryptoPP::SecByteBlock& aesKey, CryptoPP::SecByteBlock& macKey)
{
    CryptoPP::SecByteBlock dkey(this->keyLen + this->macKeyLen);
    if (!password.empty()) {
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> kdf;
        kdf.DeriveKey(
            dkey.data(), dkey.size(), 0x00, password, password.size(),
            salt, this->saltLen, this->keyIterations
        );
    }
    else if (!this->masterKey.empty()) {
        CryptoPP::HKDF<CryptoPP::SHA256> kdf;
        kdf.DeriveKey(
            dkey.data(), dkey.size(), this->masterKey, this->masterKey.size(), 
            salt, this->saltLen, NULL, 0
        );
    }
    else {
        throw AesEncryptionError("No password or key spacified!");
    }
    aesKey.Assign(dkey.begin(), this->keyLen);
    macKey.Assign(dkey.begin() + this->keyLen, this->macKeyLen);
}

CryptoPP::SecByteBlock AesEncryption::randomBytes(size_t size)
{
    CryptoPP::SecByteBlock rb(size);
    CryptoPP::AutoSeededRandomPool prng;

    prng.GenerateBlock(rb, size);
    return rb;
}

std::shared_ptr<CryptoPP::SymmetricCipher> AesEncryption::cipher(
    CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, unsigned int encMode)
{
    unsigned int aesMode = this->modes.at(this->mode);
    Ciphers::Cipher cipher = Ciphers::getCipher(aesMode, encMode);

    Ciphers::setValues(cipher, aesMode, key, iv);
    return cipher;
}

CryptoPP::SecByteBlock AesEncryption::sign(CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock key)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, macKeyLen);
    CryptoPP::SecByteBlock mac(macLen);

    hmac.Update(data, data.size());
    hmac.Final(mac);
    return mac;
}

void AesEncryption::verify(
    CryptoPP::SecByteBlock data, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, macKeyLen);

    hmac.Update(data.data(), data.size());
    if (!hmac.Verify(mac)) {
        throw AesEncryptionError("MAC check failed!");
    }
}

CryptoPP::SecByteBlock AesEncryption::signFile(std::string path, CryptoPP::SecByteBlock key)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, macKeyLen);
    FileChunks fc(path, saltLen);
    CryptoPP::byte chunk[FileChunks::chunkSize];

    while (fc.hasData()) {
        size_t chunkSize = fc.read(chunk);
        hmac.Update(chunk, chunkSize);
    }
    CryptoPP::byte mac[macLen];
    hmac.Final(mac);

    return CryptoPP::SecByteBlock(mac, macLen);
}

void AesEncryption::verifyFile(std::string path, CryptoPP::SecByteBlock mac, CryptoPP::SecByteBlock key)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, macKeyLen);
    FileChunks fc(path, saltLen, macLen);
    CryptoPP::byte chunk[FileChunks::chunkSize];

    while (fc.hasData()) {
        size_t chunkSize = fc.read(chunk);
        hmac.Update(chunk, chunkSize);
    }
    if (!hmac.Verify(mac)) {
        throw AesEncryptionError("MAC check failed!");
    }
}

void AesEncryption::errorHandler(const std::exception& exception)
{
    std::cout << exception.what() << std::endl;
}

void AesEncryption::checkSize(unsigned int dataLen)
{
    unsigned int simLen = this->saltLen + this->ivLen + this->macLen;
    unsigned int ctLen = (this->mode == "CBC") ? CryptoPP::AES::BLOCKSIZE : 0;

    if (dataLen < simLen + ctLen) {
        throw AesEncryptionError("Invalid data size!");
    }
    if (this->mode == "CBC" && (dataLen - simLen) % CryptoPP::AES::BLOCKSIZE != 0) {
        throw AesEncryptionError("Invalid data size!");
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

Ciphers::Cipher Ciphers::getCipher(unsigned int aesMode, unsigned int encMode)
{
    if (Ciphers::ciphers.find(aesMode + encMode) == Ciphers::ciphers.end()) {
        throw AesEncryptionError("Invalid mode or method!");
    }
    Ciphers::Cipher cipher = Ciphers::ciphers.at(aesMode + encMode);
    return cipher;
}

void Ciphers::setValues(
    Ciphers::Cipher cipher, unsigned int mode, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv)
{
    CryptoPP::ConstByteArrayParameter IV(iv);
    CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::IV(), IV);

    if (mode == AesEncryption::CFB) {
        params(CryptoPP::Name::FeedbackSize(), 1);
    }
    cipher->SetKey(key, key.size(), params);
}

std::map<unsigned int, Ciphers::Cipher> Ciphers::ciphers = {
    { 11, Ciphers::Cipher(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption()) },
    { 12, Ciphers::Cipher(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption()) },
    { 21, Ciphers::Cipher(new CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption()) },
    { 22, Ciphers::Cipher(new CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption()) }
};

// Base64 methods //

CryptoPP::SecByteBlock Base64::encode(const CryptoPP::byte* data, size_t size)
{
    CryptoPP::Base64Encoder encoder(NULL, false);
    encoder.Put(data, size);
    encoder.MessageEnd();

    CryptoPP::SecByteBlock encoded(encoder.MaxRetrievable());
    encoder.Get(encoded.data(), encoded.size());
    return encoded;
}

CryptoPP::SecByteBlock Base64::decode(const CryptoPP::byte* data, size_t size, bool check)
{
    if (check) {
        Base64::checkEncoded(data, size);
    }
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

    if (size % 4 != 0) {
        throw AesEncryptionError("Invalid base64 format!");
    }
    for (size_t i = 0; i < size; i++) {
        if (validChars.find(data[i]) == std::string::npos) {
            throw AesEncryptionError("Invalid base64 format!");
        }
    }
}

// FileChunks methods //

FileChunks::FileChunks(std::string path, size_t start, size_t end)
{
    this->file = std::ifstream(path, std::ios::binary);
    if (this->file.fail()) {
        throw AesEncryptionError("Can't read file " + path);
    }
    this->pos = start;
    this->end = FileChunks::fileSize(path) - end;
    this->file.seekg(start, this->file.beg);
}

size_t FileChunks::read(CryptoPP::byte* data)
{
    int count = (end - pos > chunkSize) ? chunkSize : end - pos;

    this->file.read((char*)data, chunkSize);
    int read = this->file.gcount();
    this->pos += read;

    if (!this->hasData()) {
        this->file.close();
    }
    return (read < count) ? read : count;
}

bool FileChunks::hasData()
{
    return (pos < end && !this->file.eof());
}

size_t FileChunks::fileSize(std::string path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (ifs.fail()) {
        throw AesEncryptionError("Can't access file " + path);
    }
    ifs.seekg(0, std::ios::end);
    size_t size = ifs.tellg();
    ifs.close();

    return size;
}


