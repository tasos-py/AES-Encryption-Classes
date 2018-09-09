from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode
from binascii import Error as Base64Error
from os.path import getsize


class AesEncryption:
    '''
    Encrypts data and files using AES CBC/CFB, 128/192/256 bits.
    Requires pycryptodome https://pycryptodome.readthedocs.io
    '''
    def __init__(self, mode = 'CBC', size = 128): 
        '''
        :param mode: str the AES mode.
        :param size: int the key size.
        :raises ValueError: if the mode or size is invalid.
        '''
        self._modes = {'CBC': AES.MODE_CBC, 'CFB': AES.MODE_CFB}
        self._sizes = (128, 192, 256)
        self._salt_len = 16
        self._iv_len = 16
        self._mac_len = 32

        if mode.upper() not in self._modes: 
            raise ValueError('Unsupported mode: ' + mode)
        if size not in self._sizes: 
            raise ValueError('Invalid key size')
        self._mode = mode.upper()
        self._key_len = int(size / 8)

        self.key_iterations = 20000
        self.base64 = True
    
    def encrypt(self, data, password):
        '''
        Encrypts data with the supplied password. 
        Returns raw or base64 encoded bytes.

        :param data: string or bytes
        :param password: string or bytes
        :returns bytes salt[16] + iv[16] + ciphertext[n] + mac[32]
        '''
        try:
            data = self._to_bytes(data)
            password = self._to_bytes(password)
            
            if self._mode == 'CBC':
                data = pad(data, AES.block_size)
            
            salt = self._random_bytes(self._salt_len)
            aes_key, mac_key = self._keys(password, salt)

            iv = self._random_bytes(self._iv_len)
            cipher = self._cipher(aes_key, iv)
            ciphertext = cipher.encrypt(data)

            mac = self._sign(iv + ciphertext, mac_key) 
            encrypted = salt + iv + ciphertext + mac
            
            if self.base64: 
                encrypted = b64encode(encrypted)
            return encrypted
        except AttributeError as e:
            self._error_handler(e)
    
    def decrypt(self, data, password):
        '''
        Decrypts data with the supplied password. 
        
        :param data: bytes or string (base64 encoded bytes) 
        :param password: string
        :returns bytes
        '''
        try:
            data = self._to_bytes(data)
            password = self._to_bytes(password)
            
            if self.base64: 
                data = b64decode(data)

            salt, iv, ciphertext, mac = (
                data[:self._salt_len], 
                data[self._salt_len: self._salt_len+self._iv_len], 
                data[self._salt_len+self._iv_len: -self._mac_len], 
                data[-self._mac_len:]
            )
            aes_key, mac_key = self._keys(password, salt)
            
            self._verify(iv + ciphertext, mac, mac_key)
            cipher = self._cipher(aes_key, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            if self._mode == 'CBC':
                decrypted = unpad(decrypted, AES.block_size)
            return decrypted
        except (AttributeError, ValueError, Base64Error, TypeError) as e: 
            self._error_handler(e)
    
    def encrypt_file(self, path, password):
        '''
        Encrypts files with the supplied password. 
        The original file isn't modified; an encrypted copy is created.
        Useful for larger files that can't be stored in memory.
        
        :param path: string
        :param password: string or bytes
        :returns string new file path
        '''
        try:
            password = self._to_bytes(password)
            salt = self._random_bytes(self._salt_len)
            iv = self._random_bytes(self._iv_len)
            
            aes_key, mac_key = self._keys(password, salt)
            cipher = self._cipher(aes_key, iv)
            hmac = HMAC.new(mac_key, digestmod = SHA256)
            
            file_size = getsize(path)
            new_path = path + '.enc'

            with open(new_path, 'wb') as f:
                f.write(salt + iv)
                hmac.update(iv)
                
                for data, count in self._read_file_chunks(path):
                    if count == file_size and self._mode == 'CBC':
                        data = pad(data, AES.block_size)
                    encrypted = cipher.encrypt(data)
                    f.write(encrypted)
                    hmac.update(encrypted)
                
                mac = hmac.digest()
                f.write(mac)
            return new_path
        except (AttributeError, IOError) as e:
            self._error_handler(e)
    
    def decrypt_file(self, path, password):
        '''
        Decrypts files with the supplied password. 
        The original file isn't modified; a decrypted copy is created.
        Useful for larger files that can't be stored in memory. 
        
        :param path: string
        :param password: string or bytes
        :returns string new file path
        '''    
        try:
            password = self._to_bytes(password)
            file_size = getsize(path)

            with open(path, 'rb') as f:
                salt, iv = f.read(self._salt_len), f.read(self._iv_len)
                f.seek(file_size - self._mac_len)
                mac = f.read(self._mac_len)
            
            aes_key, mac_key = self._keys(password, salt)
            self._verify_file(path, mac, mac_key) 

            cipher = self._cipher(aes_key, iv)  
            new_path = path.rstrip('.enc') + '.dec'

            with open(new_path, 'wb') as f:
                beg, end = self._salt_len + self._iv_len, self._mac_len
                for data, count in self._read_file_chunks(path, beg, end):
                    plaintext = cipher.decrypt(data)                
                    if count == file_size - self._mac_len and self._mode == 'CBC':
                        plaintext = unpad(plaintext, AES.block_size)
                    f.write(plaintext)
            return new_path
        except (AttributeError, ValueError, IOError) as e: 
            self._error_handler(e)
    
    def _keys(self, password, salt):
        '''
        Creates a pair of keys; one for AES the other for MAC.
        '''
        key = PBKDF2(
            password, salt, self._key_len * 2, self.key_iterations, 
            hmac_hash_module = SHA256
        )
        return (key[:self._key_len], key[self._key_len:])
    
    def _random_bytes(self, size = 16): 
        '''
        Creates random bytes; used for IV and salt generation.
        '''
        return get_random_bytes(size)
    
    def _cipher(self, key, iv):
        '''
        Creates an AES object for encryption / decryption.
        '''
        return AES.new(key, self._modes[self._mode], IV = iv)
    
    def _sign(self, data, key): 
        '''
        Computes the MAC of data.
        '''
        hmac = HMAC.new(key, data, digestmod = SHA256)
        return hmac.digest()
    
    def _sign_file(self, path, key): 
        '''
        Computes the MAC of a file.
        '''
        hmac = HMAC.new(key, digestmod = SHA256)
        for data, _ in self._read_file_chunks(path, self._mac_len):
            hmac.update(data)
        return hmac.digest()
    
    def _verify(self, data, mac, key): 
        '''
        Verifies that the MAC is valid.
        
        :raises ValueError: if MACs don't match.  
        '''    
        hmac = HMAC.new(key, data, digestmod = SHA256)
        hmac.verify(mac)
    
    def _verify_file(self, path, mac, key): 
        '''
        Verifies that the MAC is valid.
        
        :raises ValueError: if MACs don't match.
        '''
        hmac = HMAC.new(key, digestmod = SHA256)
        beg, end = self._salt_len, self._mac_len
        for data, _ in self._read_file_chunks(path, beg, end):
            hmac.update(data)
        hmac.verify(mac)
    
    def _error_handler(self, exception):
        '''
        Handles exceptions (prints the error message by default)
        '''
        print(exception)

    def _read_file_chunks(self, path, start = 0, end = 0):
        '''
        A generator that yields file chunks.
        '''
        size = 1024
        end = getsize(path) - end
        with open(path, 'rb') as f:
            counter = (len(f.read(start)))
            while counter < end: 
                buffer = size if end - counter > size else end - counter
                data = f.read(buffer)
                counter += len(data)
                yield (data, counter)
    
    def _to_bytes(self, data):
        '''
        Covnerts unicode strings to byte strings.
        '''
        if type(data) is not bytes:
            data = data.encode()
        return data


