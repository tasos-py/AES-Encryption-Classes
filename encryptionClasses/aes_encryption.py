from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode
from binascii import Error as BinasciiError
from os.path import getsize


class AesEncryption:
    '''
    Encrypts - decrypts data using AES CBC/CFB, 128/192/256 bits.
    Requires pycryptodome https://pycryptodome.readthedocs.io
    '''
    _modes = {'CBC': AES.MODE_CBC, 'CFB': AES.MODE_CFB}
    _sizes = (128, 192, 256)
    _salt_len = 16
    _iv_len = 16
    _mac_len = 32
    _block_size = 128
    
    def __init__(self, mode='CBC', size=128): 
        '''
        :param mode: str the AES mode.
        :param size: int the key size.
        :raises ValueError: if the mode or size is invalid.
        '''
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
        
        :param data: string or bytes
        :param password: string
        :returns bytes (raw or base64 encoded)
        '''
        if type(data) is not bytes: 
            data = data.encode()
        if self._mode == 'CBC':
            data = pad(data, AES.block_size)
        
        salt = self._random_bytes(self._salt_len)
        iv = self._random_bytes(self._iv_len)
        aes_key, mac_key = self._keys(password, salt)
        
        cipher = self._cipher(self._mode, aes_key, iv)
        ciphertext = cipher.encrypt(data)
        mac = self._sign(iv + ciphertext, mac_key) 
        encrypted = salt + iv + ciphertext + mac
        
        if self.base64: 
            encrypted = b64encode(encrypted)
        return encrypted
    
    def decrypt(self, data, password):
        '''
        Decrypts data with the supplied password. 
        Data should be bytes or string (base64 encoded bytes) 
        
        :param data: string or bytes
        :param password: string
        :returns bytes
        '''
        try:
            if type(data) is not bytes:
                data = data.encode()
            if self.base64: 
                data = b64decode(data)
            self._check_size(len(data))

            salt, iv, ciphertext, mac = (
                data[:self._salt_len], 
                data[self._salt_len: self._salt_len+self._iv_len], 
                data[self._salt_len+self._iv_len: -self._mac_len], 
                data[-self._mac_len:]
            )
            aes_key, mac_key = self._keys(password, salt)
            
            self._verify(iv + ciphertext, mac, mac_key)
            cipher = self._cipher(self._mode, aes_key, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            if self._mode == 'CBC':
                decrypted = unpad(decrypted, AES.block_size)
            return decrypted
        except (BinasciiError, TypeError, ValueError) as e: 
            self._error_handler(e)
            return b''
    
    def encrypt_file(self, path, password):
        '''
        Encrypts files with the supplied password. 
        The original file is not modified, but an encrypted copy is created.
        Useful for larger files that can't be stored in memory.
        
        :param path: string
        :param password: string
        :returns string new file path
        '''
        new_path = path + '.enc'
        salt = self._random_bytes(self._salt_len)
        iv = self._random_bytes(self._iv_len)
        
        aes_key, mac_key = self._keys(password, salt)
        cipher = self._cipher(self._mode, aes_key, iv)
        hmac = HMAC.new(mac_key, digestmod=SHA256)
        
        try:
            file_size = getsize(path)
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
        except (EnvironmentError, IOError) as e:
            self._error_handler(e)
            return ''
    
    def decrypt_file(self, path, password):
        '''
        Decrypts files with the supplied password. 
        The encrypted file is not modified, but a decrypted copy is created.
        Useful for larger files that can't be stored in memory. 
        
        :param path: string
        :param password: string
        :returns string new file path
        '''    
        try:
            file_size = getsize(path)
            self._check_size(file_size)

            with open(path, 'rb') as f:
                salt, iv = f.read(self._salt_len), f.read(self._iv_len)
                f.seek(file_size - self._mac_len)
                mac = f.read(self._mac_len)
            
            aes_key, mac_key = self._keys(password, salt)
            self._verify_file(path, mac, mac_key) 

            cipher = self._cipher(self._mode, aes_key, iv)    
            new_path = path.rstrip('.enc') + '.dec'
            
            with open(new_path, 'wb') as f:
                start, end = self._salt_len + self._iv_len, self._mac_len
                for data, count in self._read_file_chunks(path, start, end):
                    cleartext = cipher.decrypt(data)                
                    if count == file_size - self._mac_len and self._mode == 'CBC':
                        cleartext = unpad(cleartext, AES.block_size)
                    f.write(cleartext)            
            return new_path
        except (EnvironmentError, IOError, ValueError) as e: 
            self._error_handler(e)
            return ''
    
    def _keys(self, password, salt):
        '''
        Creates a pair of keys from the password and salt. 
        One key is used for encryption, the other for authentication.
        
        :param password: string or bytes
        :param salt: bytes
        :returns tuple[bytes]
        '''
        key = PBKDF2(
            password, salt, self._key_len * 2, self.key_iterations, 
            hmac_hash_module = SHA256
        )
        return (key[:self._key_len], key[self._key_len:])
    
    def _random_bytes(self, size=16): 
        '''
        Creates random bytes. Used for IV and salt generation.
        
        :param size: int, optional
        :returns bytes
        '''
        return get_random_bytes(size)
    
    def _cipher(self, mode, key, iv):
        '''
        Creates an AES object for encryption / decryption.
        
        :param mode: string (CBC or CFB)
        :param key: bytes the encryption key
        :param iv: bytes
        :returns AES object
        '''
        mode = self._modes.get(mode)
        return AES.new(key=key, mode=mode, IV=iv)
    
    def _sign(self, data, key): 
        '''
        Computes the MAC of data.
        
        :param data: bytes
        :param key: bytes HMAC key
        :returns bytes
        '''
        hmac = HMAC.new(key, data, digestmod=SHA256)
        return hmac.digest()
    
    def _sign_file(self, path, key): 
        '''
        Computes the MAC of a file.
        
        :param path: str file path
        :param key: bytes HMAC key
        :returns bytes 
        '''
        hmac = HMAC.new(key, digestmod=SHA256)
        for data, count in self._read_file_chunks(path, self._mac_len):
            hmac.update(data)
        return hmac.digest()
    
    def _verify(self, data, mac, key): 
        '''
        Verifies that the MAC is valid.
        
        :param data: bytes received data
        :param mac: bytes received MAC
        :param key: bytes 
        :raises ValueError: if MACs don't match.  
        '''    
        hmac = HMAC.new(key, data, digestmod=SHA256)
        hmac.verify(mac)
    
    def _verify_file(self, path, mac, key): 
        '''
        Verifies that the MAC is valid.
        
        :param path: str file path
        :param mac: bytes
        :param key: bytes
        :raises ValueError: if MACs don't match.
        '''
        hmac = HMAC.new(key, digestmod=SHA256)
        start, end = self._salt_len, self._mac_len
        for data, count in self._read_file_chunks(path, start, end):
            hmac.update(data)
        hmac.verify(mac)
        
    def _error_handler(self, exception):
        '''
        Handles exceptions (prints the error message by default)
        :param exception: Exception object
        '''
        print(exception)

    def _read_file_chunks(self, path, start=0, end=0):
        '''
        A generator that yields file chunks.
        
        :param path: str file path
        :param start: int, optional the start position in file
        :param end: int, optional the end position in file (filesize - end)
        :yields bytes
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
    
    def _check_size(self, data_len):
        '''
        Checks if encrypted data have the minimum expected size.
        
        :param data_len: int
        :raises ValueError: if size is invalid
        '''
        min_len = AES.block_size * int(self._mode == 'CBC')
        sim_len = self._salt_len + self._iv_len + self._mac_len
        if data_len < min_len + sim_len:
            raise ValueError('Invalid data size')
        if self._mode == 'CBC' and (data_len - sim_len) % AES.block_size:
            raise ValueError('Invalid data size')



