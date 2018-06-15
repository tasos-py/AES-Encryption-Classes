from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256 
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from binascii import Error as BinasciiError
from os.path import getsize


class AesEncryption: 
	'''
	Encrypts - decrypts data using AES CBC/CFB, 128/192/256 bits.
	Requires pycryptodome or pycrypto.
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
		if self._mode == "CBC":
			data = self._pkcs_pad(data)
		
		salt = self._random_bytes(self._salt_len)
		iv = self._random_bytes(self._iv_len)
		aes_key, mac_key = self._keys(password, salt)
		
		cipher = self._cipher(self._mode, aes_key, iv)
		ciphertext = cipher.encrypt(data)
		hmac = self._sign(iv + ciphertext, mac_key) 
		new_data = salt + iv + ciphertext + hmac
		
		if self.base64: 
			new_data = b64encode(new_data)
		return new_data
	
	def decrypt(self, data, password):
		'''
		Decrypts data with the supplied password. 
		Data should be bytes or string (base64 encoded bytes) 
		
		:param data: string or bytes
		:param password: string
		:returns bytes or None
		'''
		try:
			if type(data) is not bytes:
				data = data.encode()
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
			cipher = self._cipher(self._mode, aes_key, iv)
			decrypted = cipher.decrypt(ciphertext)
			
			if self._mode == "CBC":
				decrypted = self._pkcs_unpad(decrypted)
			return decrypted
		except (BinasciiError, TypeError, ValueError) as e: 
			print(e)
	
	def encrypt_file(self, path, password):
		'''
		Encrypts files with the supplied password. 
		The original file is not modified, but an encrypted copy is created.
		Useful for larger files that can't be stored in memory.
		
		:param path: string
		:param password: string
		:returns string (new file name)
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
					if count == file_size and self._mode == "CBC":
						data = self._pkcs_pad(data)
					encrypted = cipher.encrypt(data)
					f.write(encrypted)
					hmac.update(encrypted)
				
				mac = hmac.digest()
				f.write(mac)
			return new_path
		except (FileNotFoundError, PermissionError) as e:
			print(e)
	
	def decrypt_file(self, path, password):
		'''
		Decrypts files with the supplied password. 
		The encrypted file is not modified, but a decrypted copy is created.
		Useful for larger files that can't be stored in memory. 
		
		:param path: string
		:param password: string
		:returns string (new file name)
		'''	
		try:
			file_size = getsize(path)
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
					if count == file_size - self._mac_len and self._mode == "CBC":
						cleartext = self._pkcs_unpad(cleartext)
					f.write(cleartext)
			return new_path
		except (FileNotFoundError, PermissionError, ValueError) as e: 
			print(e)
	
	def _keys(self, password, salt):
		'''
		Creates a pair of keys from the password and salt. 
		One key is used for encryption, the other for authentication.
		
		:param password: string or bytes
		:param salt: bytes
		:returns tuple[bytes]
		'''
		key = PBKDF2(password, salt, self._key_len * 2, self.key_iterations)
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
		:param key: bytes
		:param iv: bytes
		:returns Cipher
		'''
		mode = self._modes.get(mode)
		return AES.new(key=key, mode=mode, IV=iv)
	
	def _sign(self, data, key): 
		'''
		Computes the MAC of data.
		
		:param data: bytes
		:param key: bytes
		:returns bytes
		'''
		return HMAC.new(key, data, digestmod=SHA256).digest()
	
	def _sign_file(self, path, key, start=0, end=0): 
		'''
		Computes the MAC of a file.
		
		:param path: str
		:param key: bytes
		:returns bytes
		'''
		hmac = HMAC.new(key, digestmod=SHA256)
		for data, count in self._read_file_chunks(path, start, end):
			hmac.update(data)
		return hmac.digest()
	
	def _verify(self, data, mac, key): 
		'''
		Verifies that the MAC is valid.
		
		:param data: bytes
		:param mac: bytes
		:param key: bytes
		:raises ValueError: if MACs don't match.  
		'''	
		if hasattr(HMAC.new(b''), 'verify'):
			HMAC.new(key, data, digestmod=SHA256).verify(mac)
		elif not self._compare_macs(mac, self._sign(data, key)):
			raise ValueError("MAC check failed.")
	
	def _verify_file(self, path, mac, key): 
		'''
		Verifies that the MAC is valid.
		
		:param path: str
		:param mac: bytes
		:param key: bytes
		:raises ValueError: if MACs don't match.
		'''
		hmac = HMAC.new(key, digestmod=SHA256)
		start, end = self._salt_len, self._mac_len
		for data, count in self._read_file_chunks(path, start, end):
			hmac.update(data)
		
		if hasattr(hmac, 'verify'):
			hmac.verify(mac)
		elif not self._compare_macs(mac, hmac.digest()):
			raise ValueError("MAC check failed.")
	
	def _compare_macs(self, mac1, mac2):
		'''
		Checks if the MACs are equal; using constant time comparisson.
		
		:param mac1: bytes
		:param mac2: bytes
		:returns bool
		'''
		result = 0
		if len(mac1) != len(mac2):
			return False
		for i in range(len(mac1)):
			result |= ord(mac1[i:i+1]) ^ ord(mac2[i:i+1])
		return result == 0
	
	def _read_file_chunks(self, path, start=0, end=0):
		'''
		A generator that yields file chunks.
		
		:param path: str
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
	
	def _pkcs_pad(self, data): 
		'''
		Preforms PKCS7 padding for CBC mode.
		'''
		padding = AES.block_size - (len(data) % AES.block_size)
		return data + (chr(padding) * padding).encode()
	
	def _pkcs_unpad(self, data): 
		'''
		Removes PKCS7 padding. 
		:raises ValueError: if the padding is invalid
		'''
		padding = ord(data[-1:])
		pad = [i if type(i) is int else ord(i) for i in data[-padding:]]
		
		if 1 < padding > 16 or any(i != padding for i in pad):
			raise ValueError("Padding is invalid")
		return data[:-padding]



