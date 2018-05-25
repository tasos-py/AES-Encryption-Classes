from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256 
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


class AesEncryption: 
	'''
	Encrypts and decrypts data using AES CBC/CFB, 128/192/256 bits.
	'''
	_modes = {'CBC': AES.MODE_CBC, 'CFB': AES.MODE_CFB}
	_sizes = (128, 192, 256)
	_salt_len = 16
	_iv_len = 16
	_mac_len = 32
	
	def __init__(self, mode='CBC', size=128): 
		'''
		:param mode: str, the mode.
		:param size: int, the key size.
		:raises ValueError: if the mode is not supported or the size is invalid.
		'''
		if mode.upper() not in self._modes: 
			raise ValueError('Unsupported mode selected: {}.'.format(mode))
		if size not in self._sizes: 
			raise ValueError('Key size must be 128, 192 or 256 bits.')
		self._mode = mode.upper()
		self._key_size = size
		self._block_size = 128
		self.key = None
		self.rounds = 100000
		self.base64 = True
	
	def encrypt(self, data, password):
		'''
		Encrypts data with the selected mode. 
		
		:param data: string or bytes
		:param password: string
		:returns bytes (raw or base64)
		'''
		if type(data) is not bytes: 
			data = data.encode()
		if self._mode == "CBC":
			data = self._pkcs_pad(data)
		
		salt = self.random_bytes(self._salt_len)
		iv = self.random_bytes(self._iv_len)
		self.key, mac_key = self._keys(password, salt)
		
		mode = self._modes.get(self._mode)
		cipher = AES.new(key=self.key, mode=mode, IV=iv)
		ciphertext = cipher.encrypt(data)
		mac = self._sign(iv + ciphertext, mac_key) 
		new_data = salt + iv + ciphertext + mac
		
		if self.base64: 
			new_data = b64encode(new_data)
		return new_data
	
	def decrypt(self, data, password):
		'''
		Decrypts data with the selected mode. 
		Data could be bytes or string (base64 encoded) 
		
		:param data: string or bytes
		:param password: string
		:returns bytes or None
		'''
		try:
			if type(data) is not bytes:
				data = data.encode()
			if self.base64: 
				data = b64decode(data)
			min_len = int(self._mode == "CBC") * int(self._block_size / 8)
			if len(data) < self._salt_len + self._iv_len + min_len + self._mac_len: 
				raise Exception("Not enough data!")
			
			salt, iv, ciphertext, mac = (
				data[:self._salt_len], 
				data[self._salt_len: self._salt_len+self._iv_len], 
				data[self._salt_len+self._iv_len: -self._mac_len], 
				data[-self._mac_len:]
			)
			self.key, mac_key = self._keys(password, salt)
			if not self._verify(iv + ciphertext, mac, mac_key): 
				raise ValueError("MAC Verification failed.")
			
			mode = self._modes.get(self._mode)
			cipher = AES.new(key=self.key, mode=mode, IV=iv)
			decrypted = cipher.decrypt(ciphertext)
			if self._mode == "CBC":
				decrypted = self._pkcs_unpad(decrypted)
			return decrypted
		except Exception as e: 
			print(e)
	
	def random_bytes(self, size=16): 
		'''
		Creates random bytes. 
		Used for IV or password generation.
		
		:param size: int, optional
		:returns bytes
		'''
		return get_random_bytes(size)
	
	def _keys(self, password, salt):
		'''
		Creates a pair of keys from the password. 
		One key is used for AES, the other for MAC
		
		:param password: string or bytes
		:param salt: bytes
		:returns tuple[bytes]
		'''
		key_size = int(self._key_size / 8)
		key = PBKDF2(password, salt, key_size * 2, self.rounds)
		return (key[:key_size], key[key_size:])
	
	def _sign(self, data, key): 
		'''
		Creates MAC signature.
		
		:param data: bytes
		param key: bytes
		returns bytes
		'''
		hmac = HMAC.new(key, data, digestmod=SHA256)
		return hmac.digest()
	
	def _verify(self, data, mac, key): 
		'''
		Verifies that the MAC is valid.
		
		:param data: bytes
		:param mac: bytes
		:param key: bytes
		:returns bool
		'''
		return mac == self._sign(data, key)
	
	def _pkcs_pad(self, data): 
		'''Preforms PKCS padding.'''
		padding = AES.block_size - (len(data) % AES.block_size)
		return data + (chr(padding) * padding).encode()
	
	def _pkcs_unpad(self, data): 
		'''Removes PKCS padding.'''
		padding = ord(data[-1:])
		return data[:-padding]


