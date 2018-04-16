from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256 
from Crypto import Random
from base64 import b64encode, b64decode


class AesCbc: 
	'''
	Encrypts / decrypts data using AES CBC 128 / 256.
	'''
	_sizes = (128, 256)
	_salt_size = 16
	_iv_size = 16
	_mac_size = 32
	
	def __init__(self, size=128): 
		'''
		:param size: int, the key size.
		:raises ValueError: if the size is invalid.
		'''
		if size not in self._sizes: 
			raise ValueError('Key size must be {} or {} bits.'.format(*self._sizes))
		self._key_size = size
		self.rounds = 1000
		self.b64 = True
	
	def encrypt(self, data, password):
		'''
		Encrypts data (strings or bytes), returns a base64 encoded string or raw bytes. 
		
		:param data: string or bytes
		:param password: string
		:returns bytes or string (base64)
		'''
		data = self._pkcs_pad(data if type(data) is bytes else data.encode())
		iv, salt = self._ivgen(self._iv_size), self._ivgen(self._salt_size)
		aes_key, mac_key = self._keygen(password, salt)
		
		cipher = AES.new(key=aes_key, mode=AES.MODE_CBC, IV=iv)
		encrypted = cipher.encrypt(data)
		mac = self._sign(iv + encrypted, mac_key) 
		new_data = salt + iv + encrypted + mac
		
		if self.b64: 
			new_data = b64encode(new_data)
		return new_data
	
	def decrypt(self, data, password):
		'''
		Decrypts data - data could be bytes or string (base64 encoded bytes) 
		
		:param data: string or bytes
		:param password: string
		:returns bytes or None
		'''
		try:
			if type(data) is not bytes:
				data = data.encode()
			if self.b64: 
				data = b64decode(data)
			if len(data) < self._iv_size + self._salt_size + AES.block_size + self._mac_size: 
				raise ValueError("Not enough data!")
			
			salt, iv, encrypted, mac = (
				data[:self._iv_size], 
				data[self._iv_size:self._iv_size+self._salt_size], 
				data[self._iv_size+self._salt_size:-self._mac_size], 
				data[-self._mac_size:]
			)
			
			if len(encrypted) % AES.block_size != 0: 
				raise ValueError('Ciphertext must be a multiple of %d bytes in length.' % AES.block_size)
			aes_key, mac_key = self._keygen(password, salt)
			if not self._verify(iv + encrypted, mac, mac_key): 
				raise Exception('Verification failed.')
			
			cipher = AES.new(key=aes_key, mode=AES.MODE_CBC, IV=iv)
			decrypted = cipher.decrypt(encrypted)
			return self._pkcs_unpad(decrypted)
		except Exception as e: 
			print(e)
	
	def _keygen(self, password, salt):
		'''
		Creates a pair of keys from the password. 
		
		:param password: string
		:param salt: bytes
		:returns tuple[bytes]
		'''
		key = PBKDF2(password, salt, int(self._key_size/8)*2, self.rounds)
		return (key[:int(self._key_size/8)], key[int(self._key_size/8):])
	
	def _ivgen(self, size=16): 
		'''
		Creates random bytes.
		
		:param size: int, optional
		:returns bytes
		'''
		return Random.new().read(size)
	
	def _sign(self, data, key): 
		'''
		Creates HMAC signature.
		
		:param data: bytes
		param key: bytes
		returns bytes
		'''
		hmac = HMAC.new(key, data, digestmod=SHA256)
		return hmac.digest()
	
	def _verify(self, data, mac, key): 
		'''
		Preforms HMAC verification.
		
		:param data: bytes
		:param mac: bytes
		:param key: bytes
		:returns bool
		'''
		return mac == self._sign(data, key)
	
	def _pkcs_pad(self, data): 
		'''PKCS7 padding.'''
		padding = AES.block_size - (len(data) % AES.block_size)
		return data + (chr(padding) * padding).encode()
	
	def _pkcs_unpad(self, data): 
		'''Removes PKCS7 padding.'''
		padding = ord(data[-1:])
		return data[:-padding]
	
	def create_password(self, size=16):
		'''
		Creates random 0-9a-zA-Z strings.
		
		:param size: int, optional
		:returns str
		'''
		random_bytes = self._ivgen(size)
		password = b64encode(random_bytes)[:size]
		return password.decode()


if __name__ == '__main__' : 
	from sys import argv
	
	aes = AesCbc()
	e = aes.encrypt("word", "pass")
	d = aes.decrypt(e, "pass")
	print(e.decode())
	print(d.decode())

