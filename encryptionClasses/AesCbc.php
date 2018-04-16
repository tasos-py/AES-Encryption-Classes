<?php 

/**
* Encrypts and decrypts data using AES-CBC 128 / 256.
*/
class AesCbc {	
	/**
	* @var int $sizes 
	* @var int $ivSize 
	* @var int $ivSize 
	* @var int $macSize 
	* @var int $blockSize 
	* @var int $rounds 
	* @var bool $b64 
	*/
	private $sizes = array(128, 256);
	private $ivSize = 16;
	private $macSize = 32;
	private $blockSize = 16;
	private $keySize = 128;
	public $rounds = 100000;
	public $b64 = true;
	
	/**
	* Class constructor
	* @param int $size optional
	* @throws UnexpectedValueException
	*/
	public function __construct($size=128) {
		if(!in_array($size, $this->sizes)) 
			throw new UnexpectedValueException("Key size must be 128 or 256 bits.\n");
		$this->keySize = $size;
		$this->cipher = "AES-$this->keySize-CBC";
	}
	
	/**
	* Encrypts data and returns a base64 encoded string or raw bytes string. 
	* @param string $data 
	* @param string $password
	* @return string (salt + iv + ciphertext + hmac)
	*/
	public function encrypt($data, $password) {
		$iv = $this->IVGen($this->ivSize);
		$salt = $this->IVGen($this->ivSize);
		list($aes_key, $mac_key) = $this->keyGen($password, $salt);
		
		$encrypted = openssl_encrypt($data, $this->cipher, $aes_key, true, $iv);
		$mac = $this->sign($iv.$encrypted, $mac_key); 
		$new_data = $salt.$iv.$encrypted.$mac;
		if($this->b64) 
			$new_data = base64_encode($new_data);
		return $new_data;
	}
	
	/**
	* Decrypts encrypted data. Data can be base64 string or raw bytes.
	* @param string $data 
	* @param string $password
	* @return string|null
	*/
	public function decrypt($data, $password) {
		try {
			if($this->b64) 
				$data = $this->decode($data);
			if(strlen($data) < $this->ivSize + $this->ivSize + $this->blockSize + $this->macSize) 
				throw new Exception("Not enough data!\n");
			
			list($salt, $iv, $encrypted, $mac) = array(
				substr($data, 0, $this->ivSize), 
				substr($data, $this->ivSize, $this->ivSize), 
				substr($data, ($this->ivSize + $this->ivSize), -$this->macSize), 
				substr($data, -$this->macSize)
			);
			
			if(strlen($encrypted) % $this->blockSize != 0) 
				throw new UnexpectedValueException(
					"Ciphertext must be a multiple of $this->blockSize bytes in length.\n"
				);
			list($aes_key, $mac_key) = $this->keyGen($password, $salt);
			if(!$this->verify($iv.$encrypted, $mac, $mac_key)) 
				throw new Exception("Verification failed.\n");
			
			$decrypted = openssl_decrypt($encrypted, $this->cipher, $aes_key, true, $iv);
			return $decrypted;
		} catch(Exception $e) {
			echo $e->getMessage() . "\n";
		}
	}
	
	/**
	* Creates a pair of keys from the password.
	* @param string $password
	* @param string $salt
	* @return array[string]
	*/
	private function keyGen($password, $salt) {
		$key_size = $this->keySize/8;
		$key = openssl_pbkdf2($password, $salt, $key_size*2, $this->rounds, "SHA1");
		$keys = array(substr($key, 0, $key_size), substr($key, $key_size));
		return $keys;
	}
	
	/**
	* Creates random bytes.
	* @param int $size optional
	* @return string
	*/
	private function IVGen($size=16) {
		return openssl_random_pseudo_bytes($size);
	}
	
	/**
	* Creates HMAC signature.
	* @param string $data
	* @param string $key
	* @return string
	*/
	private function sign($data, $key) {
		$hmac = hash_hmac('SHA256', $data, $key, true);
		return $hmac;
	}
	
	/**
	* Preforms HMAC verification.
	* @param string $data
	* @param string $mac
	* @param string $key
	* @return bool
	*/
	private function verify($data, $mac, $key) {
		$data_mac = $this->sign($data, $key);
		return $data_mac === $mac;
	}
	
	/** 
	* Decodes data - if it's base64 encoded. 
	* @param string $data
	* @return string
	*/
	private function decode($data) {
		$decoded = base64_decode($data, true);
		return ($decoded) ? $decoded : $data;
	}
}

?>
