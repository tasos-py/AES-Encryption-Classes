<?php 

/**
* Encrypts and decrypts data using AES CBC/CFB, 128/192/256 bits.
*/
class AesEncryption {	
	/**
	* @var string $key 
	* @var int $rounds 
	* @var bool $base64 
	*/
	private $modes = array("CBC" => "CBC", "CFB" => "CFB8");
	private $sizes = array(128, 192, 256);
	private $saltLen = 16;
	private $ivLen = 16;
	private $macLen = 32;
	private $blockSize = 128;
	private $keySize = 128;
	private $mode = "CBC";
	public $key = null;
	public $rounds = 100000;
	public $base64 = true;
	
	/**
	* @param string $mode optional
	* @param int $size optional
	* @throws UnexpectedValueException
	*/
	public function __construct($mode="CBC", $size=128) {
		if(!array_key_exists(strtoupper($mode), $this->modes)) {
			throw new UnexpectedValueException("Unsupported mode selected: $mode.\n");
		}
		if(!in_array($size, $this->sizes)) {
			throw new UnexpectedValueException("Key size must be 128, 192 or 256 bits.\n");
		}
		$this->mode = strtoupper($mode);
		$this->keySize = $size;
	}
	
	/**
	* Encrypts data with the selected method, 
	* returns a base64 encoded string or raw bytes string. 
	* @param string $data 
	* @param string $password
	* @return string 
	*/
	public function encrypt($data, $password) {
		$salt = $this->randomBytes($this->saltLen);
		$iv = $this->randomBytes($this->ivLen);
		list($this->key, $mac_key) = $this->keys($password, $salt);
		
		$mode = $this->modes[$this->mode];
		$cipher = "AES-$this->keySize-$mode";
		$ciphertext = openssl_encrypt($data, $cipher, $this->key, true, $iv);
		$mac = $this->sign($iv.$ciphertext, $mac_key); 
		$new_data = $salt.$iv.$ciphertext.$mac;
		
		if($this->base64) 
			$new_data = base64_encode($new_data);
		return $new_data;
	}
	
	/**
	* Decrypts data with the selected method. 
	* Data can be base64 string or raw bytes.
	* @param string $data 
	* @param string $password
	* @return string|null
	*/
	public function decrypt($data, $password) {
		try {
			if($this->base64) 
				$data = base64_decode($data, true);
			if($data === false) 
				throw new Exception("Failed to decode the data.\n");
			$minLen = (int)($this->mode == "CBC") * ($this->blockSize / 8);
			if(strlen($data) < $this->saltLen + $this->ivLen + $minLen + $this->macLen) 
				throw new UnexpectedValueException("Not enough data!\n");
			
			list($salt, $iv, $ciphertext, $mac) = array(
				substr($data, 0, $this->saltLen), 
				substr($data, $this->saltLen, $this->ivLen), 
				substr($data, ($this->saltLen + $this->ivLen), -$this->macLen), 
				substr($data, -$this->macLen)
			);
			list($this->key, $mac_key) = $this->keys($password, $salt);
			if(!$this->verify($iv.$ciphertext, $mac, $mac_key)) 
				throw new UnexpectedValueException("MAC verification failed.\n");
			
			$mode = $this->modes[$this->mode];
			$cipher = "AES-$this->keySize-$mode";
			$decrypted = openssl_decrypt($ciphertext, $cipher, $this->key, true, $iv);
			return $decrypted;
		} catch(Exception $e) {
			echo $e->getMessage() . "\n";
		}
	}
	
	/**
	* Creates random bytes for IV or password generation.
	* @param int $size optional
	* @return string
	*/
	public function randomBytes($size=16) {
		return openssl_random_pseudo_bytes($size);
	}
	
	/**
	* Creates a pair of keys from the password and salt.
	* One key is used for AES, the other for MAC.
	* @param string $password
	* @param string $salt
	* @return array[string]
	*/
	private function keys($password, $salt) {
		$keySize = $this->keySize / 8;
		$key = openssl_pbkdf2($password, $salt, $keySize * 2, $this->rounds, "SHA1");
		$keys = array(substr($key, 0, $keySize), substr($key, $keySize));
		return $keys;
	}
	
	/**
	* Creates MAC signature.
	* @param string $data
	* @param string $key
	* @return string
	*/
	private function sign($data, $key) {
		$hmac = hash_hmac("SHA256", $data, $key, true);
		return $hmac;
	}
	
	/**
	* Verifies that the MAC is valid.
	* @param string $data
	* @param string $mac
	* @param string $key
	* @return bool
	*/
	private function verify($data, $mac, $key) {
		$data_mac = $this->sign($data, $key);
		return $mac === $data_mac;
	}
}

?>
