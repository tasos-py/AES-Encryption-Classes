<?php 

/**
* Encrypts - decrypts data using AES CBC/CFB, 128/192/256 bits.
* @author Tasos M. Adamopoulos
*/
class AesEncryption {
    /**
    * @var int $keyIterations the KDF iterations
    * @var bool $base64 accept/return base64 encoded data
    */
    private $modes = array(
        "CBC" => "AES-%d-CBC", "CFB" => "AES-%d-CFB8"
    );
    private $sizes = array(128, 192, 256);
    private $size = 128;
    private $saltLen = 16;
    private $ivLen = 16;
    private $macLen = 32;
    private $blockLen = 16;
    private $mode = "CBC";
    private $keyLen = 16;
    public $keyIterations = 20000;
    public $base64 = true;
    
    /**
    * @param string $mode AES mode (CBC, CFB)
    * @param int $size key size (128, 192, 256)
    * @throws UnexpectedValueException when mode or size is invalid
    */
    public function __construct($mode="CBC", $size=128) {
        if(!array_key_exists(strtoupper($mode), $this->modes)) {
            throw new UnexpectedValueException("Unsupported mode: $mode\n");
        }
        if(!in_array($size, $this->sizes)) {
            throw new UnexpectedValueException("Invalid key size.\n");
        }
        $this->mode = strtoupper($mode);
        $this->keyLen = $size / 8;
        $this->size = $size;
    }
    
    /**
    * Encrypts data, returns raw bytes or base64 encoded string. 
    * @param string $data 
    * @param string $password
    * @return string (salt + iv + ciphertext + hmac)
    */
    public function encrypt($data, $password) {
        $salt = $this->randomBytes($this->saltLen);
        $iv = $this->randomBytes($this->ivLen);
        list($aesKey, $macKey) = $this->keys($password, $salt);
        
        $cipher = sprintf($this->modes[$this->mode], $this->size);        
        $ciphertext = openssl_encrypt($data, $cipher, $aesKey, true, $iv);        
        
        if($ciphertext === false) {
            echo "Encryption failed.\n";
            return "";
        }
        $mac = $this->sign($iv.$ciphertext, $macKey); 
        $encrypted = $salt . $iv . $ciphertext . $mac;
        
        if($this->base64) 
            return base64_encode($encrypted);
        return $encrypted;
    }
    
    /**
    * Decrypts data (base64 encoded or raw). 
    * @param string $data base64 encoded or raw bytes
    * @param string $password
    * @return string decrypted data
    */
    public function decrypt($data, $password) {
        try {
            $data = $this->base64 ? base64_decode($data, true) : $data;
            if($data === false) {
                throw new UnexpectedValueException("Invalid data format.\n");
            }
            $this->checkSize(mb_strlen($data, "8bit"));
            
            list($salt, $iv, $ciphertext, $mac) = array(
                mb_substr($data, 0, $this->saltLen, "8bit"), 
                mb_substr($data, $this->saltLen, $this->ivLen, "8bit"), 
                mb_substr($data, $this->saltLen + $this->ivLen, -$this->macLen, "8bit"), 
                mb_substr($data, -$this->macLen, $this->macLen, "8bit")
            );
            list($aesKey, $macKey) = $this->keys($password, $salt);
            $this->verify($iv.$ciphertext, $mac, $macKey);
            
            $cipher =  sprintf($this->modes[$this->mode], $this->size);
            $decrypted = openssl_decrypt($ciphertext, $cipher, $aesKey, true, $iv);
            
            if($decrypted === false) {
                throw new UnexpectedValueException("Decryption failed.\n");
            }
            return $decrypted;
        } catch(Exception $e) {
            $this->errorHandler($e);
            return "";
        }
    }
    
    /**
    * Encrypts files with the supplied password. 
    * The original file is not modified; an encrypted copy is created.
    * @param string $path file path
    * @param string $password
    * @return string path of encrypted file
    */
    public function encryptFile($path, $password) {
        $newPath = $path . ".enc";
        $salt = $this->randomBytes($this->saltLen);
        $iv = $this->randomBytes($this->ivLen);
        list($aesKey, $macKey) = $this->keys($password, $salt);
        
        try {
            if(($fileSize = filesize($path)) === false) {
                throw new RuntimeException("Can't read file '$path'.\n");
            }
            if(($fp = fopen($newPath, "wb")) === false) {
                throw new RuntimeException("Can't write file '$newPath'.\n");
            }
            fwrite($fp, $salt . $iv);

            $cipher = sprintf($this->modes[$this->mode], $this->size);
            $helper = new AesEncryptionHelper($cipher);
            $hmac = new HmacSha256($macKey, $iv);            

            foreach($this->readFileChunks($path) as list($data, $count)) {
                if($count == $fileSize && $this->mode == "CBC") {
                    $data = $helper->pkcs7Pad($data);
                }
                $ciphertext = $helper->encryptBlock($aesKey, $data, $iv);
                $iv = $helper->getIV($ciphertext);
                $hmac->update($ciphertext);
                fwrite($fp, $ciphertext);
            }
            $mac = $hmac->digest();
            fwrite($fp, $mac);
            fclose($fp);
            
            return $newPath;
        } catch(Exception $e) {
            $this->errorHandler($e);
            return "";
        }
    }
    
    /**
    * Decrypts files with the supplied password. 
    * The encrypted file is not modified; a decrypted copy is created.
    * @param string $path file path
    * @param string $password
    * @return string path of decrypted file
    */
    public function decryptFile($path, $password) {    
        try {
            if(($fp = fopen($path, "rb")) === false) {
                throw new RuntimeException("Can't read file '$path'.\n");
            }
            $fileSize = filesize($path);
            $this->checkSize($fileSize);
            
            list($salt, $iv) = array(fread($fp, $this->saltLen), fread($fp, $this->ivLen));
            fseek($fp, $fileSize - $this->macLen);
            $mac = fread($fp, $this->macLen);
            fclose($fp);

            list($aesKey, $macKey) = $this->keys($password, $salt);
            $this->verifyFile($path, $mac, $macKey);
            
            $newPath = preg_replace("/\.enc$/", ".dec", $path);
            if(($fp = fopen($newPath, "wb")) === false) {
                throw new RuntimeException("Can't write file '$newPath'.\n");
            }
            $cipher = sprintf($this->modes[$this->mode], $this->size);
            $helper = new AesEncryptionHelper($cipher);
            $fileChunks = $this->readFileChunks($path, $this->saltLen+$this->ivLen, $this->macLen);
            
            foreach($fileChunks as list($data, $count)) {
                $decrypted = $helper->decryptBlock($aesKey, $data, $iv);
                $iv = $helper->getIV($data);
                if($count == $fileSize - $this->macLen && $this->mode == "CBC") {
                    $decrypted = $helper->pkcs7UnPad($decrypted);
                }
                fwrite($fp, $decrypted);
            }
            fclose($fp);
            return $newPath;
        } catch(Exception $e) {
            $this->errorHandler($e);
            return "";
        }
    }
    
    /**
    * Creates random bytes for IV and salt generation.
    * @return string
    */
    private function randomBytes($size=16) {
        return openssl_random_pseudo_bytes($size);
    }
    
    /**
    * Creates a pair of keys, one for AES the other for MAC.
    * @param string $password
    * @param string $salt
    * @return array[string]
    */
    private function keys($password, $salt) {
        $hash = "SHA256";
        $keyBytes = openssl_pbkdf2(
            $password, $salt, $this->keyLen * 2, $this->keyIterations, $hash
        );
        $keys = array(
            mb_substr($keyBytes, 0, $this->keyLen, "8bit"), 
            mb_substr($keyBytes, $this->keyLen, $this->keyLen, "8bit")
        );
        return $keys;
    }
    
    /**
    * Creates MAC signature of data.
    * @return string
    */
    private function sign($data, $key) {
        $hash = "SHA256";
        return hash_hmac($hash, $data, $key, true);
    }
    
    /**
    * Creates MAC signature of a file.
    * @return string
    */
    private function signFile($path, $key, $start=0, $end=0) {
        $hmac = new HmacSha256($key);
        foreach($this->readFileChunks($path, $start, $end) as $data_count) {
            $hmac->update($data_count[0]);
        }
        return $hmac->digest();
    }
    
    /**
    * Verifies that the MAC is valid.
    * @throws UnexpectedValueException when MAC is invalid
    */
    private function verify($data, $mac, $key) {
        $dataMac = $this->sign($data, $key);
        
        if(is_callable("hash_equals") && !hash_equals($mac, $dataMac)) {
            throw new UnexpectedValueException("MAC check failed.\n");
        }
        elseif(!$this->compareMacs($mac, $dataMac)) {
            throw new UnexpectedValueException("MAC check failed.\n");
        }
    }
    
    /**
    * Verifies that the MAC of file is valid.
    * @throws UnexpectedValueException when MAC is invalid
    */
    private function verifyFile($path, $mac, $key) {
        $fileMac = $this->signFile($path, $key, $this->saltLen, $this->macLen);
        
        if(is_callable("hash_equals") && !hash_equals($mac, $fileMac)) {
            throw new UnexpectedValueException("MAC check failed.\n");
        }
        elseif (!$this->compareMacs($mac, $fileMac)) {
            throw new UnexpectedValueException("MAC check failed.\n");
        }
    }
    
    /**
    * Handles exceptions (prints the error message by default).
    */
    private function errorHandler($exception) {
        echo $exception->getMessage();
    }
    
    /**
    * Checks if the two MACs are equal; using constant time comparison.
    * @return bool
    */
    private function compareMacs($mac1, $mac2) {
        if(mb_strlen($mac1, "8bit") == mb_strlen($mac2, "8bit")) {
            $result = 0;
            for ($i = 0; $i < mb_strlen($mac1, "8bit"); $i++) {
                $result |= ord($mac1[$i]) ^ ord($mac2[$i]);
            }
            return $result == 0;
        }
        return false;
    }
    
    /**
    * Checks if encrypted data have the minimum expected size.
    * @throws UnexpectedValueException if size is invalid
    */
    private function checkSize($dataLen) {
        $minLen = ($this->mode == "CBC") ? $this->blockLen : 0;
        $simLen = $this->saltLen + $this->ivLen + $this->macLen;
        
        if($dataLen < $simLen + $minLen) {
            throw new UnexpectedValueException("Invalid data size.\n");
        }
        if($this->mode == "CBC" && ($dataLen - $simLen) % $this->blockLen != 0) {
            throw new UnexpectedValueException("Invalid data size.\n");
        }
    }
    
    /**
    * A generator that yields file chunks. 
    * Chunk size must be a nultiple of 16 in CBC mode.
    * @param string $path file path
    * @param int $start optional, the start position in file
    * @param int $end optional, the end position (filesize - end)
    */
    public function readFileChunks($path, $start=0, $end=0) {
        $size = 1024;
        $end = filesize($path) - $end;
        $f = fopen($path, "rb");
        $counter = ($start > 0) ? mb_strlen(fread($f, $start), "8bit") : $start; 
        
        while($counter < $end) {
            $buffer = ($end - $counter > $size) ? $size : $end - $counter;
            $data = fread($f, $buffer);
            $counter += mb_strlen($data, "8bit");
            yield array($data, $counter);
        }
        fclose($f);
    }
}


/**
* A wrapper class for openssl encrypt / decrypt functions, 
* that can be used to encrypt multiple blocks.
* This class is a helper of AesEncryption (when  encrypting files) 
* and should NOT be used on its own.
*/
class AesEncryptionHelper {
    private $cipher;
    private $blockSize = 16;
    
    /**
    * @param string $cipher cipher method
    */
    function __construct($cipher) {
        $this->cipher = $cipher;
    }
    
    /**
    * Returns an encrypted block.
    * @param string $data must be a multiple of 16 in CBC mode
    * @param string $iv (IV or previous block)
    * @throws UnexpectedValueException on failure
    */
    public function encryptBlock($key, $data, $iv) {
        $iv = $this->getIV($iv);
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;      
        $encrypted = openssl_encrypt($data, $this->cipher, $key, $options, $iv);
        if($encrypted === false) {
            throw new UnexpectedValueException("Encryption failed.\n");
        }
        return $encrypted;
    }
    
    /**
    * Returns a decrypted block.
    * @param string $data must be a multiple of 16 in CBC mode
    * @param string $iv (IV or previous block)
    * @throws UnexpectedValueException on failure
    */
    public function decryptBlock($key, $data, $iv) {
        $iv = $this->getIV($iv);
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;    
        $decrypted = openssl_decrypt($data, $this->cipher, $key, $options, $iv);
        if($decrypted === false) {
            throw new UnexpectedValueException("Decryption failed.\n");
        }
        return $decrypted;
    }
    
    /**
    * Pads data for CBC mode.
    */
    public function pkcs7Pad($data) {
        $padding = $this->blockSize - (mb_strlen($data, "8bit") % $this->blockSize);
        return $data . str_repeat(chr($padding), $padding);
    }

    /**
    * Removes padding from decrypted data.
    * @throws UnexpectedValueException if padding is invalid.
    */
    public function pkcs7Unpad($data) {
        $padding = ord(mb_substr($data, -1, 1, "8bit"));
        $pad = mb_substr($data, -1 * $padding, $padding, "8bit");
        if($padding < 1 || $padding > 16 || substr_count($pad, chr($padding)) != $padding) {
            throw new UnexpectedValueException("Padding is invalid");
        }
        return mb_substr($data, 0, -$padding, "8bit");
    }
    
    /**
    * Returns the last 16 bytes of a block to use as IV.
    */
    public function getIV($block) {
        $iv = mb_substr($block, -$this->blockSize, $this->blockSize, "8bit");
        return $iv;
    }
}


/**
* Computes the MAC of multiple chunks of data.
* Used by AesEncryption class when encrypting files, as it needs to include 
* only specific file parts, so hash_hmac_file can't be used.
*/
class HmacSha256 {
    private $inner;
    private $outer;
    
    /**
    * @param string $key the HMAC key
    * @param string $data optional, initiates the HMAC with data
    */
    function __construct($key, $data=null) {
        $key = $this->padKey($key);
        $this->inner = hash_init("SHA256");
        $this->outer = hash_init("SHA256");
        $innerKey = $this->keyTrans($key, 0x36);
        $outerKey = $this->keyTrans($key, 0x5C);
        hash_update($this->inner, $innerKey);
        hash_update($this->outer, $outerKey);
        $this->update($data);
    }
    
    /**
    * Updates MAC with new data.
    * @param string $data
    */
    public function update($data) {
        hash_update($this->inner, $data);
    }
    
    /**
    * Returns the computed MAC.
    * @param bool $raw optional, return raw bytes or hex string
    * @return string 
    */
    public function digest($raw=true) {
        $ihf = hash_final($this->inner, true);
        hash_update($this->outer, $ihf);
        return hash_final($this->outer, $raw);
    }
    
    /**
    * Translates the key (shifts characters).
    * @param string $key
    * @param string $value the xor value
    * @return string 
    */
    private function keyTrans($key, $value) {
        $intXval_chr = function($n) use($value) { return chr($n ^ $value); };
        $int_chr = function($n) { return chr($n); };
        $values = array_map($intXval_chr, range(0, 256));
        $trans = array_combine(array_map($int_chr, range(0, 256)), $values);
        return strtr($key, $trans);
    }
    
    /** 
    * Pads the key to match the hash block size.
    * @param string $key
    * @return string
    */
    private function padKey($key) {
        if(mb_strlen($key, "8bit") > 64) {
            $key = hash("SHA256", $key, true);
        }
        $padding = str_repeat("\0", 64 - mb_strlen($key, "8bit"));
        return $key . $padding;
    }
}

?>
