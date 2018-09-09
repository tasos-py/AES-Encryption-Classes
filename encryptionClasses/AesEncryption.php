<?php

/**
 * Encrypts data and files using AES CBC/CFB, 128/192/256 bits.
 * @author Tasos M. Adamopoulos
 */
class AesEncryption {
    private $modes = array(
        "CBC" => "AES-%d-CBC", "CFB" => "AES-%d-CFB8"
    );
    private $sizes = array(128, 192, 256);
    private $saltLen = 16;
    private $ivLen = 16;
    private $macLen = 32;
    private $blockLen = 16;
    private $mode;
    private $keyLen;

    /** The number of kdf iterations */
    public $keyIterations = 20000;

    /** Accept / return base64 encoded data */
    public $base64 = true;
    
    /**
     * @param string $mode AES mode (CBC, CFB)
     * @param int $size key size (128, 192, 256)
     * @throws UnexpectedValueException when mode or size is invalid
     */
    public function __construct($mode = "CBC", $size = 128) {
        $mode = strtoupper($mode);
        if(!array_key_exists($mode, $this->modes)) {
            throw new UnexpectedValueException("Unsupported mode: $mode\n");
        }
        if(!in_array($size, $this->sizes)) {
            throw new UnexpectedValueException("Invalid key size.\n");
        }
        $this->mode = $mode;
        $this->keyLen = $size / 8;
    }
    
    /**
     * Encrypts data, returns raw bytes or base64 encoded string. 
     * @param string $data 
     * @param string $password
     * @return string encrypted data (salt + iv + ciphertext + hmac)
     */
    public function encrypt($data, $password) {
        $salt = $this->randomBytes($this->saltLen);
        $iv = $this->randomBytes($this->ivLen);
        list($aesKey, $macKey) = $this->keys($password, $salt);
        
        $method = $this->cipher();       
        $ciphertext = openssl_encrypt($data, $method, $aesKey, true, $iv);    
        
        if($ciphertext === false) {
            $this->errorHandler("Encryption failed.\n");
            return null;
        }
        $mac = $this->sign($iv.$ciphertext, $macKey); 
        $encrypted = $salt . $iv . $ciphertext . $mac;
        
        if($this->base64) 
            $encrypted = base64_encode($encrypted);
        return $encrypted;
    }
    
    /**
     * Decrypts data with the supplied password. 
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
            
            list($salt, $iv, $ciphertext, $mac) = array(
                mb_substr($data, 0, $this->saltLen, "8bit"), 
                mb_substr($data, $this->saltLen, $this->ivLen, "8bit"), 
                mb_substr($data, $this->saltLen + $this->ivLen, -$this->macLen, "8bit"), 
                mb_substr($data, -$this->macLen, $this->macLen, "8bit")
            );
            list($aesKey, $macKey) = $this->keys($password, $salt);
            $this->verify($iv.$ciphertext, $mac, $macKey);
            
            $method = $this->cipher();
            $decrypted = openssl_decrypt($ciphertext, $method, $aesKey, true, $iv);
            
            if($decrypted === false) {
                throw new UnexpectedValueException("Decryption failed.\n");
            }
            return $decrypted;
        } catch(Exception $e) {
            $this->errorHandler($e);
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
        try {
            if(($fileSize = filesize($path)) === false) {
                throw new RuntimeException("Can't read file '$path'.\n");
            }
            if(($fp = fopen($newPath, "wb")) === false) {
                throw new RuntimeException("Can't write file '$newPath'.\n");
            }
            fwrite($fp, $salt . $iv);

            list($aesKey, $macKey) = $this->keys($password, $salt);
            $cipher = new Cipher($this->cipher(), Cipher::Encrypt, $aesKey, $iv);
            $hmac = new HmacSha256($macKey, $iv);

            foreach($this->readFileChunks($path) as list($data, $count)) {
                if($count == $fileSize && $this->mode == "CBC") {
                    $data = $cipher->pad($data);
                }
                $ciphertext = $cipher->update($data);
                $hmac->update($ciphertext);
                fwrite($fp, $ciphertext);
            }
            $mac = $hmac->digest();
            fwrite($fp, $mac);
            fclose($fp);
            
            return $newPath;
        } catch(Exception $e) {
            $this->errorHandler($e);
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
            $cipher = new Cipher($this->cipher(), Cipher::Decrypt, $aesKey, $iv);

            list($beg, $end) = array($this->saltLen + $this->ivLen, $this->macLen);
            foreach($this->readFileChunks($path, $beg, $end) as list($data, $count)) {
                $plaintext = $cipher->update($data);
                if($count == $fileSize - $this->macLen && $this->mode == "CBC") {
                    $plaintext = $cipher->unpad($plaintext);
                }
                fwrite($fp, $plaintext);
            }
            fclose($fp);
            return $newPath;
        } catch(Exception $e) {
            $this->errorHandler($e);
        }
    }

    /**
     * Creates a pair of keys, for encryption and autthentication.
     */
    private function keys($password, $salt) {
        $keyBytes = openssl_pbkdf2(
            $password, $salt, $this->keyLen * 2, $this->keyIterations, "SHA256"
        );
        $keys = array(
            mb_substr($keyBytes, 0, $this->keyLen, "8bit"), 
            mb_substr($keyBytes, $this->keyLen, $this->keyLen, "8bit")
        );
        return $keys;
    }

    /**
     * Creates random bytes for IV and salt generation.
     */
    private function randomBytes($size = 16) {
        return openssl_random_pseudo_bytes($size);
    }

    /**
     * Returns the cipher method of openssl.
     */
    private function cipher() {
        return sprintf($this->modes[$this->mode], $this->keyLen * 8);
    }

    /**
     * Creates MAC signature of data; using HMAC-SHA256.
     */
    private function sign($data, $key) {
        return hash_hmac("SHA256", $data, $key, true);
    }
    
    /**
     * Creates MAC signature of a file; using HMAC-SHA256.
     */
    private function signFile($path, $key, $start = 0, $end = 0) {
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
     * Handles exceptions (prints the error message by default)
     */
    private function errorHandler($exception) {
        $msg = (gettype($exception) == "string") ? $exception : $exception->getMessage();
        echo $msg;
    }
    
    /**
     * A generator that yields file chunks. 
     * Chunk size must be a nultiple of 16 in CBC mode.
     */
    public function readFileChunks($path, $start = 0, $end = 0) {
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
    
    /**
     * Checks if the two MACs are equal; using constant time comparison.
     */
    private function compareMacs($mac1, $mac2) {
        $result = mb_strlen($mac1, "8bit") ^ mb_strlen($mac2, "8bit");
        $minLen = min(mb_strlen($mac1, "8bit"), mb_strlen($mac2, "8bit"));

        for ($i = 0; $i < $minLen; $i++) {
            $result |= ord($mac1[$i]) ^ ord($mac2[$i]);
        }
        return $result == 0;
    }
}


/**
 * A wrapper class for openssl encrypt / decrypt functions, 
 * that can be used to encrypt multiple blocks.
 * This class is a helper of AesEncryption (when  encrypting files) 
 * and should NOT be used on its own.
 */
class Cipher {
    private $method;
    private $mode;
    private $key;
    private $iv;
    private $blockSize = 16;

    const Encrypt = 1;
    const Decrypt = 2;
    
    /**
     * @param string $method cipher method
     * @param int $mode encryption mode
     * @param string $key encryption key
     * @param string $iv
     */
    function __construct($method, $mode, $key, $iv) {
        $this->method = $method;
        $this->mode = $mode;
        $this->key = $key;
        $this->iv = $iv;
    }

    /**
     * Encrypts / decrypts data.
     * @param string $data (must be a multiple of 16 in CBC mode)
     * @return string 
     * @throws UnexpectedValueException on encryption error
     */
    public function update($data) {
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING; 
        $fun = ($this->mode == Cipher::Encrypt) ? "openssl_encrypt" : "openssl_decrypt";
        $newData = $fun($data, $this->method, $this->key, $options, $this->iv);

        if($newData === false) {
            throw new UnexpectedValueException("Encryption failed\n");
        }
        $ivSource = ($this->mode == Cipher::Encrypt) ? $newData : $data;
        $this->iv = $this->getIV($ivSource);
        return $newData;
    }
    
    /**
     * Adds padding to data (for CBC mode).
     * @param string $data
     * @return string padded data
     */
    public function pad($data) {
        $pad = $this->blockSize - (mb_strlen($data, "8bit") % $this->blockSize);
        return $data . str_repeat(chr($pad), $pad);
    }

    /**
     * Removes padding from decrypted data.
     * @param string $data
     * @return string unpadded data
     * @throws UnexpectedValueException if padding is invalid.
     */
    public function unpad($data) {
        $pad = ord(mb_substr($data, -1, 1, "8bit"));
        $padding = mb_substr($data, -1 * $pad, $pad, "8bit");
        if($pad < 1 || $pad > 16 || substr_count($padding, chr($pad)) != $pad) {
            throw new UnexpectedValueException("Padding is invalid");
        }
        return mb_substr($data, 0, -$pad, "8bit");
    }
    
    /**
     * Returns the last 16 bytes of data to use as IV.
     */
    private function getIV($data) {
        $iv = mb_substr($data, -$this->blockSize, $this->blockSize, "8bit");
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
    function __construct($key, $data = null) {
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
     * @return string the MAC
     */
    public function digest($raw = true) {
        $innerHash = hash_final($this->inner, true);
        hash_update($this->outer, $innerHash);
        return hash_final($this->outer, $raw);
    }
    
    /**
     * Translates the key (shifts bytes).
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
