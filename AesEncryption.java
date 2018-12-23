import java.util.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.*;


/**
 * Encrypts data and files using AES CBC/CFB - 128/192/256 bits.
 *
 * The encryption and authentication keys 
 * are derived from the supplied key/password using HKDF/PBKDF2.
 * The master key can be set either with `setMasterKey` or with `randomKeyGen`.
 * Encrypted data format: salt[16] + iv[16] + ciphertext[n] + mac[32].
 * Ciphertext authenticity is verified with HMAC SHA256.
 * 
 * @author Tasos M. Adamopoulos
 */
class AesEncryption {
	private HashMap<String, String> modes = new HashMap<String, String>() {
        { put("CBC", "AES/CBC/PKCS5Padding"); }; 
        { put("CFB", "AES/CFB8/NoPadding"); } 
    };
    private List<Integer> sizes = Arrays.asList(128, 192, 256);
    private int saltLen = 16;
    private int ivLen = 16;
    private int macLen = 32;
    private int macKeyLen = 32;
    
    private String mode;
    private int keyLen;
    private byte[] masterKey;

    /**The number of PBKDF2 iterations. */
    public int keyIterations = 20000;
    /**Accepts ans returns base64 encoded data. */
    public Boolean base64 = true;
    
    /**
     * Creates a new AesEncryption object.
     * 
     * @param mode The AES mode (CBC, CFB).
     * @param size The key size in bits (128, 192, 256).
     * @throws IllegalArgumentException when the mode or key size are not supported.
     */
    public AesEncryption(String mode, int... size) throws IllegalArgumentException {
        int keySize = (size.length > 0) ? size[0] : 128;
        this.mode = mode.toUpperCase();
        this.keyLen = keySize / 8;
        
        if (this.modes.get(this.mode) == null) {
            throw new IllegalArgumentException(mode + " is not supported!");
        } 
        if (!sizes.contains(keySize)) {
            throw new IllegalArgumentException("Invalid key size!");
        } 
        if (keySize > maxKeyLen()) {
            throw new IllegalArgumentException("Key size is not supported!");
        }
    }
    
    /**
     * Creates a new AesEncryption object.
     * @throws IllegalArgumentException when the key size is not supported.
     */
    public AesEncryption() throws IllegalArgumentException {
    	this("CBC", 128);
    }
    
    /**
     * Encrypts data using a master key or the supplied password.
     * 
     * The password is not required if a master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     * 
     * @param data The plaintext.
     * @param password Optional, the password.
     * @return Encrypted data (salt + iv + ciphertext + hmac).
     */
    public byte[] encrypt(byte[] data, String... password) {
        byte[] iv = randomBytes(ivLen);
        byte[] salt = randomBytes(saltLen);
        try {
            SecretKeySpec[] keys = this.keys(salt, password);
            SecretKeySpec aesKey = keys[0], macKey = keys[1];

            Cipher cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] ciphertext = cipher.doFinal(data);
            byte[] encrypted = new byte[saltLen + ivLen + ciphertext.length + macLen];

            System.arraycopy(salt, 0, encrypted, 0, saltLen);
            System.arraycopy(iv, 0, encrypted, saltLen, ivLen);
            System.arraycopy(ciphertext, 0, encrypted, saltLen + ivLen, ciphertext.length);

            byte[] iv_ct = Arrays.copyOfRange(encrypted, saltLen, encrypted.length - macLen);
            byte[] mac = sign(iv_ct, macKey);
            System.arraycopy(mac, 0, encrypted, encrypted.length - macLen, mac.length);
            
            if (this.base64) {
                return Base64.getEncoder().encode(encrypted);
            }
            return encrypted;
        } catch (IllegalArgumentException e) {
            this.errorHandler(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    	return null;
    }

    /**
     * Encrypts data using a master key or the supplied password.
     * 
     * The password is not required if a master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     * 
     * @param data The plaintext.
     * @param password Optional, the password.
     * @return Encrypted data (salt + iv + ciphertext + hmac).
     */
    public byte[] encrypt(String data, String... password) {
        return encrypt(data.getBytes(), password);
    }
    
    /**
     * Decrypts data using a master key or the supplied password.
     *  
     * The password is not required if a master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     *
     * @param data The ciphertext.
     * @param password Optional, the password.
     * @return Plaintext.
     */
    public byte[] decrypt(byte[] data, String... password) {
        try {
            if (base64) {
                data = Base64.getDecoder().decode(data);
            }
            byte[] salt = Arrays.copyOfRange(data, 0, saltLen);
            byte[] iv = Arrays.copyOfRange(data, saltLen, saltLen + ivLen);
            byte[] ciphertext = Arrays.copyOfRange(data, saltLen + ivLen, data.length - macLen);
            byte[] mac = Arrays.copyOfRange(data, data.length - macLen, data.length);
            
            SecretKeySpec[] keys = this.keys(salt, password);
            SecretKeySpec aesKey = keys[0], macKey = keys[1];
            
            byte[] iv_ct = Arrays.copyOfRange(data, saltLen, data.length - macLen);
            this.verify(iv_ct, mac, macKey);
            
            Cipher cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv);
            byte[] plaintext = cipher.doFinal(ciphertext);
            return plaintext;
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            this.errorHandler(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            this.errorHandler(e);
        }
        return null;
    }
    
    /**
     * Decrypts data using a master key or the supplied password.
     *  
     * The password is not required if a master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     *
     * @param data The ciphertext, base64 encoded.
     * @param password Optional, the password.
     * @return Plaintext.
     */
    public byte[] decrypt(String data, String... password) {
        return decrypt(data.getBytes(), password);
    }

    /**
     * Encrypts files using a master key or the supplied password.
     * 
     * The original file is not modified; a new encrypted file is created.
     * The password is not required if a master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     * 
     * @param path The file path.
     * @param password Optional, the password.
     * @return The new file path.
     */
    public String encryptFile(String path, String... password) {
        byte[] salt = randomBytes(saltLen);
        byte[] iv = randomBytes(ivLen);
        try {
            SecretKeySpec[] keys = this.keys(salt, password);
            SecretKeySpec aesKey = keys[0], macKey = keys[1];
            
            String newPath = path + ".enc";
            FileOutputStream fos = new FileOutputStream(newPath);
            fos.write(salt);
            fos.write(iv);
            
            Cipher cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv);
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(macKey);
            hmac.update(iv);
            
            for (byte[] chunk: new FileChunks(path, 0, 0)) {
                byte[] ciphertext = cipher.update(chunk);
                hmac.update(ciphertext);
                fos.write(ciphertext);
            }
            byte[] ciphertext = cipher.doFinal();
            byte[] mac = hmac.doFinal(ciphertext);
            
            fos.write(ciphertext);
            fos.write(mac);
            fos.close();
            return newPath;
        } catch (IllegalArgumentException | IOException e) {
            this.errorHandler(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
        return null;
    }
    

    /**
     * Decrypts files using a master key or the supplied password.
     * 
     * The original file is not modified; a new decrypted file is created.
     * The password is not required if a master key has been set - 
     * either with `randomKeyGen` or with `setMasterKey`. 
     * If a password is supplied, it will be used to create a key with PBKDF2.
     * 
     * @param path The file path.
     * @param password Optional, the password.
     * @return The new file path.
     */
    public String decryptFile(String path, String... password) {
        byte[] salt = new byte[saltLen];
        byte[] iv = new byte[ivLen];
        byte[] mac = new byte[macLen];
        try {
            FileInputStream fis = new FileInputStream(path);
            fis.read(salt);
            fis.read(iv);
            fis.skip(new File(path).length() - saltLen - ivLen - macLen);
            fis.read(mac);
            fis.close();
            
            SecretKeySpec[] keys = this.keys(salt, password);
            SecretKeySpec aesKey = keys[0], macKey = keys[1];
            this.verifyFile(path, mac, macKey);
            Cipher cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv);

            String newPath = path.replaceAll("\\.enc$", ".dec");
            FileOutputStream fos = new FileOutputStream(newPath);
            FileChunks chunks = new FileChunks(path, saltLen + ivLen, macLen);
            
            for (byte[] chunk: chunks) {
                fos.write(cipher.update(chunk));
            }
            fos.write(cipher.doFinal());
            fos.close();            
            return newPath;
        } catch (IllegalArgumentException | IOException e)  {
            this.errorHandler(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            this.errorHandler(e);
        }
        return null;
    }

    /**
     * Sets a new master key, 
     * from which the encryption and authentication keys will be derived.
     * 
     * @param key The new master key.
     * @param raw Expects raw bytes (not base64-encoded).
     */
    public void setMasterKey(byte[] key, boolean... raw) {
        boolean _raw = (raw.length > 0) ? raw[0] : false;
    	try {
            masterKey = (_raw) ? key : Base64.getDecoder().decode(key);
    	} catch (IllegalArgumentException e) {
            this.errorHandler(e);
    	}
    }

    /**
     * Sets a new master key, 
     * from which the encryption and authentication keys will be derived.
     * 
     * @param key The new master key, base64-encoded.
     */
    public void setMasterKey(String key) {
        this.setMasterKey(key.getBytes(), false);
    }

    /**
     * Returns the master key (or null if the key is not set).
     * 
     * @param raw Returns raw bytes (not base64-encoded).
     * @return The master key.
     */
    public byte[] getMasterKey(boolean... raw) {
        boolean _raw = (raw != null && raw.length > 0) ? raw[0] : false;
        if (this.masterKey == null) {
            this.errorHandler(new Exception("The key is not set!"));
        } else if (!_raw) {
            return Base64.getEncoder().encode(this.masterKey);
        }
        return this.masterKey;
    }

    /**
     * Generates a new random key.
     * This key will be used to create the encryption and authentication keys.
     * 
     * @param keyLen The key size, in bytes.
     * @param raw Returns raw bytes (not base64-encoded).
     * @return The new master key.
     */
    public byte[] randomKeyGen(int keyLen, boolean... raw) {
        boolean _raw = (raw.length > 0) ? raw[0] : false;
        masterKey = this.randomBytes(keyLen);
        return (_raw) ? masterKey : Base64.getEncoder().encode(masterKey);
    }

    /**
     * Generates a new random key.
     * This key will be used to create the encryption and authentication keys.
     * 
     * @param raw Returns raw bytes (not base64-encoded).
     * @return The new master key.
     */
    public byte[] randomKeyGen(boolean... raw) {
        return this.randomKeyGen(32, raw);
    }

    /**
     * Handles exceptions (prints the exception by default).
     */
    protected void errorHandler(Exception exception) {
        System.out.println(exception);
    }
    
    /**
     * Derives encryption and authentication keys from a key or password.
     * If the password is not null, it will be used to create the keys.
     * @throws IllegalArgumentException If neither the key or password is set.
     */
    private SecretKeySpec[] keys(byte[] salt, String... password) throws IllegalArgumentException {
    	byte[] dkey;
        if (password != null && password.length > 0) {
            dkey = this.pbkdf2Sha512(password[0], salt, keyLen + macKeyLen);
        } else if (this.masterKey != null) {
            dkey = this.hkdfSha256(this.masterKey, salt, keyLen + macKeyLen);
        } else {
            throw new IllegalArgumentException("No password or key specified!"); 
        }
        return new SecretKeySpec[] {
            new SecretKeySpec(dkey, 0, keyLen, "AES"), 
            new SecretKeySpec(dkey, keyLen, macKeyLen, "HmacSHA256")
        };
    }

    /**
     * Creates random bytes; used for IV, salt and key generation.
     */
    private byte[] randomBytes(int size) {
        byte[] rb = new byte[size];
        try {
            SecureRandom srng = SecureRandom.getInstance("SHA1PRNG");
            srng.nextBytes(rb);
            return rb;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Creates a new Cipher object; used for encryption / decryption.
     */ 
    private Cipher cipher(int cipherMode, SecretKey key, byte[] iv) {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance(modes.get(mode));
            cipher.init(cipherMode, key, ivSpec);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new AssertionError(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Computes the MAC of ciphertext; used for authentication.
     */
    private byte[] sign(byte[] data, SecretKeySpec key) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(key);
            return  hmac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Computes the MAC of ciphertext; used for authentication.
     * @throws IOException When file is not accessible.
     */
    private byte[] signFile(String path, SecretKeySpec key, int start, int end) throws IOException {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(key);
                
            FileChunks fc = new FileChunks(path, start, end);
            for (byte[] chunk: fc) {
                hmac.update(chunk);
            }
            return hmac.doFinal(new byte[0]);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Verifies the authenticity of ciphertext.
     * @throws IllegalArgumentException When the MAC is invalid.
     */
    private void verify(byte[] data, byte[] mac, SecretKeySpec key) throws IllegalArgumentException {
        byte[] dataMac = sign(data, key); 
        if (!MessageDigest.isEqual(dataMac, mac)) {
            throw new IllegalArgumentException("MAC check failed!");
        }
    }
    
    /**
     * Verifies the authenticity of ciphertext.
     * @throws IllegalArgumentException when the MAC is invalid.
     * @throws IOException When the file is not accessible.
     */
    private void verifyFile(String path, byte[] mac, SecretKeySpec key) throws IllegalArgumentException, IOException {
        byte[] fileMac = signFile(path, key, saltLen, macLen);
        if (!MessageDigest.isEqual(fileMac, mac)) {
            throw new IllegalArgumentException("MAC check failed!");
        }
    }

    /**
     * Reads a file and yields chunks of data. 
     */
    private class FileChunks implements Iterable<byte[]> {    
        private FileInputStream fis;
        private int fileSize;
        private int pos;
        private int end;
        public final int size = 1024;
        
        /**
         * @param path The file path.
         * @param start The starting position in file.
         * @param end The ending position in file (filesize - end).
         * @throws IOException When the file is not accessible.
         */
        public FileChunks(String path, int start, int end) throws IOException {
            this.fis = new FileInputStream(path);
            this.fileSize = (int)new File(path).length();
            this.pos = fis.read(new byte[start]);
            this.end = fileSize - end;
        }
        
        @Override
        public Iterator<byte[]> iterator() {
            return new Iterator<byte[]> () {
                
                @Override
                public boolean hasNext() {
                    return (pos < end);
                }
                
                @Override
                public byte[] next() {
                    int bufferLen = (end - pos > size) ? size : end - pos;
                    byte[] data = new byte[bufferLen];
                    try {
                        pos += fis.read(data);
                        if(pos == fileSize) {
                            fis.close();
                        }
                    } catch (IOException e) {
                    	AesEncryption.this.errorHandler(e);
                    }
                    return data;                
                }
            };
        }
    }
    
    /**
     * Derives a key from the password and salt using PBKDF2.
     */
    private byte[] pbkdf2Sha512(String password, byte[] salt, int dkeyLen) {        
        try {
            PBEKeySpec kspec = new PBEKeySpec(
            	password.toCharArray(), salt, keyIterations, dkeyLen * 8
            );
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] dkey = skf.generateSecret(kspec).getEncoded();
            kspec.clearPassword();
            return dkey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * A HKDF algorithm implementation, with HMAC-SHA256.
     * Expands the master key to derive AES and HMAC keys.
     */
    private byte[] hkdfSha256(byte[] key, byte[] salt, int dkeyLen) {
        byte[] dkey = new byte[dkeyLen];
        byte[] hkey = new byte[0];
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = hmac.doFinal(key);
            int hashLen = hmac.getMacLength();

            for (int i = 0; i < dkeyLen; i +=  hashLen) {
                hkey = Arrays.copyOf(hkey, hkey.length + 1);
                hkey[hkey.length - 1] = (byte)(i / hashLen + 1);
                hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
                hkey = hmac.doFinal(hkey);

                if (i + hashLen > dkeyLen) 
                    hashLen = hashLen - (i + hashLen - dkeyLen);
                System.arraycopy(hkey, 0, dkey, i, hashLen);
            }
            return dkey;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Returns the maximum allowed key length.
     */
    private int maxKeyLen() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } 
    }
}

