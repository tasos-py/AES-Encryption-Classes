import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.*;


/**
 * Encrypts data and files using AES CBC/CFB, 128/192/256 bits.
 * @author Tasos M. Adamopoulos
 */
class AesEncryption {
    private HashMap<String, String> modes = new HashMap<String, String>() {
        { put("CBC", "AES/CBC/PKCS5Padding"); }; 
        { put("CFB", "AES/CFB8/NoPadding"); } 
    };
    private List<Integer> sizes = Arrays.asList(128, 192, 256);
    private int size = 128;
    private int saltLen = 16;
    private int ivLen = 16;
    private int macLen = 32;
    private String mode = "CBC";
    private int keyLen = 16;
    public int keyIterations = 20000;
    public Boolean base64 = true;
    
    /**
     * @param mode AES mode (CBC, CFB)
     * @param size key size in bits (128, 192, 256)
     * @throws IllegalArgumentException if mode is not supported or key size is invalid.
     */
    public AesEncryption(String mode, int size) throws IllegalArgumentException {
        mode = mode.toUpperCase();
        if(modes.get(mode) == null) {
            throw new IllegalArgumentException("Unsupported mode: " + mode);
        } 
        if(!sizes.contains(size)) {
            throw new IllegalArgumentException("Invalid key size");
        } 
        if(size > maxKeyLen()) {
            throw new IllegalArgumentException("Key size is not supported");
        }
        this.mode = mode;
        this.keyLen = size / 8;
        this.size = size;
    }
    
    /**
     * @param mode AES mode
     * @throws IllegalArgumentException when mode is not supported.
     */
    public AesEncryption(String mode) throws IllegalArgumentException {    
        this(mode, 128);
    }
    
    /**
     * @param size key size
     * @throws IllegalArgumentException when key size is invalid.
     */
    public AesEncryption(int size) throws IllegalArgumentException {        
        this("CBC", size);
    }
        
    public AesEncryption() {}
        
    /**
     * Encrypts bytes with the supplied password, returns raw or base64 encoded bytes. 
     * @param data the data to encrypt
     * @param password
     * @return encrypted data (salt + iv + ciphertext + hmac)
     */
    public byte[] encrypt(byte[] data, String password) {
        try {
            byte[] iv = randomBytes(ivLen);
            byte[] salt = randomBytes(saltLen);
            
            byte[][] keys = this.keys(password, salt);
            byte[] aesKey = keys[0], macKey = keys[1];
            
            Cipher cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] ciphertext = cipher.doFinal(data);
            
            byte[] encrypted = new byte[saltLen + ivLen + ciphertext.length + macLen];
            System.arraycopy(salt, 0, encrypted, 0, saltLen);
            System.arraycopy(iv, 0, encrypted, saltLen, ivLen);
            System.arraycopy(ciphertext, 0, encrypted, saltLen + ivLen, ciphertext.length);
            
            byte[] iv_ct = Arrays.copyOfRange(encrypted, 16, encrypted.length - macLen);
            byte[] mac = sign(iv_ct, macKey);
            System.arraycopy(mac, 0, encrypted, saltLen + ivLen + ciphertext.length, mac.length);
            
            if(base64) {
                return Base64.getEncoder().encodeToString(encrypted).getBytes();
            }
            return encrypted;
        } catch(IllegalBlockSizeException | BadPaddingException e) {
            this.errorHandler(e);
            return new byte[0];
        }
    }
    
    /** 
     * Encrypts strings with the supplied password. 
     */
    public byte[] encrypt(String data, String password) {
        return encrypt(data.getBytes(), password);
    }
    
    /**
     * Decrypts data (raw bytes) with the supplied password.
     * @param data encrypted data
     * @param password
     * @return decrypted data
     */
    public byte[] decrypt(byte[] data, String password) {
        try {
            if(base64) {
                data = Base64.getDecoder().decode(new String(data));
            }
            byte[] salt = Arrays.copyOfRange(data, 0, saltLen);
            byte[] iv = Arrays.copyOfRange(data, saltLen, saltLen + ivLen);
            byte[] encrypted = Arrays.copyOfRange(data, saltLen + ivLen, data.length - macLen);
            byte[] mac = Arrays.copyOfRange(data, saltLen + ivLen + encrypted.length, data.length);
            
            byte[][] keys = this.keys(password, salt);
            byte[] aesKey = keys[0], macKey = keys[1];
            
            byte[] iv_ct = Arrays.copyOfRange(data, ivLen, data.length - macLen);
            verify(iv_ct, mac, macKey);
            
            Cipher cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv);
            byte[] cleartext = cipher.doFinal(encrypted);
            return cleartext;
        } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException | 
                BadPaddingException | IllegalBlockSizeException e) {
            this.errorHandler(e);
            return new byte[0];
        }
    }
    
    /** 
     * Decrypts strings (base64 encoded bytes) with the supplied password. 
     */
    public byte[] decrypt(String data, String password) {
        return decrypt(data.getBytes(), password);
    }
    
    /**
     * Encrypts files with the supplied password. 
     * The original file is not modified, but an encrypted copy is created.
     * @param path the file path
     * @param password
     * @return path to encrypted file
     */
    public String encryptFile(String path, String password) {
        String newPath = path + ".enc";
        try {
            byte[] salt = randomBytes(saltLen);
            byte[] iv = randomBytes(ivLen);
            
            byte[][] keys = this.keys(password, salt);
            byte[] aesKey = keys[0], macKey = keys[1];
            
            FileOutputStream fos = new FileOutputStream(newPath);
            fos.write(salt);
            fos.write(iv);
            
            Cipher cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv);
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            hmac.update(iv);
            
            FileChunks fc = new FileChunks(path, 0, 0);
            for(byte[] chunk: fc) {
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
        } catch(IOException | NoSuchAlgorithmException | InvalidKeyException | 
                BadPaddingException | IllegalBlockSizeException e) {
            this.errorHandler(e);
            return "";
        }
    }
    
    /**
     * Decrypts files with the supplied password. 
     * The encrypted file is not modified, but a decrypted copy is created.
     * @param path file path
     * @param password
     * @return path to decrypted file
     */
    public String decryptFile(String path, String password) {
        String newPath = path.replace(".enc", ".dec");    
        
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
            
            byte[][] keys = this.keys(password, salt);
            byte[] aesKey = keys[0], macKey = keys[1];
            
            verifyFile(path, mac, macKey);
            Cipher cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv);
            FileOutputStream fos = new FileOutputStream(newPath);
            
            FileChunks fc = new FileChunks(path, saltLen + ivLen, macLen);
            for(byte[] chunk: fc) {
                byte[] cleartext = cipher.update(chunk); 
                fos.write(cleartext);
            }
            fos.write(cipher.doFinal());
            fos.close();            
            return newPath;
        } catch (IOException | IllegalArgumentException | 
                BadPaddingException | IllegalBlockSizeException e) {
            this.errorHandler(e);
            return "";
        } 
    }
    
    /**
     * Creates a pair of keys from the given password and salt.
     * One key is used for encryption, the other for authentication.
     * @param password
     * @param salt
     * @return keys, the derived key split in two parts
     */
    private byte[][] keys(String password, byte[] salt) {
        String hash = "PBKDF2WithHmacSHA256";
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(), salt, keyIterations, keyLen * 8 * 2
        );
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(hash);
            byte[] keys = skf.generateSecret(spec).getEncoded();
            byte[] aes_key = Arrays.copyOfRange(keys, 0, keyLen);
            byte[] mac_key = Arrays.copyOfRange(keys, keyLen, keyLen * 2);
            return new byte[][] {aes_key, mac_key};
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Creates random bytes, used for IV and salt.
     * @param size the length of random bytes
     * @return random bytes
     * @throws AssertionError 
     */
    private byte[] randomBytes(Integer... size) {
        String rng = "SHA1PRNG";
        byte[] rb = new byte[(size.length > 0) ? size[0] : ivLen];
        try {
            SecureRandom sr = SecureRandom.getInstance(rng);
            sr.nextBytes(rb);
            return rb;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Initiates a Cipher object with the key and iv. 
     * @param cipherMode encrypt / decrypt mode
     * @param key AES key
     * @param iv
     * @return Cipher object
     * @throws AssertionError 
     */ 
    private Cipher cipher(int cipherMode, byte[] key, byte[] iv) {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance(modes.get(mode));
            cipher.init(cipherMode, keySpec, ivSpec);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | 
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Creates a MAC for ciphertext authentication.
     * @param data
     * @param key the HMAC key
     * @return MAC
     * @throws AssertionError
     */
    private byte[] sign(byte[] data, byte[] key) {
        String hash = "HmacSHA256";
        try {
            Mac hmac = Mac.getInstance(hash);
            hmac.init(new SecretKeySpec(key, hash));
            return  hmac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Computes the MAC of file, for data authentication.
     * @param path the file path
     * @param key the HMAC key
     * @param start the starting position
     * @param end the ending position (filesize - end)
     * @return MAC
     * @throws IOException, AssertionError 
     */
    private byte[] signFile(String path, byte[] key, int start, int end) throws IOException {
        String hash = "HmacSHA256";
        try {
            Mac hmac = Mac.getInstance(hash);
            hmac.init(new SecretKeySpec(key, hash));
                
            FileChunks fc = new FileChunks(path, start, end);
            for(byte[] chunk: fc) {
                hmac.update(chunk);
            }
            return hmac.doFinal(new byte[0]);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Verifies that the received MAC is valid.
     * @param data the received data
     * @param mac the received MAC
     * @param key HMAC key
     * @throws IllegalArgumentException when MAC is invalid
     */
    private void verify(byte[] data, byte[] mac, byte[] key) throws IllegalArgumentException {
        byte[] dataMac = sign(data, key); 
        if(!MessageDigest.isEqual(dataMac, mac)) {
            throw new IllegalArgumentException("MAC verification failed.");
        }
    }
    
    /**
     * Verifies that the MAC of a file is valid.
     * @param path the file path
     * @param mac the received MAC
     * @param key HMAC key
     * @throws IllegalArgumentException when MAC is invalid
     * @throws IOException when file is inaccessible
     */
    private void verifyFile(String path, byte[] mac, byte[] key) throws IllegalArgumentException, IOException {
        byte[] fileMac;
        fileMac = signFile(path, key, saltLen, macLen);
        if(!MessageDigest.isEqual(fileMac, mac)) {
            throw new IllegalArgumentException("MAC verification failed.");
        }
    }
    
    /**
     * Handles exceptions - prints a message by default.
     * @param exception
     */
    private void errorHandler(Exception exception) {
        System.out.println(exception);
    }
    
    /**
     * A poor man's generator that "yields" file chunks.
     */
    private class FileChunks implements Iterable<byte[]> {    
        private FileInputStream fis;
        private int fileSize;
        private int counter;
        private int end;
        public final int size = 1024;
        
        /**
         * @param path file path
         * @param start starting position in file
         * @param end ending position in file (filesize - end)
         * @throws IOException 
         */
        public FileChunks(String path, int start, int end) throws IOException {
            File file = new File(path);
            fis = new FileInputStream(file);
            fileSize = (int)file.length();
            counter = fis.read(new byte[start]);
            this.end = fileSize - end;
        }
        
        @Override
        public Iterator<byte[]> iterator() {
            return new Iterator<byte[]> () {
                
                @Override
                public boolean hasNext() {
                    return (counter < end);
                }
                
                @Override
                public byte[] next() {
                    int buffer = (end - counter > size) ? size : end - counter;
                    byte[] data = new byte[buffer];
                    try {
                        counter += fis.read(data);
                        if(counter == fileSize) {
                            fis.close();
                        }
                    } catch (IOException e) {
                        AesEncryption.this.errorHandler(e);
                        throw new AssertionError(e);
                    }
                    return data;                
                }
            };
        }
    }
    
    /**
     * Returns the maximum allowed key length.
     */
    private int maxKeyLen() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES");
        } catch (NoSuchAlgorithmException e) {
            this.errorHandler(e);
            return 0;
        } 
    }
}

