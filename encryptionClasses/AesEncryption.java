import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
* Encrypts - decrypts data and files using AES CBC/CFB, 128/192/256 bits.
* @author Tasos M. Adamopoulos
*/
class AesEncryption {
	private HashMap<String, String> modes = new HashMap<String, String>() {
		{ put("CBC", "AES/CBC/PKCS5Padding"); }; 
		{ put("CFB", "AES/CFB8/NoPadding"); } 
	};
	private int[] sizes = new int[] { 128, 192, 256 };
	private int size = 128;
	private int saltLen = 16;
	private int ivLen = 16;
	private int macLen = 32;
	private String mode = "CBC";
	private int keyLen = 16;
	public int keyIterations = 20000;
	public Boolean base64 = true;
	
	/**
	 * @param mode AES mode
	 * @param size key size in bits
	 * @throws IllegalArgumentException if mode is not supported or key size is invalid.
	 */
	public AesEncryption(String mode, int size) throws IllegalArgumentException {
		mode = mode.toUpperCase();
		if(modes.get(mode) == null) {
			throw new IllegalArgumentException("Unsupported mode: " + mode);
		} 
		if(size != sizes[0] && size != sizes[1] && size != sizes[2]) {
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
	
	public AesEncryption() {
	}
	
	/**
	 * Encrypts bytes with the supplied password, returns raw or base64 encoded bytes. 
	 * @param data the data to encrypt
	 * @param password
	 * @return encrypted data (salt + iv + ciphertext + hmac)
	 */
	public byte[] encrypt(byte[] data, String password) {
		byte[] iv = randomBytes(ivLen);
		byte[] salt = randomBytes(saltLen);
		
		byte[][] keys = this.keys(password, salt);
		byte[] aesKey = keys[0];
		byte[] macKey = keys[1];
		try {
			Cipher cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv);
			byte[] encrypted;
			encrypted = cipher.doFinal(data);

			byte[] newData = new byte[saltLen + ivLen + encrypted.length + macLen];
			System.arraycopy(salt, 0, newData, 0, saltLen);
			System.arraycopy(iv, 0, newData, saltLen, ivLen);
			System.arraycopy(encrypted, 0, newData, saltLen + ivLen, encrypted.length);

			byte[] iv_ct = Arrays.copyOfRange(newData, saltLen, newData.length - macLen);
			byte[] mac = sign(iv_ct, macKey);
			System.arraycopy(mac, 0, newData, saltLen + ivLen + encrypted.length, mac.length);
			
			if(base64) {
				return Base64.getEncoder().encodeToString(newData).getBytes();
			}
			return newData;
		} catch(IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/** 
	 * Encrypts strings with the supplied password. 
	 */
	public byte[] encrypt(String data, String password) {
		return encrypt(data.getBytes(), password);
	}
	
	/**
	 * Decrypts data (bytes) with the supplied password.
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
			byte[] aesKey = keys[0];
			byte[] macKey = keys[1];
	        
			byte[] iv_ct = Arrays.copyOfRange(data, ivLen, data.length - macLen);
			if(!verify(iv_ct, mac, macKey)) {
				throw new IllegalArgumentException("MAC verification failed.");
			}
			
			Cipher cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv);
			byte[] cleartext = cipher.doFinal(encrypted);
			return cleartext;
		} catch (IllegalArgumentException | ArrayIndexOutOfBoundsException 
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/** 
	 * Decrypts strings (base64 encoded bytes) with the supplied password. 
	 */
	public byte[] decrypt(String data, String password) {
		return decrypt(data.getBytes(), password);
	}
	
	/**
	 * Encrypts files with the selected password. 
	 * The original file is not modified, but an encrypted copy is created.
	 * @param path the file path
	 * @param password the password
	 * @return path to encrypted file
	 */
	public String encryptFile(String path, String password) {
		String newPath = path + ".enc";
		byte[] salt = randomBytes(saltLen);
		byte[] iv = randomBytes(ivLen);
		
		byte[][] keys = this.keys(password, salt);
		byte[] aesKey = keys[0];
		byte[] macKey = keys[1];

		try {
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
		} catch(IOException | NoSuchAlgorithmException | InvalidKeyException 
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Decrypts files with the selected password. 
	 * The encrypted file is not modified, but a decrypted copy is created.
	 * @param path file path
	 * @param password the password
	 * @return path to decrypted file
	 */
	public String decryptFile(String path, String password) {
		String newPath = path.replace(".enc", "") + ".dec";	
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
			byte[] aesKey = keys[0];
			byte[] macKey = keys[1];
	        
			if(!verifyFile(path, mac, macKey)) {
				throw new IllegalArgumentException("MAC verification failed.");
			}
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
		} catch(IOException | IllegalArgumentException
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Creates a pair of keys from the given password and salt.
	 * One key is used for encryption, the other for authentication.
	 * @param password
	 * @param salt
	 * @return keys
	 */
	public byte[][] keys(String password, byte[] salt) {
		String hash = "PBKDF2WithHmacSHA1";
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, keyIterations, keyLen * 8 * 2);
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance(hash);
			byte[] keys = skf.generateSecret(spec).getEncoded();
			byte[] aes_key = Arrays.copyOfRange(keys, 0, keyLen);
			byte[] mac_key = Arrays.copyOfRange(keys, keyLen, keyLen * 2);
			return new byte[][] {aes_key, mac_key};
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			return null;
		}
	}

	/**
	 * Creates random bytes, used for IV and salt.
	 * @param size the length of random bytes
	 * @return random bytes
	 */
	private byte[] randomBytes(Integer... size) {
		String rng = "SHA1PRNG";
		byte[] rb = new byte[(size.length > 0) ? size[0] : ivLen];
		try {
			SecureRandom sr = SecureRandom.getInstance(rng);
			sr.nextBytes(rb);
			return rb;
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}
	
	/**
	 * Initiates a Cipher object with the key and iv. 
	 * @param cipherMode encrypt/decrypt mode
	 * @param key
	 * @param iv
	 * @return Cipher object
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
			return null;
		}
	}
	
	/**
	 * Creates MAC, for ciphertext authentication.
	 * @param data
	 * @param key
	 * @return MAC
	 */
	private byte[] sign(byte[] data, byte[] key) {
		String hash = "HmacSHA256";
		try {
			Mac hmac = Mac.getInstance(hash);
			hmac.init(new SecretKeySpec(key, hash));
			return  hmac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			return null;
		}
	}
	
	/**
	 * Computes the MAC of file, for data authentication.
	 * @param path file path
	 * @param key the MAC key
	 * @param start the starting position
	 * @param end the ending position (filesize - end)
	 * @return MAC
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
			return null;
		}
	}
	
	/**
	 * Verifies that the received MAC is valid.
	 * @param data
	 * @param mac
	 * @param key
	 */
	private Boolean verify(byte[] data, byte[] mac, byte[] key) {
		byte[] dataMac = sign(data, key); 
		return compareMacs(dataMac, mac);
	}
	
	/**
	 * Verifies that the MAC hash of a file is valid.
	 * @param path file path
	 * @param mac 
	 * @param key
	 */
	private Boolean verifyFile(String path, byte[] mac, byte[] key) throws IOException {
		byte[] fileMac = signFile(path, key, saltLen, macLen);
		return compareMacs(fileMac, mac);
	}
	
	/**
	 * Checks if MACs are equal - using constant time comparisson algorithm.
	 * @param mac1 
	 * @param mac2
	 * @return true if MACs match, else false.
	 */
	private Boolean compareMacs(byte[] mac1, byte[] mac2) {
		if(mac1.length == mac2.length) {
			int result = 0;
			for(int i = 0; i < mac1.length; i++) {
				result |= mac1[i] ^ mac2[i];
			}
			return result == 0;
		}
		return false;
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
						e.printStackTrace();
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
		} catch (Exception e) {
			return 0;
		} 
	}
}

