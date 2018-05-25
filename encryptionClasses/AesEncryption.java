import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import javax.crypto.Mac;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;

/**
 * @author Tasos M. Adamopoulos
 * Encrypts and decrypts data using AES CBC/CFB, 128/192/256 bits.
 */
class AesEncryption {
	private HashMap<String, String> modes = new HashMap<String, String>() {
		{ put("CBC", "AES/CBC/PKCS5Padding"); }; 
		{ put("CFB", "AES/CFB8/NoPadding"); } 
	};
	private int[] sizes = new int[] { 128, 192, 256 };
	private int saltLen = 16;
	private int ivLen = 16;
	private int macLen = 32;
	private int blockSize = 128;
	private int keySize = 128;
	private String mode = "CBC";
	public byte[] key = null;
	public int rounds = 100000;
	public Boolean base64 = true;

	public AesEncryption() {
	}
	
	/**
	 * @param mode, the AES mode
	 * @throws IllegalArgumentException when mode is not supported.
	 */
	public AesEncryption(String mode) throws IllegalArgumentException {	
		this(mode, 128);
	}
	
	/**
	 * @param size, the key size
	 * @throws IllegalArgumentException when key size is invalid.
	 */
	public AesEncryption(int size) throws IllegalArgumentException {		
		this("CBC", size);
	}
	
	/**
	 * @param mode, the AES mode
	 * @param size, the key size
	 * @throws IllegalArgumentException when mode is not supported or key size is invalid.
	 */
	public AesEncryption(String mode, int size) throws IllegalArgumentException {
		mode = mode.toUpperCase();
		if(modes.get(mode) == null) {
			throw new IllegalArgumentException("Unsupported mode selected: " + mode);
		} 
		if(size != sizes[0] && size != sizes[1] && size != sizes[2]) {
			throw new IllegalArgumentException("Key size must be 128, 192 or 256 bits.");
		} 
		if(size > maxKeyLen()) {
			throw new Exception(size + " key size not supported.");
		}
		this.mode = mode;
		this.keySize = size;
	}
	
	/**
	 * Encrypts bytes using the selected mode, returns raw or base64 encoded bytes. 
	 * @param data
	 * @param password
	 * @return salt + iv + ciphertext + hmac
	 */
	public byte[] encrypt(byte[] data, String password) {
		byte[] iv = randomBytes(ivLen);
		byte[] salt = randomBytes(saltLen);
		byte[][] keys = this.keys(password, salt);
		key = keys[0];
		try{
			Cipher cipher = Cipher.getInstance(modes.get(mode));
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			
			byte[] encrypted = cipher.doFinal(data);
			byte[] newData = new byte[saltLen + ivLen + encrypted.length + macLen];
			System.arraycopy(salt, 0, newData, 0, saltLen);
			System.arraycopy(iv, 0, newData, saltLen, ivLen);
			System.arraycopy(encrypted, 0, newData, saltLen + ivLen, encrypted.length);

			byte[] iv_encrypted = Arrays.copyOfRange(newData, 16, newData.length - macLen);
			byte[] mac = sign(iv_encrypted, keys[1]);
			System.arraycopy(mac, 0, newData, saltLen + ivLen + encrypted.length, mac.length);
			
			if(base64) 
				return Base64.getEncoder().encodeToString(newData).getBytes();
			return newData;
		} catch(Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	/**
	 * Encrypts strings using the selected mode. 
	 */
	public byte[] encrypt(String data, String password) {
		return encrypt(data.getBytes(), password);
	}
	
	/**
	 * Decrypts bytes using the selected mode.
	 * @param data
	 * @param password
	 * @return decrypted data.
	 */
	public byte[] decrypt(byte[] data, String password) {
		try {
			if(base64)
				data = Base64.getDecoder().decode(new String(data, "ASCII"));
			int minLen = (mode == "CBC" ? 1 : 0) * (blockSize / 8);
			if(data.length < ivLen + saltLen + minLen + macLen)
				throw new Exception("Not enough data.");
			
			byte[] salt = Arrays.copyOfRange(data, 0, saltLen);
			byte[] iv = Arrays.copyOfRange(data, saltLen, saltLen + ivLen);
			byte[] encrypted = Arrays.copyOfRange(data, saltLen + ivLen, data.length - macLen);
			byte[] mac = Arrays.copyOfRange(data, saltLen + ivLen + encrypted.length, data.length);
			byte[][] keys = this.keys(password, salt);
			key = keys[0];
			byte[] iv_encrypted = Arrays.copyOfRange(data, ivLen, data.length - macLen);
			if(!verify(iv_encrypted, mac, keys[1]))
				throw new Exception("HMAC verification failed.");
			
			Cipher cipher = Cipher.getInstance(modes.get(mode));
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			return cipher.doFinal(encrypted);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	/**
	 * Decrypts strings (base64 encoded bytes) using the selected mode.
	 */
	public byte[] decrypt(String data, String password) {
		return decrypt(data.getBytes(), password);
	}
	
	/**
	 * Creates random bytes, used for IV and salt.
	 * @param size
	 * @return random bytes
	 */
	public byte[] randomBytes(Integer... size) {
		byte[] rb = new byte[(size.length > 0) ? size[0] : ivLen];
		SecureRandom sr;
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
			sr.nextBytes(rb);
			return rb;
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Creates a pair of keys from the given password and salt.
	 * @param password
	 * @param salt
	 * @return keys
	 */
	private byte[][] keys(String password, byte[] salt) {
		String mode = "PBKDF2WithHmacSHA1";
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, rounds, keySize * 2);
		int ks = keySize / 8;
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance(mode);
			byte[] keys = skf.generateSecret(spec).getEncoded();
			byte[] aes_key = Arrays.copyOfRange(keys, 0, ks);
			byte[] mac_key = Arrays.copyOfRange(keys, ks, ks * 2);
			return new byte[][] {aes_key, mac_key};
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Creates MAC signature.
	 * @param data
	 * @param key
	 * @return
	 */
	private byte[] sign(byte[] data, byte[] key) {
		String mode = "HmacSHA256";
		try {
			Mac hmac = Mac.getInstance(mode);
			hmac.init(new SecretKeySpec(key, mode));
			return  hmac.doFinal(data);
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Verifies that the MAC is valid.
	 * @param data
	 * @param mac
	 * @param key
	 * @return
	 */
	private Boolean verify(byte[] data, byte[] mac, byte[] key) {
		byte[] data_mac = sign(data, key); 
		return Arrays.equals(data_mac, mac);
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

