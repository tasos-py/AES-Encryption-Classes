import java.util.Arrays;
import java.util.Base64;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author T.M.Adamopoulos
 * Encrypts and decrypts data using AES-CBC 128 / 256.
 */
class AesCbc {
	private int[] sizes = new int[]{ 128, 256 };
	private int ivSize = 16;
	private int macSize = 32;
	private int blockSize = 16;
	private int keySize = 128;
	public byte[] key = null;
	public int rounds = 100000;
	public Boolean b64 = true;
	
	/**
	 * @param size, the key size
	 * @throws IllegalArgumentException
	 */
	public AesCbc(int... size) throws IllegalArgumentException {		
		keySize = (size.length > 0) ? size[0] : keySize;
		if(keySize != 128 && keySize != 256) {
			throw new IllegalArgumentException("Key size must be 128 or 256 bits.");
		} 
		if(keySize > maxKeyLen()) {
			throw new IllegalArgumentException(keySize + " key size not supported.");
		}
	}
	
	/**
	 * Encrypts strings and returns raw or base64 encoded bytes. 
	 * @param data
	 * @param password
	 * @return salt + iv + ciphertext + hmac
	 */
	public byte[] Encrypt(String data, String password) {
		return Encrypt(data.getBytes(), password);
	}
	
	/**
	 * Encrypts bytes and returns raw or base64 encoded bytes. 
	 */
	public byte[] Encrypt(byte[] data, String password) {
		byte[] iv = IVGen(ivSize);
		byte[] salt = IVGen(ivSize);
		byte[][] keys = KeyGen(password, salt);
		key = keys[0];
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			
			byte[] encrypted = cipher.doFinal(data);
			byte[] newData = new byte[ivSize + ivSize + encrypted.length + macSize];
			System.arraycopy(salt, 0, newData, 0, ivSize);
			System.arraycopy(iv, 0, newData, ivSize, ivSize);
			System.arraycopy(encrypted, 0, newData, ivSize + ivSize, encrypted.length);

			byte[] iv_encrypted = Arrays.copyOfRange(newData, 16, newData.length - macSize);
			byte[] mac = this.Sign(iv_encrypted, keys[1]);
			System.arraycopy(mac, 0, newData, ivSize + ivSize + encrypted.length, mac.length);
			
			if(this.b64) 
				newData = Base64.getEncoder().encodeToString(newData).getBytes();
			return newData;
		} catch(Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	/**
	 * Decrypts encrypted data (string)
	 * @param data
	 * @param password
	 * @return decrypted data.
	 */
	public byte[] Decrypt(String data, String password) {
		return Decrypt(data.getBytes(), password);
	}
	
	/**
	 * Decrypts encrypted data (bytes).
	 */
	public byte[] Decrypt(byte[] data, String password) {
		try {
			if(this.b64)
				data = Base64.getDecoder().decode(new String(data, "ASCII"));
			if(data.length < ivSize + ivSize + blockSize)
				throw new Exception("Not enough data.");
			
			byte[] salt = Arrays.copyOfRange(data, 0, ivSize);
			byte[] iv = Arrays.copyOfRange(data, ivSize, ivSize * 2);
			byte[] encrypted = Arrays.copyOfRange(data, ivSize * 2, data.length - macSize);
			byte[] mac = Arrays.copyOfRange(data, ivSize * 2 + encrypted.length, data.length);
			byte[][] keys = this.KeyGen(password, salt);
			key = keys[0];
			byte[] iv_encrypted = Arrays.copyOfRange(data, ivSize, data.length - macSize);
			if(!this.Verify(iv_encrypted, mac, keys[1]))
				throw new Exception("HMAC verification failed.");
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			return cipher.doFinal(encrypted);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	/**
	 * Creates a pair of keys from the given password.
	 * @param password
	 * @param salt
	 * @return keys
	 */
	private byte[][] KeyGen(String password, byte[] salt) {
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, rounds, keySize*2);
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte[] keys = skf.generateSecret(spec).getEncoded();
			byte[] aes_key = Arrays.copyOfRange(keys, 0, keySize/8);
			byte[] mac_key = Arrays.copyOfRange(keys, keySize/8, (keySize/8)*2);
			return new byte[][] {aes_key, mac_key};
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Creates random bytes.
	 * @param size
	 * @return random bytes
	 */
	private byte[] IVGen(Integer... size) {
		SecureRandom sr;
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
			byte[] iv = new byte[(size.length > 0) ? size[0] : ivSize];
			sr.nextBytes(iv);
			return iv;
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Creates HMAC signature.
	 * @param data
	 * @param key
	 * @return
	 */
	private byte[] Sign(byte[] data, byte[] key) {
		try {
			Mac hmac = Mac.getInstance("HmacSHA256");
			hmac.init(new SecretKeySpec(key, "HmacSHA256"));
			return  hmac.doFinal(data);
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Preforms HMAC verification.
	 * @param data
	 * @param mac
	 * @param key
	 * @return
	 */
	private Boolean Verify(byte[] data, byte[] mac, byte[] key) {
		byte[] data_mac = Sign(data, key); 
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

