import java.security._
import javax.crypto._
import javax.crypto.spec._
import java.util.Base64
import java.io._
import scala.math.ceil


/**
 * Encrypts data and files using AES CBC/CFB, 128/192/256 bits. 
 * 
 * The encryption and authentication keys 
 * are derived from the supplied key/password using HKDF/PBKDF2.
 * The key can be set either with `setMasterKey` or with `randomKeyGen`.
 * Encrypted data format: salt[16] + iv[16] + ciphertext[n] + mac[32].
 * Ciphertext authenticity is verified with HMAC SHA256.
 * 
 * @param mode Optional, the AES mode (CBC, CFB).
 * @param size Optional, the key size in bits (128, 192, 256).
 * @throws IllegalArgumentException If mode or key size is not supported.
 */
class AesEncryption(val mode:String = "CBC", val size:Int = 128) {
  private val modes = Map[String, String](
    "CBC" -> "AES/CBC/PKCS5Padding", 
    "CFB" -> "AES/CFB8/NoPadding"
  )
  private val sizes = Array[Int](128, 192, 256)
  private val saltLen = 16
  private val ivLen = 16
  private val macLen = 32
  private val macKeyLen = 32
  
  private val keyLen = size / 8
  private val aesMode = mode.toUpperCase
  private var masterKey: Array[Byte] = null
  
  var keyIterations: Int = 20000
  var base64: Boolean = true

  if (!modes.contains(aesMode)) {
    throw new IllegalArgumentException("Unsupported mode: " + mode)
  }
  if (!sizes.contains(size)) {
    throw new IllegalArgumentException("Invalid key size!")
  }
  if (size > Cipher.getMaxAllowedKeyLength("AES")) {
    throw new IllegalArgumentException("Key size is not supported!")
  }

  /**
   * Encrypts data using the supplied password.
   * The password will be used to create a master key with PBKDF2.
   * 
   * @param data The plaintext.
   * @param password The password.
   * @return Encrypted data (salt + iv + ciphertext + hmac).
   */
  def encrypt(data: Array[Byte], password: String): Array[Byte] = {
    val salt = randomBytes(saltLen)
    val iv = randomBytes(ivLen)
    try {
      val (aesKey, macKey) = this.keys(salt, password)
      val cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv)
      
      val ciphertext = cipher.doFinal(data)
      val mac = this.sign(iv ++ ciphertext, macKey)
      var encrypted = salt ++ iv ++ ciphertext ++ mac
          
      if (this.base64)
        encrypted = Base64.getEncoder.encode(encrypted)
      encrypted
    } catch {
      case e: IllegalArgumentException => this.errorHandler(e); null
    }
  }
  
  /**
   * Encrypts data using the supplied password.
   * The password will be used to create a master key with PBKDF2.
   * 
   * @param data The plaintext.
   * @param password The password.
   * @return Encrypted data (salt + iv + ciphertext + hmac).
   */
  def encrypt(data: String, password: String): Array[Byte] = {
    encrypt(data.getBytes, password)
  }
  
  /**
   * Encrypts data using a key.
   * The key can be set either with `setMasterKey` or with `randomKeyGen`. 
   * 
   * @param data The plaintext.
   * @return Encrypted data (salt + iv + ciphertext + hmac).
   */
  def encrypt(data: Array[Byte]): Array[Byte] = {
    encrypt(data, null)
  }
  
  /**
   * Encrypts data using a key.
   * The key can be set either with `setMasterKey` or with `randomKeyGen`. 
   * 
   * @param data The plaintext.
   * @return Encrypted data (salt + iv + ciphertext + hmac).
   */
  def encrypt(data: String): Array[Byte] = {
    encrypt(data.getBytes, null)
  }
  
  /**
   * Decrypts data using the supplied password.
   * The password will be used to create a master key with PBKDF2.
   * 
   * @param data The ciphertext.
   * @param password The password.
   * @return Plaintext.
   */
  def decrypt(data: Array[Byte], password: String): Array[Byte] = {
    try {
      val _data = if (this.base64) Base64.getDecoder.decode(data) else data
      
      val salt = _data.slice(0, saltLen)
      val iv = _data.slice(saltLen, saltLen + ivLen)
      val ciphertext = _data.slice(saltLen + ivLen, _data.length - macLen)
      val mac = _data.slice(_data.length - macLen, _data.length)

      val (aesKey, macKey) = this.keys(salt, password)
      this.verify(iv ++ ciphertext, mac, macKey)

      val cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv)
      val plaintext = cipher.doFinal(ciphertext)
      plaintext
    } catch {
      case e: IllegalArgumentException => this.errorHandler(e); null
      case e: IllegalBlockSizeException => this.errorHandler(e); null
      case e: BadPaddingException => this.errorHandler(e); null
    }
  }
  
  /**
   * Decrypts data using the supplied password.
   * The password will be used to create a master key with PBKDF2.
   * 
   * @param data The ciphertext, base64-encoded.
   * @param password The password.
   * @return Plaintext.
   */
  def decrypt(data: String, password: String): Array[Byte] = {
    decrypt(data.getBytes, password)
  }
  
  /**
   * Decrypts data using a key.
   * The key can be set either with `setMasterKey` or with `randomKeyGen`. 
   * 
   * @param data The ciphertext.
   * @return Plaintext.
   */
  def decrypt(data: Array[Byte]): Array[Byte] = {
    decrypt(data, null)
  }
  
  /**
   * Decrypts data using a key.
   * The key can be set either with `setMasterKey` or with `randomKeyGen`. 
   * 
   * @param data The ciphertext, base64-encoded.
   * @return Plaintext.
   */
  def decrypt(data: String): Array[Byte] = {
    decrypt(data.getBytes, null)
  }
  
  /**
   * Encrypts files using the supplied password.
   * The password will be used to create a master key with PBKDF2.
   * The original file is not modified; a new encrypted file is created.
   * 
   * @param path The file path.
   * @param password The password.
   * @return The new file path.
   */
  def encryptFile(path: String, password: String): String = {
    val salt = randomBytes(saltLen)
    val iv = randomBytes(ivLen)
    try {
      val (aesKey, macKey) = this.keys(salt, password)      
      val cipher = this.cipher(Cipher.ENCRYPT_MODE, aesKey, iv)
      
	    val hmac = Mac.getInstance("HmacSHA256")	    
	    hmac.init(new SecretKeySpec(macKey, "HmacSHA256"))
      hmac.update(iv)

      val newPath = path + ".enc"
      val fs = new FileOutputStream(newPath)
      fs.write(salt)
      fs.write(iv)
      
      for (chunk <- new FileChunks(path)) {
        val ciphertext = cipher.update(chunk)
        hmac.update(ciphertext)
        fs.write(ciphertext)
      }
      val ciphertext = cipher.doFinal           
      val mac = hmac.doFinal(ciphertext)
      
      fs.write(ciphertext)
      fs.write(mac)
      fs.close
      newPath
    } catch {
      case e: IllegalArgumentException => this.errorHandler(e); null
      case e: IOException => this.errorHandler(e); null
    }
  }
  
  /**
   * Decrypts files using a key.
   * The key can be set either with `setMasterKey` or with `randomKeyGen`. 
   * The original file is not modified; a new encrypted file is created.
   * 
   * @param path The file path.
   * @return The new file path.
   */
  def encryptFile(path: String): String = {
    encryptFile(path, null)
  }
  
  /**
   * Decrypts files using the supplied password.
   * The password will be used to create a master key with PBKDF2.
   * The original file is not modified; a new decrypted file is created.
   * 
   * @param path The file path.
   * @param password The password.
   * @return The new file path.
   */
  def decryptFile(path: String, password: String): String = {    
    val salt = new Array[Byte](saltLen)
    val iv = new Array[Byte](ivLen)
    val mac = new Array[Byte](macLen)
    try {
      val fis = new FileInputStream(path)

      fis.read(salt)
      fis.read(iv)
      fis.skip(new File(path).length - saltLen - ivLen - macLen)
      fis.read(mac)
      fis.close
      
      val (aesKey, macKey) = this.keys(salt, password)
      verifyFile(path, mac, macKey)
      val cipher = this.cipher(Cipher.DECRYPT_MODE, aesKey, iv)
        
      val newPath = path.replaceAll("\\.enc$", ".dec")
      val fos = new FileOutputStream(newPath)
      val fc = new FileChunks(path, saltLen + ivLen, macLen)

      for (chunk <- fc) {
        fos.write(cipher.update(chunk))
      }
      fos.write(cipher.doFinal)
      fos.close
      newPath
    } catch {
      case e: IllegalArgumentException => this.errorHandler(e); null
      case e: IOException => this.errorHandler(e); null
      case e: IllegalBlockSizeException => this.errorHandler(e); null
      case e: BadPaddingException => this.errorHandler(e); null
    }
  }
  
  /**
   * Decrypts files using a key.
   * The key can be set either with `randomKeyGen` or with `setMasterKey`. 
   * The original file is not modified; a new decrypted file is created.
   * 
   * @param data The file path.
   * @return The new file path.
   */
  def decryptFile(path: String): String = {
    decryptFile(path, null)
  }
  
  /**
   * Sets a new master key, 
   * which will be used to create the encryption and authentication keys.
   * 
   * @param key The new master key.
   * @param raw Optional, expects raw bytes (not base64-encoded).
   */
  def setMasterKey(key: Array[Byte], raw: Boolean = false): Unit = {
    try {
      masterKey = if (!raw) Base64.getDecoder().decode(key) else key
    } catch {
      case e: IllegalArgumentException => this.errorHandler(e)
    }
  }

  /**
   * Sets a new master key, 
   * which will be used to create the encryption and authentication keys.
   * 
   * @param key The new master key, base64-encoded.
   */
  def setMasterKey(key: String): Unit = {
    this.setMasterKey(key.getBytes, false)
  }

  /**
   * Returns the master key (or `null` if the key is not set).
   * 
   * @param raw Optional, returns raw bytes (not base64-encoded).
   */
  def getKey(raw: Boolean = false): Array[Byte] = {
    if (masterKey == null) {
      this.errorHandler(new Exception("The key is not set!")); null
    } else if (!raw) {
      Base64.getEncoder().encode(masterKey)
    } else {
      masterKey   
    }
  }
  
  /**
   * Generates a new random master key.
   * 
   * @param keyLen Optional, the key size.
   * @param raw Optional, returns raw bytes (not base64-encoded).
   */
  def randomKeyGen(keyLen: Int = 32, raw: Boolean = false): Array[Byte] = {
    masterKey = this.randomBytes(keyLen)
    if (raw) masterKey else Base64.getEncoder().encode(masterKey)
  }
  
  /**
   * Handles exceptions (prints the exception by default).
   */
  protected def errorHandler(exception: Exception) {
    println(exception)
  }
  
  /**
   * Derives encryption and authentication keys from a key or password.
   * If the password is not null, it will be used to create the keys.
   * @throws IllegalArgumentException If neither the key or password is set.
   */
  private def keys(salt: Array[Byte], password: String): (Array[Byte], Array[Byte]) = {
    var dkey: Array[Byte] = Array[Byte]()
    if (password != null) {
      val ks = new PBEKeySpec(
        password.toCharArray, salt, keyIterations, (keyLen + macKeyLen) * 8
      )
      val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
      dkey = skf.generateSecret(ks).getEncoded() 
    } else if (masterKey != null) {
      dkey = this.hkdfSha256(masterKey, salt, keyLen + macKeyLen)
    } else {
      throw new IllegalArgumentException("No password or key specified!")
    }
    (dkey.slice(0, keyLen), dkey.slice(keyLen, keyLen + macKeyLen))
  }
  
  /** 
   * Creates a new Cipher object; used for encryption / decryption.
   */
  private def cipher(cipherMode: Int, key: Array[Byte], iv: Array[Byte]): Cipher = {
	  val cipher = Cipher.getInstance(this.modes(this.aesMode))
	  cipher.init(cipherMode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
    cipher
  }
  
  /**
   * Creates random bytes; used for IV, salt and key generation.
   */
  private def randomBytes(size:Int): Array[Byte] = {
    val rb = new Array[Byte](size)
    val rng = SecureRandom.getInstance("SHA1PRNG");
    rng.nextBytes(rb)
    rb
  }
  
  /**
   * Computes the MAC of ciphertext; used for authentication.
   */
  private def sign(data: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val hmac = Mac.getInstance("HmacSha256")
    hmac.init(new SecretKeySpec(key, "HmacSha256"))
    hmac.doFinal(data)
  }
  
   /**
   * Verifies the authenticity of ciphertext.
   * @throws IllegalArgumentException When the MAC is invalid.
   */
  private def verify(data: Array[Byte], mac: Array[Byte], key: Array[Byte]) {
    val dataMac = sign(data, key) 
    if (!MessageDigest.isEqual(dataMac, mac)) {
      throw new IllegalArgumentException("MAC check failed!")
    }
  }

  /**
   * Computes the MAC of ciphertext; used for authentication.
   * @throws IOException When file is not accessible.
   */
  private def signFile(path: String, key: Array[Byte], start: Int, end: Int): Array[Byte] = {
    val hmac = Mac.getInstance("HmacSha256")
    hmac.init(new SecretKeySpec(key, "HmacSha256"))
    
    for (chunk <- new FileChunks(path, start, end)) {
      hmac.update(chunk)
    }
    hmac.doFinal(new Array[Byte](0))
  }
  
  /**
   * Verifies the authenticity of ciphertext.
   * @throws IllegalArgumentException when the MAC is invalid.
   * @throws IOException When the file is not accessible.
   */
  private def verifyFile(path: String, mac: Array[Byte], key: Array[Byte]) {
    val fileMac = signFile(path, key, saltLen, macLen)
    if (!MessageDigest.isEqual(fileMac, mac)) {
      throw new IllegalArgumentException("MAC check failed!")
    }
  }
  
  /**
   * Reads a file and yields chunks of data.
   * 
   * @param path The file path.
   * @param start The starting position in file.
   * @param end Tje ending position in file (filesize - end).
   * @throws IOException When the file is not accessible.
   */
  private class FileChunks(path:String, beg:Int = 0, end:Int = 0) extends Iterator[Array[Byte]] {
    private val fis = new FileInputStream(path)
    private var pos = fis.read(new Array[Byte](beg))
    private val _end = new File(path).length - end
    final val chunkSize = 1024
    
    def hasNext = (this.pos < this._end)
    
    def next = {
      val bufferSize = if (_end - pos > chunkSize) chunkSize else _end - pos
      val data = new Array[Byte](bufferSize.toInt) 
      this.pos += this.fis.read(data)
      
      if (pos == this._end) 
        fis.close()
      data 
    }
  }
  
  /**
   * A HKDF algorithm implementation, with HMAC-SHA256.
   * Expands the master key to create the AES and HMAC keys.
   */
  private def hkdfSha256(key: Array[Byte], salt: Array[Byte], dkeyLen: Int): Array[Byte] = {
    var dkey = new Array[Byte](0)    
    val hmac = Mac.getInstance("HmacSHA256")
    hmac.init(new SecretKeySpec(salt, "HmacSHA256"))
    val hashLen = hmac.getMacLength
    val prk = hmac.doFinal(key)

    for (i <- 0 until (dkeyLen / hashLen.toFloat).ceil.toInt) {
      var data = dkey.slice(dkey.length - hashLen, dkey.length) :+ (i + 1).toByte
      hmac.init(new SecretKeySpec(prk, "HmacSHA256"))
      dkey = dkey ++ hmac.doFinal(data)
    }
    dkey.slice(0, dkeyLen)
  }
}


