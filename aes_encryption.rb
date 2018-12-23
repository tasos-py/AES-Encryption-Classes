require 'openssl'
require 'base64'


# Encrypts data and files using AES CBC/CFB - 128/192/256 bits.
#
# The encryption and authentication keys 
# are derived from the supplied key/password using HKDF/PBKDF2.
# Ciphertext authenticity is verified with HMAC SHA256.
# Encrypted data format: salt[16] + iv[16] + ciphertext[n] + mac[32].
class AesEncryption
  attr_accessor :key_iterations, :base64

  # Creates a new AesEncryption object.
  # @param [String] mode Optional, the AES mode (CBC or CFB).
  # @param [Integer] size Optional, the key size (128, 192 or 256).
  # @throws [ArgumentError] if the mode or key size is not supported.
  def initialize(mode = 'CBC', size = 128)
    @modes = { 'CBC' => 'AES-%d-CBC', 'CFB' => 'AES-%d-CFB8' }
    @sizes = [128, 192, 256]
    @salt_len = 16
    @iv_len = 16
    @mac_len = 32
    @mac_key_len = 32

    unless @modes.has_key?(mode.upcase)
      raise ArgumentError, mode + ' is not supported!'
    end
    unless @sizes.include? size
      raise ArgumentError, 'Invalid key size!'
    end
    @mode = mode.upcase
    @key_len = size / 8
    @master_key = nil

    @base64 = true
    @key_iterations = 20000
  end

  # Encrypts data with the supplied password or master key.
  #
  # The password is not required if a master key has been set 
  # (either with `random_key_gen` or with `set_master_key`).
  # If a password is supplied it will be used to create a key with PBKDF2.
  #
  # @param [String] data The plaintext.
  # @param [String] password Optional, the password.
  # @return [String] Encrypted data (salt + iv + ciphertext + mac).
  def encrypt(data, password = nil)
    salt = random_bytes(@salt_len)
    iv = random_bytes(@salt_len)
    aes_key, mac_key = keys(salt, password)

    aes = cipher(aes_key, iv, true)
    ciphertext = aes.update(data) + aes.final
    mac = sign(iv + ciphertext, mac_key)

    encrypted = salt + iv + ciphertext + mac
    encrypted = Base64.strict_encode64(encrypted) if @base64
    encrypted
  rescue TypeError, ArgumentError => e
    error_handler e
  end
  
  # Decrypts data with the supplied password or master key.
  #
  # The password is not required if a master key has been set 
  # (either with `random_key_gen` or with `set_master_key`).
  # If a password is supplied it will be used to create a key with PBKDF2.
  #
  # @param [String] data The ciphertext.
  # @param [String] password Optional, the password.
  # @return [String] Plaintext.
  def decrypt(data, password = nil)
    data = Base64.strict_decode64(data) if @base64

    salt = data[0, @salt_len]
    iv = data[@salt_len, @iv_len]
    ciphertext = data[@salt_len + @iv_len..-@mac_len - 1]
    mac = data[data.length - @mac_len, @mac_len]

    aes_key, mac_key = keys(salt, password)
    verify(iv + ciphertext, mac, mac_key)

    aes = cipher(aes_key, iv, false)
    plaintext = aes.update(ciphertext) + aes.final
    plaintext
  rescue TypeError, ArgumentError, NoMethodError => e
    error_handler e
  rescue OpenSSL::OpenSSLError => e
    error_handler e
  end

  # Encrypts files with the supplied password or master key.
  #
  # The original file is not modified; a new encrypted file is created.
  # The password is not required if a master key has been set 
  # (either with `random_key_gen` or with `set_master_key`).
  # If a password is supplied it will be used to create a key with PBKDF2.
  #
  # @param [String] path The file path.
  # @param [String] password Optional, the password.
  # @return [String] Encrypted file path.
  def encrypt_file(path, password = nil)
    salt = random_bytes(@salt_len)
    iv = random_bytes(@salt_len)
    aes_key, mac_key = keys(salt, password)

    cipher = cipher(aes_key, iv)
    hmac = OpenSSL::HMAC.new(mac_key, OpenSSL::Digest::SHA256.new)
    new_path = path + '.enc'

    File.open(new_path, 'wb') do |out_file|
      out_file.syswrite salt
      out_file.syswrite iv
      hmac.update iv

      file_chunks(path).each do |chunk|
        encrypted = cipher.update(chunk)
        hmac.update encrypted
        out_file.syswrite encrypted
      end
      encrypted = cipher.final

      hmac.update encrypted
      out_file.syswrite encrypted
      out_file.syswrite hmac.digest
    end
    new_path
  rescue TypeError, ArgumentError, SystemCallError, IOError => e
    error_handler e
  end

  # Decrypts files with the supplied password or master key.
  #
  # The original file is not modified; a new decrypted file is created.
  # The password is not required if a master key has been set 
  # (either with `random_key_gen` or with `set_master_key`).
  # If a password is supplied it will be used to create a key with PBKDF2.
  #
  # @param [String] path The file path. 
  # @param [String] password Optional, the password.
  # @return [String] Decrypted file path.
  def decrypt_file(path, password = nil)
    in_file = File.new(path, 'rb')

    salt = in_file.sysread(@salt_len)
    iv = in_file.sysread(@iv_len)
    in_file.seek(-@mac_len, IO::SEEK_END)
    mac = in_file.sysread(@mac_len)

    in_file.close

    aes_key, mac_key = keys(salt, password)
    verify_file(path, mac, mac_key)

    cipher = cipher(aes_key, iv, false)
    chunks = file_chunks(path, @salt_len + @iv_len, @mac_len)
    new_path = path.gsub(/\.enc$/, '.dec')

    File.open(new_path, 'wb') do |out_file|
      chunks.each do |chunk| 
        out_file.syswrite cipher.update(chunk)
      end
      out_file.syswrite cipher.final
    end
    new_path
  rescue TypeError, ArgumentError, NoMethodError => e
    error_handler e
  rescue SystemCallError, IOError, OpenSSL::OpenSSLError => e
    error_handler e
  end
  
  # Sets a new master key,
  # which will be used to create the encryption and authentication keys.
  # 
  # @param [String] key The new master key.
  # @param [Boolean] raw Optional, expexts raw bytes (not base64-encoded).
  def set_master_key(key, raw = false)
    key = Base64.strict_decode64(key) unless raw
    @master_key = key
  rescue TypeError, ArgumentError => e
    error_handler e
  end

  # Returns the master key (or nil if the key is not set).
  #
  # @param [Boolean] raw Optional, returns raw bytes (not base64-encoded).
  # @return [String] The master key.
  def get_master_key(raw = false)
    if @master_key.nil?
      error_handler(ArgumentError, 'The key is not specified!')
    else
      raw ? @master_key : Base64.strict_encode64(@master_key)
    end
  end

  # Generates a random key.
  # This key will be to create the encryption and authentication keys.
  # 
  # @param [Integer] key_len Optional, the key size.
  # @param [Boolean] raw Optional, returns raw bytes (not base64-encoded).
  # @return [String] The new master key.
  def random_key_gen(key_len = 32, raw = false)
    @master_key = random_bytes key_len
    raw ? @master_key : Base64.strict_encode64(@master_key)
  end

  protected

  # Handles exceptions (prints the exception by default).
  def error_handler(exception)
    puts exception
  end

  private

  # Derives encryption and authentication keys from a key or password.
  # If the password is not nil, it will be used to create the keys.
  def keys(salt, password = nil)
    dkey_len = @key_len + @mac_key_len
    if !password.nil?
      begin
        dkey = OpenSSL::PKCS5.pbkdf2_hmac(
          password, salt, @key_iterations, dkey_len, OpenSSL::Digest::SHA512.new
        )
      rescue NotImplementedError
        dkey = pbkdf2_sha512(password, salt, dkey_len, @key_iterations)
      end
    elsif !@master_key.nil?
      dkey = hkdf_sha256(@master_key, salt, dkey_len)
    else
      raise ArgumentError, 'No password or key specified!'
    end
    [dkey[0, @key_len], dkey[@key_len, dkey_len]]
  end

  # Creates a OpenSSL Cipher object, used for encryption.
  def cipher(key, iv, encrypt = true)
    mode = @modes[@mode] % (@key_len * 8)
    cipher = OpenSSL::Cipher.new(mode)
    encrypt ? cipher.encrypt : cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    cipher
  end

  # Creates random bytes, used for IV, salt and key generation.
  def random_bytes(size)
    OpenSSL::Random.random_bytes size
  end

  # Computes the MAC of ciphertext, used for authentication.
  def sign(data, key)
    hmac = OpenSSL::HMAC.new(key, OpenSSL::Digest::SHA256.new)
    hmac.update data
    hmac.digest
  end

  # Verifies the authenticity of ciphertext.
  def verify(data, mac, key)
    data_mac = sign(data, key)
    unless constant_time_comparison(mac, data_mac)
      raise ArgumentError, 'MAC check failed!'
    end
  end

  # Computes the MAC of ciphertext, used for authentication.
  def sign_file(path, key)
    hmac = OpenSSL::HMAC.new(key, OpenSSL::Digest::SHA256.new)
    file_chunks(path, 0, @mac_len).each { |chunk| hmac.update chunk }
    hmac.digest
  end

  # Verifies the authenticity of ciphertext.
  def verify_file(path, mac, key)
    hmac = OpenSSL::HMAC.new(key, OpenSSL::Digest::SHA256.new)
    file_chunks(path, @salt_len, @mac_len).each do |chunk|
      hmac.update chunk
    end
    unless constant_time_comparison(mac, hmac.digest)
      raise ArgumentError, 'MAC check failed!'
    end
  end

  # A generator that reads a file and yields chunks of data.
  def file_chunks(path, fbeg = 0, fend = 0)
    size = 1024
    fend = File.size(path) - fend

    Enumerator::Generator.new { |gen|
      File.open(path, 'rb') do |file|
        pos = file.sysread(fbeg).length

        while pos < fend
          size = fend - pos if fend - pos < size
          data = file.sysread(size)
          pos += data.length

          gen.yield data
        end
      end
    }
  end

  # Safely compares two strings, used for uthentication.
  def constant_time_comparison(mac_a, mac_b)
    result = mac_a.length ^ mac_b.length
    for i in 0..[mac_a.length, mac_b.length].min - 1
      result |= mac_a[i].ord ^ mac_b[i].ord
    end
    result.zero?
  end

  # A PBKDF2 implementation, with HMAC SHA512.
  # Deriving a master key from the password.
  def pbkdf2_sha512(password, salt, dkey_len, iterations)
    dkey = ''
    hash = OpenSSL::Digest::SHA512.new

    (1..(1.0 * dkey_len / hash.length).ceil).each do |block|
      u = OpenSSL::HMAC.digest(hash, password, salt + [block].pack('N'))
      f = u.bytes.to_a

      (1..iterations - 1).each do
        u = OpenSSL::HMAC.digest(hash, password, u)
        u_bytes = u.bytes.to_a
        f.each.with_index.each.each { |b, i| f[i] = b ^ u_bytes[i] }
      end
      dkey += f.pack('C*')
    end
    dkey[0, dkey_len]
  end

  # A HKDF implementation, with HMAC SHA256. 
  # Expanding the master key to derive AES and HMAC keys.
  def hkdf_sha256(key, salt, dkey_len, info = nil)
    dkey = ''
    hash = OpenSSL::Digest::SHA256.new
    prk = OpenSSL::HMAC.digest(hash, salt, key)

    (1..(1.0 * dkey_len / hash.length).ceil).each do |i|
      data = (dkey[-hash.length..-1] || '') + (info || '') + [i].pack('C')
      dkey += OpenSSL::HMAC.digest(hash, prk, data)
    end
    dkey[0, dkey_len]
  end
end


