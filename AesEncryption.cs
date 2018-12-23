using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;


/// <summary>
/// Encrypts data and files using AES CBC/CFB - 128/192/256 bits.
/// </summary>
/// <remarks>
/// The encryption and authentication keys 
/// are derived from the supplied key/password using HKDF/PBKDF2.
/// The key can be set either with `SetMasterKey` or with `RandomKeyGen`.
/// Encrypted data format: salt[16] + iv[16] + ciphertext[n] + mac[32].
/// Ciphertext authenticity is verified with HMAC SHA256.
/// </remarks>
/// <note type="caution">CFB is not supported in .NET Core.</note>
class AesEncryption
{
    private Dictionary<string, CipherMode> modes = new Dictionary<string, CipherMode>()
    {
        { "CBC", CipherMode.CBC }, { "CFB", CipherMode.CFB }
    };
    private int[] sizes = new int[] { 128, 192, 256 };
    private int saltLen = 16;
    private int ivLen = 16;
    private int macLen = 32;
    private int macKeyLen = 32;

    private string mode;
    private int keyLen;
    private byte[] masterkey;

    /// The number of PBKDF2 iterations (applies to password based keys).
    public int keyIterations = 20000;
    /// Accepts ans returns base64 encoded data.
    public bool base64 = true;

    /// <param name="mode">Optional, the AES mode (CBC or CFB)</param>
    /// <param name="size">Optional, the key size (128, 192, 256)</param>
    /// <exception cref="ArgumentException">
    /// Thrown when mode is not supported or size is invalid.
    /// </exception>
    public AesEncryption(string mode = "CBC", int size = 128)
    {
        this.mode = mode.ToUpper();
        this.keyLen = size / 8;

        if (!modes.ContainsKey(this.mode))
            throw new ArgumentException(mode + " is not supported!");
        if (Array.IndexOf(sizes, size) == -1)
            throw new ArgumentException("Invalid key size!");
    }

    /// <summary>Encrypts data using a key or the supplied password.</summary>
    /// <remarks>
    /// The password is not required if a master key has been set 
    /// (either with `RandomKeyGgen` or with `SetMasterKey`). 
    /// If a password is supplied, it will be used to create a key with PBKDF2.
    /// </remarks>
    /// <param name="data">The plaintext.</param>
    /// <param name="password">Optional, the password.</param>
    /// <returns>Encrypted data (salt + iv + ciphertext + mac).</returns>
    public byte[] Encrypt(byte[] data, string password = null)
    {
        byte[] iv = this.RandomBytes(ivLen);
        byte[] salt = this.RandomBytes(saltLen);
        try
        {
            byte[][] keys = this.Keys(salt, password);
            byte[] aesKey = keys[0], macKey = keys[1];

            byte[] ciphertext;
            using (SymmetricAlgorithm cipher = this.Cipher(aesKey, iv))
            using (ICryptoTransform ict = cipher.CreateEncryptor())
            {
                ciphertext = ict.TransformFinalBlock(data, 0, data.Length);
            }
            byte[] encrypted = new byte[saltLen + ivLen + ciphertext.Length + macLen];

            Array.Copy(salt, 0, encrypted, 0, saltLen);
            Array.Copy(iv, 0, encrypted, saltLen, ivLen);
            Array.Copy(ciphertext, 0, encrypted, saltLen + ivLen, ciphertext.Length);

            byte[] iv_ct = new byte[ivLen + ciphertext.Length];
            Array.Copy(encrypted, saltLen, iv_ct, 0, iv_ct.Length);
            byte[] mac = Sign(iv_ct, macKey);
            Array.Copy(mac, 0, encrypted, encrypted.Length - macLen, macLen);

            if (this.base64)
                return Encoding.ASCII.GetBytes(Convert.ToBase64String(encrypted));
            return encrypted;
        }
        catch (ArgumentException e)
        {
            this.ErrorHandler(e);
        }
        catch (CryptographicException e)
        {
            this.ErrorHandler(e);
        }
        return null;
    }

    /// <summary>Encrypts data using a key or the supplied password.</summary>
    /// <param name="data">The plaintext.</param>
    /// <param name="password">Optional, the password.</param>
    /// <returns>Encrypted data (salt + iv + ciphertext + mac).</returns>
    public byte[] Encrypt(string data, string password = null)
    {
        return Encrypt(Encoding.UTF8.GetBytes(data), password);
    }

    /// <summary>Decrypts data using a key or the supplied password.</summary>
    /// <remarks>
    /// The password is not required if a master key has been set 
    /// (either with `RandomKeyGgen` or with `SetMasterKey`). 
    /// If a password is supplied, it will be used to create a key with PBKDF2.
    /// </remarks>
    /// <param name="data">The ciphertext (raw of base46-encoded bytes).</param>
    /// <param name="password">Optional, the pasword.</param>
    /// <returns>Plaintext.</returns>
    public byte[] Decrypt(byte[] data, string password = null)
    {
        try
        {
            if (this.base64)
                data = Convert.FromBase64String((Encoding.ASCII.GetString(data)));
            if (data.Length - saltLen - ivLen - macLen < 0)
                throw new ArgumentException("Invalid data size!");
            
            byte[] salt = new byte[saltLen];
            byte[] iv = new byte[ivLen];
            byte[] ciphertext = new byte[data.Length - saltLen - ivLen - macLen];
            byte[] mac = new byte[macLen];

            Array.Copy(data, 0, salt, 0, saltLen);
            Array.Copy(data, saltLen, iv, 0, ivLen);
            Array.Copy(data, saltLen + ivLen, ciphertext, 0, ciphertext.Length);
            Array.Copy(data, saltLen + ivLen + ciphertext.Length, mac, 0, macLen);

            byte[][] keys = this.Keys(salt, password);
            byte[] aesKey = keys[0], macKey = keys[1];

            byte[] iv_ct = new byte[ivLen + ciphertext.Length];
            Array.Copy(data, saltLen, iv_ct, 0, iv_ct.Length);
            this.Verify(iv_ct, mac, macKey);

            byte[] plaintext;
            using (SymmetricAlgorithm cipher = this.Cipher(aesKey, iv))
            using (ICryptoTransform ict = cipher.CreateDecryptor())
            {
                plaintext = ict.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
            return plaintext;
        }
        catch (ArgumentException e)
        {
            this.ErrorHandler(e);
        }
        catch (CryptographicException e)
        {
            this.ErrorHandler(e);
        }
        catch (FormatException e)
        {
            this.ErrorHandler(e);
        }
        return null;
    }

    /// <summary>Decrypts data using a key or the supplied password.</summary>
    /// <param name="data">The ciphertext (raw of base46-encoded bytes).</param>
    /// <param name="password">Optional, the pasword.</param>
    /// <returns>Plaintext.</returns>
    public byte[] Decrypt(string data, string password = null)
    {
        return Decrypt(Encoding.ASCII.GetBytes(data), password);
    }

    /// <summary>Encrypts files using a key or the supplied password.</summary>
    /// <remarks>
    /// The original file is not modified; a new encrypted file is created.
    /// The password is not required if a master key has been set 
    /// (either with `RandomKeyGgen` or with `SetMasterKey`). 
    /// If a password is supplied, it will be used to create a key with PBKDF2.
    /// </remarks>
    /// <param name="path">The file path.</param>
    /// <param name="password">Optional, the pasword.</param>
    /// <returns>The encrypted file path.</returns>
    public string EncryptFile(string path, string password = null)
    {
        byte[] salt = RandomBytes(saltLen);
        byte[] iv = RandomBytes(ivLen);
        try
        {
            byte[][] keys = this.Keys(salt, password);
            byte[] aesKey = keys[0], macKey = keys[1];
            string newPath = path + ".enc";

            using (FileStream fs = new FileStream(newPath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(salt, 0, saltLen);
                fs.Write(iv, 0, ivLen);

                RijndaelManaged cipher = this.Cipher(aesKey, iv);
                ICryptoTransform ict = cipher.CreateEncryptor();
                HMACSHA256 hmac = new HMACSHA256(macKey);

                hmac.TransformBlock(iv, 0, iv.Length, null, 0);

                foreach (Object[] chunk in FileChunks(path))
                {
                    byte[] data = (byte[])chunk[0];
                    byte[] ciphertext = new byte[data.Length];

                    if ((bool)chunk[1])
                        ciphertext = ict.TransformFinalBlock(data, 0, data.Length);
                    else
                        ict.TransformBlock(data, 0, data.Length, ciphertext, 0);
                    
                    hmac.TransformBlock(ciphertext, 0, ciphertext.Length, null, 0);
                    fs.Write(ciphertext, 0, ciphertext.Length);
                }
                hmac.TransformFinalBlock(new byte[0], 0, 0);
                byte[] mac = hmac.Hash;
                fs.Write(mac, 0, mac.Length);

                ict.Dispose();
                cipher.Dispose();
                hmac.Dispose();
            }
            return newPath;
        }
        catch (ArgumentException e)
        {
            this.ErrorHandler(e);
        }
        catch (CryptographicException e)
        {
            this.ErrorHandler(e);
        }
        catch (UnauthorizedAccessException e)
        {
            this.ErrorHandler(e);
        }
        catch (IOException e)
        {
            this.ErrorHandler(e);
        }
        return null;
    }

    /// <summary>Decrypts files using a key or the supplied password.</summary>
    /// <remarks>
    /// The original file is not modified; a new decrypted file is created.
    /// The password is not required if a master key has been set 
    /// (either with `RandomKeyGgen` or with `SetMasterKey`). 
    /// If a password is supplied, it will be used to create a key with PBKDF2.
    /// </remarks>
    /// <param name="path">The file path.</param>
    /// <param name="password">Optional, the pasword.</param>
    /// <returns>Decrypted file path.</returns>
    public string DecryptFile(string path, string password = null)
    {
        byte[] salt = new byte[saltLen];
        byte[] iv = new byte[ivLen];
        byte[] mac = new byte[macLen];
        try
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                fs.Read(salt, 0, saltLen);
                fs.Read(iv, 0, ivLen);
                fs.Seek(new FileInfo(path).Length - macLen, SeekOrigin.Begin);
                fs.Read(mac, 0, macLen);
            }
            byte[][] keys = this.Keys(salt, password);
            byte[] aesKey = keys[0], macKey = keys[1];

            this.VerifyFile(path, mac, macKey);
            string newPath = Regex.Replace(path, ".enc$", ".dec");

            using (FileStream fs = new FileStream(newPath, FileMode.Create, FileAccess.Write))
            {
                RijndaelManaged cipher = this.Cipher(aesKey, iv);
                ICryptoTransform ict = cipher.CreateDecryptor();

                foreach (Object[] chunk in FileChunks(path, saltLen + ivLen, macLen))
                {
                    byte[] data = (byte[])chunk[0];
                    byte[] plaintext = new byte[data.Length];

                    if ((bool)chunk[1])
                    {
                        plaintext = ict.TransformFinalBlock(data, 0, data.Length);
                        fs.Write(plaintext, 0, plaintext.Length);
                    }
                    else
                    {
                        int size = ict.TransformBlock(data, 0, data.Length, plaintext, 0);
                        fs.Write(plaintext, 0, size);
                    }
                }
                ict.Dispose();
                cipher.Dispose();
            }
            return newPath;
        }
        catch (ArgumentException e)
        {
            this.ErrorHandler(e);
        }
        catch (CryptographicException e)
        {
            this.ErrorHandler(e);
        }
        catch (UnauthorizedAccessException e)
        {
            this.ErrorHandler(e);
        }
        catch (IOException e)
        {
            this.ErrorHandler(e);
        }
        return null;
    }

    /// <summary>Sets a new master key.</summary>
    /// <remarks>
    /// This key will be used to create the encryption and authentication keys.
    /// </remarks>
    /// <param name="key">The new master key.</param>
    /// <param name="raw">Optional, expexts raw bytes (not base64-encoded).</param>
    public void SetMasterKey(byte[] key, bool raw = false)
    {
        try
        {
            if (!raw)
                key = Convert.FromBase64String((Encoding.ASCII.GetString(key)));
            this.masterkey = key;
        }
        catch (FormatException e)
        {
            this.ErrorHandler(e);
        }
    }

    /// <summary>Sets a new master key.</summary>
    /// <remarks>
    /// This key will be used to create the encryption and authentication keys.
    /// </remarks>
    /// <param name="key">The new master key.</param>
    public void SetMasterKey(string key)
    {
        this.SetMasterKey(Encoding.ASCII.GetBytes(key), false);
    }

    /// <summary>
    /// Returns the master key (or null if the key is not set).
    /// </summary>
    /// <param name="raw">Optional, returns raw bytes (not base64-encoded).</param>
    /// <returns>The master key.</returns>
    public byte[] GetMasterKey(bool raw = false)
    {
        if (masterkey == null)
            this.ErrorHandler(new ArgumentException("The key is not set!"));
        else if (!raw)
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(masterkey));
        return masterkey;
    }

    /// <summary>Generates a new random key.</summary>
    /// <remarks>
    /// This key will be used to create the encryption and authentication keys.
    /// </remarks>
    /// <param name="keyLen">Optional, the key size.</param>
    /// <param name="raw">Optional, returns raw bytes (not base64-encoded).</param>
    /// <returns>The new master key.</returns>
    public byte[] RandomKeyGen(int keyLen = 32, bool raw = false)
    {
        masterkey = this.RandomBytes(keyLen);
        if (!raw)
        {
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(masterkey));
        }
        return masterkey;
    }

    /// <summary>
    /// Handles exceptions (prints the exception message by default).
    /// </summary>
    protected virtual void ErrorHandler(Exception exception)
    {
        Console.WriteLine(exception.Message);
    }

    /// <summary>
    /// Derives encryption and authentication keys from a key or password.
    /// If the password is not null, it will be used to create the keys.
    /// </summary>
    private byte[][] Keys(byte[] salt, string password = null)
    {
        byte[] dkey;
        if (password != null)
            dkey = Kdf.Pbkdf2Sha512(password, salt, keyLen + macKeyLen, keyIterations);
        else if (this.masterkey != null)
            dkey = Kdf.HkdfSha256(this.masterkey, salt, keyLen + macKeyLen);
        else
            throw new ArgumentException("No password or key specified!");

        byte[][] keys = new byte[2][] { new byte[keyLen], new byte[macKeyLen] };

        Array.Copy(dkey, 0, keys[0], 0, keyLen);
        Array.Copy(dkey, keyLen, keys[1], 0, macKeyLen);
        return keys;
    }

    /// <summary>
    /// Creates random bytes; used for IV, salt and key generation.
    /// </summary>
    private byte[] RandomBytes(int size)
    {
        byte[] rb = new byte[size];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(rb);
        }
        return rb;
    }

    /// <summary>
    /// Creates an RijndaelManaged object; used for encryption / decryption.
    /// </summary>
    private RijndaelManaged Cipher(byte[] key, byte[] iv)
    {
        RijndaelManaged cipher = new RijndaelManaged
        {
            KeySize = this.keyLen * 8,
            BlockSize = 128,
            Mode = this.modes[this.mode],
            Padding = (mode == "CFB") ? PaddingMode.None : PaddingMode.PKCS7,
            FeedbackSize = (mode == "CFB") ? 8 : 128,
            Key = key,
            IV = iv
        };
        return cipher;
    }

    /// <summary>
    /// Computes the MAC of ciphertext; used for authentication.
    /// </summary>
    private byte[] Sign(byte[] data, byte[] key)
    {
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(data);
        }
    }

    /// <summary>
    /// Computes the MAC of ciphertext; used for authentication.
    /// </summary>
    private byte[] SignFile(string path, byte[] key, int beg = 0, int end = 0)
    {
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            foreach (Object[] chunk in this.FileChunks(path, beg, end))
            {
                byte[] data = (byte[])chunk[0];
                hmac.TransformBlock(data, 0, data.Length, null, 0);
            }
            hmac.TransformFinalBlock(new byte[0], 0, 0);
            return hmac.Hash;
        }
    }

    /// <summary>Verifies the authenticity of ciphertext.</summary>
    /// <exception cref="ArgumentException">Thrown when MAC check fails.</exception>
    private void Verify(byte[] data, byte[] mac, byte[] key)
    {
        byte[] dataMac = this.Sign(data, key);

        if (!this.ConstantTimeComparison(mac, dataMac))
            throw new ArgumentException("MAC verification failed!");
    }

    /// <summary>Verifies the authenticity of ciphertext.</summary>
    /// <exception cref="ArgumentException">Thrown when MAC check fails.</exception>
    private void VerifyFile(string path, byte[] mac, byte[] key)
    {
        byte[] fileMac = this.SignFile(path, key, saltLen, macLen);

        if (!this.ConstantTimeComparison(mac, fileMac))
            throw new ArgumentException("MAC verification failed!");
    }

    /// <summary>A generator that reads a file and yields chunks of data.</summary>
    /// <remarks>The chunk size should be a multiple of the block size (16).</remarks>
    /// <exception cref="FileNotFoundException">
    /// Thrown when the file is not found.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// Thrown when the file is not accesible.
    /// </exception>
    private IEnumerable<Object[]> FileChunks(string path, int beg = 0, int end = 0)
    {
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
        {
            int size = 1024;
            end = (int)fs.Length - end;
            int pos = fs.Read(new byte[beg], 0, beg);

            while (pos < end)
            {
                size = (end - pos > size) ? size : end - pos;
                byte[] data = new byte[size];
                pos += fs.Read(data, 0, size);

                yield return new Object[] { data, (pos == end) };
            }
        }
    }

    /// <summary>Safely compares two byte arrays, used for uthentication.</summary>
    private bool ConstantTimeComparison(byte[] mac1, byte[] mac2)
    {
        int result = mac1.Length ^ mac2.Length;
        for (int i = 0; i < mac1.Length && i < mac2.Length; i++)
        {
            result |= mac1[i] ^ mac2[i];
        }
        return result == 0;
    }

    private class Kdf
    {
        /// <summary>An PBKDF2 algorithm implementation, with HMAC-SHA512.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="keyLen">The derived key size.</param>
        /// <param name="iterations">The number of iterations.</param>
        public static byte[] Pbkdf2Sha512(string password, byte[] salt, int keyLen, int iterations)
        {
            using (HMACSHA512 prf = new HMACSHA512(Encoding.UTF8.GetBytes(password)))
            {
                byte[] dkey = new byte[keyLen];
                int hashLen = prf.HashSize / 8;

                for (int i = 0; i < keyLen; i += hashLen)
                {
                    byte[] b = BitConverter.GetBytes(i / hashLen + 1);
                    byte[] sb = new byte[salt.Length + 4];

                    Array.Reverse(b);
                    Array.Copy(salt, sb, salt.Length);
                    Array.Copy(b, 0, sb, salt.Length, 4);

                    byte[] u = prf.ComputeHash(sb);
                    byte[] f = u;
                    for (int j = 1; j < iterations; j++)
                    {
                        u = prf.ComputeHash(u);
                        for (int k = 0; k < f.Length; k++)
                            f[k] ^= u[k];
                    }
                    if (i + hashLen > keyLen)
                        hashLen = hashLen - (i + hashLen - keyLen);
                    Array.Copy(f, 0, dkey, i, hashLen);
                }
                return dkey;
            }
        }

        /// <summary>A HKDF algorithm implementation, with HMAC-SHA256.</summary>
        /// <param name="key">The key.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="keyLen">The derived key size.</param>
        public static byte[] HkdfSha256(byte[] key, byte[] salt, int keyLen)
        {
            byte[] dkey = new byte[keyLen];
            byte[] mkey = new byte[0];
            byte[] prk;
            int hashLen = 32;

            using (HMACSHA256 hmac = new HMACSHA256(salt))
                prk = hmac.ComputeHash(key);
            
            for (int i = 0; i < keyLen; i += hashLen)
            {
                Array.Resize(ref mkey, mkey.Length + 1);

                mkey[mkey.Length - 1] = BitConverter.GetBytes(i / hashLen + 1)[0];
                using (HMACSHA256 hmac = new HMACSHA256(prk))
                    mkey = hmac.ComputeHash(mkey);

                if (i + hashLen > keyLen)
                    hashLen = hashLen - (i + hashLen - keyLen);
                Array.Copy(mkey, 0, dkey, i, hashLen);
            }
            return dkey;
        }
    }
}
