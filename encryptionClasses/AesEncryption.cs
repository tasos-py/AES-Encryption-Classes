using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;


/// <summary>
/// Encrypts data and files using AES CBC/CFB, 128/192/256 bits.
/// </summary>
class AesEncryption
{
    private Dictionary<string, CipherMode> modes = new Dictionary<string, CipherMode>()
    {
        { "CBC", CipherMode.CBC }, { "CFB", CipherMode.CFB }
    };
    private int[] sizes = new int[] { 128, 192, 256 };
    private int size = 128;
    private string mode = "CBC";
    private int saltLen = 16;
    private int ivLen = 16;
    private int macLen = 32;
    private int keyLen = 16;
    public int keyIterations = 20000;
    public bool base64 = true;

    /// <param name="mode">The AES mode (CBC or CFB)</param>
    /// <param name="size">The key size (128, 192, 256)</param>
    /// <exception cref="ArgumentException">
    /// Thrown when mode is not supported or size is invalid.
    /// </exception>
    public AesEncryption(string mode = "CBC", int size = 128)
    {
        mode = mode.ToUpper();
        if (!modes.ContainsKey(mode))
            throw new ArgumentException("Unsupported mode: " + mode);
        if (Array.IndexOf(sizes, size) == -1)
            throw new ArgumentException("Invalid key size");
        this.mode = mode;
        this.keyLen = size / 8;
        this.size = size;
    }

    /// <summary>Encrypts data.</summary>
    /// <param name="data">The data.</param>
    /// <param name="password">The pasword to use.</param>
    /// <returns>Raw or base64 encoded bytes.</returns>
    public byte[] Encrypt(byte[] data, string password)
    {
        byte[] iv = RandomBytes(ivLen);
        byte[] salt = RandomBytes(saltLen);

        byte[][] keys = Keys(password, salt);
        byte[] aesKey = keys[0], macKey = keys[1];
        byte[] ciphertext;

        using (RijndaelManaged cipher = Cipher())
        {
            using (ICryptoTransform ict = cipher.CreateEncryptor(aesKey, iv))
            {
                ciphertext = ict.TransformFinalBlock(data, 0, data.Length);
            }
        }
        List<byte> sicm = new List<byte>();
        sicm.AddRange(iv);
        sicm.AddRange(ciphertext);

        byte[] mac = Sign(sicm.ToArray(), macKey);
        sicm.InsertRange(0, salt);
        sicm.AddRange(mac);

        byte[] encrypted = sicm.ToArray();
        sicm.Clear();

        if (base64)
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(encrypted));
        return encrypted;
    }

    /// <summary>Encrypts data (string)</summary>
    public byte[] Encrypt(string data, string password)
    {
        return Encrypt(Encoding.UTF8.GetBytes(data), password);
    }

    /// <summary>Decrypts data.</summary>
    /// <param name="data">Encrypted data.</param>
    /// <param name="password">The pasword to use.</param>
    /// <returns>Decrypted data.</returns>
    public byte[] Decrypt(byte[] data, string password)
    {
        try
        {
            if (base64)
                data = Convert.FromBase64String((Encoding.ASCII.GetString(data)));

            List<byte> sicm = new List<byte>(data);
            int ctSize = sicm.Count - (saltLen + ivLen + macLen);

            byte[] salt = sicm.GetRange(0, saltLen).ToArray();
            byte[] iv = sicm.GetRange(saltLen, ivLen).ToArray();
            byte[] ciphertext = sicm.GetRange(saltLen + ivLen, ctSize).ToArray();
            byte[] mac = sicm.GetRange(sicm.Count - macLen, macLen).ToArray();

            byte[][] keys = Keys(password, salt);
            byte[] aesKey = keys[0], macKey = keys[1];

            byte[] iv_ct = sicm.GetRange(saltLen, sicm.Count - (saltLen + macLen)).ToArray();
            Verify(iv_ct, mac, macKey);
            sicm.Clear();

            byte[] decrypted;
            using (RijndaelManaged cipher = Cipher())
            {
                using (ICryptoTransform ict = cipher.CreateDecryptor(aesKey, iv))
                {
                    decrypted = ict.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
            return decrypted;
        }
        catch (FormatException e)
        {
            ErrorHandler(e);
        }
        catch (ArgumentException e)
        {
            ErrorHandler(e);
        }
        return new byte[0];
    }

    /// <summary>Decrypts data (string, base64 encoded).</summary>
    public byte[] Decrypt(string data, string password)
    {
        return Decrypt(Encoding.ASCII.GetBytes(data), password);
    }

    /// <summary>
    /// Encrypts files. 
    /// Doesn't modify the original file, but creates an encrypted copy.
    /// Useful for larger files that can't be stored in memory.
    /// </summary>
    /// <param name="path">The path of file to encrypt.</param>
    /// <param name="password">The pasword.</param>
    /// <returns>New file path.</returns>
    public string EncryptFile(string path, string password)
    {
        string newPath = path + ".enc";
        byte[] salt = RandomBytes(saltLen);
        byte[] iv = RandomBytes(ivLen);

        byte[][] keys = Keys(password, salt);
        byte[] aesKey = keys[0], macKey = keys[1];
        try
        {
            using (FileStream fs = new FileStream(newPath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(salt, 0, saltLen);
                fs.Write(iv, 0, ivLen);

                RijndaelManaged cipher = Cipher();
                HMACSHA256 hmac = new HMACSHA256(macKey);
                hmac.TransformBlock(iv, 0, iv.Length, null, 0);

                using (ICryptoTransform ict = cipher.CreateEncryptor(aesKey, iv))
                {
                    long fileSize = new FileInfo(path).Length;
                    int counter = 0;
                    foreach (byte[] data in ReadFileChunks(path))
                    {
                        counter += data.Length;
                        byte[] ciphertext = new byte[data.Length];
                        if (counter == fileSize)
                            ciphertext = ict.TransformFinalBlock(data, 0, data.Length);
                        else
                            ict.TransformBlock(data, 0, data.Length, ciphertext, 0);

                        hmac.TransformBlock(ciphertext, 0, ciphertext.Length, null, 0);
                        fs.Write(ciphertext, 0, ciphertext.Length);
                    }
                }
                hmac.TransformFinalBlock(new byte[0], 0, 0);
                byte[] mac = hmac.Hash;
                fs.Write(mac, 0, mac.Length);

                cipher.Dispose();
                hmac.Dispose();
            }
            return newPath;
        }
        catch (FileNotFoundException e)
        {
            ErrorHandler(e);
        }
        catch (UnauthorizedAccessException e)
        {
            ErrorHandler(e);
        }
        return "";
    }

    /// <summary>
    /// Decrypts files. 
    /// Doesn't modify the encrypted file, but creates a decrypted copy.
    /// Useful for larger files that can't be stored in memory.
    /// </summary>
    /// <param name="path">The path of file to decrypt.</param>
    /// <param name="password">The pasword.</param>
    /// <returns>Decrypted file path.</returns>
    public string DecryptFile(string path, string password)
    {
        string newPath = Regex.Replace(path, ".enc$", ".dec");
        byte[] salt = new byte[saltLen];
        byte[] iv = new byte[ivLen];
        byte[] mac = new byte[macLen];
        try
        {
            long fileSize = new FileInfo(path).Length;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                fs.Read(salt, 0, saltLen);
                fs.Read(iv, 0, ivLen);
                fs.Seek(fileSize - macLen, SeekOrigin.Begin);
                fs.Read(mac, 0, macLen);
            }
            byte[][] keys = Keys(password, salt);
            byte[] aesKey = keys[0], macKey = keys[1];

            VerifyFile(path, mac, macKey);

            using (FileStream fs = new FileStream(newPath, FileMode.Create, FileAccess.Write))
            {
                RijndaelManaged cipher = Cipher();
                using (ICryptoTransform ict = cipher.CreateDecryptor(aesKey, iv))
                {
                    int counter = 0;
                    foreach (byte[] data in ReadFileChunks(path, saltLen + ivLen, macLen))
                    {
                        counter += data.Length;
                        byte[] cleartext = new byte[data.Length];
                        if (counter == fileSize - saltLen - ivLen - macLen)
                        {
                            cleartext = ict.TransformFinalBlock(data, 0, data.Length);
                            fs.Write(cleartext, 0, cleartext.Length);
                            break;
                        }
                        int size = ict.TransformBlock(data, 0, data.Length, cleartext, 0);
                        fs.Write(cleartext, 0, size);
                    }
                }
                cipher.Dispose();
            }
            return newPath;
        }
        catch (FileNotFoundException e)
        {
            ErrorHandler(e);
        }
        catch (UnauthorizedAccessException e)
        {
            ErrorHandler(e);
        }
        catch (ArgumentException e)
        {
            ErrorHandler(e);
        }
        return "";
    }

    /// <summary>Creates a pair of keys (one for AES, the other for MAC).</summary>
    /// <param name="password">The pasword.</param>
    /// <param name="salt">The salt.</param>
    /// <returns>keys</returns>
    private byte[][] Keys(string password, byte[] salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] key = Pbkdf2Sha256(passwordBytes, salt);
        byte[][] keys = new byte[2][] { new byte[keyLen], new byte[keyLen] };

        Array.Copy(key, 0, keys[0], 0, keyLen);
        Array.Copy(key, keyLen, keys[1], 0, keyLen);
        return keys;
    }

    /// <summary>Creates random bytes, used for IV and salt.</summary>
    /// <param name="size">The number of bytes.</param>
    /// <returns>Random bytes.</returns>
    private byte[] RandomBytes(int size = 16)
    {
        byte[] rb = new byte[size];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(rb);
        }
        return rb;
    }

    /// <summary>
    /// Creates a RijndaelManaged object for encryption.
    /// RijndaelManaged is used as AesManaged doesn't accept unpadded blocks.
    /// </summary>
    private RijndaelManaged Cipher()
    {
        RijndaelManaged cipher = new RijndaelManaged
        {
            Mode = modes[mode],
            KeySize = size,
            Padding = (mode == "CFB") ? PaddingMode.None : PaddingMode.PKCS7,
            FeedbackSize = (mode == "CFB") ? 8 : 128,
            BlockSize = 128,
        };
        return cipher;
    }

    /// <summary>Creates MAC signature.</summary>
    /// <param name="data">The data.</param>
    /// <param name="key">The key.</param>
    /// <returns>MAC</returns>
    private byte[] Sign(byte[] data, byte[] key)
    {
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(data);
        }
    }

    /// <summary>Creates MAC signature of a file.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="key">The key.</param>
    /// <returns>MAC</returns>
    private byte[] SignFile(string path, byte[] key, int start = 0, int end = 0)
    {
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            foreach (byte[] data in ReadFileChunks(path, start, end))
            {
                hmac.TransformBlock(data, 0, data.Length, null, 0);
            }
            hmac.TransformFinalBlock(new byte[0], 0, 0);
            return hmac.Hash;
        }
    }

    /// <summary>Verifies that the MAC is valid.</summary>
    /// <param name="data">The data (IV + ciphertext).</param>
    /// <param name="mac">The MAC to check.</param>
    /// <param name="key">The key.</param>
    /// <exception cref="ArgumentException">Thrown if MAC check fails</exception>
    private void Verify(byte[] data, byte[] mac, byte[] key)
    {    
        byte[] dataMac = Sign(data, key);

        if (!CompareMacs(mac, dataMac))
            throw new ArgumentException("MAC verification failed.");
    }

    /// <summary>Verifies that the MAC of file is valid.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="mac">The MAC to check.</param>
    /// <param name="key">The key.</param>
    /// <exception cref="ArgumentException">Thrown if MAC check fails</exception>
    private void VerifyFile(string path, byte[] mac, byte[] key)
    {
        byte[] fileMac = SignFile(path, key, saltLen, macLen);

        if (!CompareMacs(mac, fileMac))
            throw new ArgumentException("MAC verification failed.");
    }

    /// <summary>
    /// Handles exceptions (prints the exception message by default).
    /// Any error handling logic could be implemented here.
    /// </summary>
    private void ErrorHandler(Exception exception)
    {
        Console.WriteLine(exception.Message);
    }

    /// <summary>
    /// Checks if the two MACs are equal, using constant time comparison.
    /// </summary>
    /// <returns>True if MACs match else false.</returns>
    private bool CompareMacs(byte[] mac1, byte[] mac2)
    {
        int result = mac1.Length ^ mac2.Length;
        for (int i = 0; i < mac1.Length && i < mac2.Length; i++)
        {
            result |= mac1[i] ^ mac2[i];
        }
        return result == 0;
    }

    /// <summary>A generator that yields file chunks.</summary>
    /// <param name="path">The file path</param>
    /// <param name="start">The starting position in file</param>
    /// <param name="end">The ending position in file (file size - end)</param>
    /// <yields>bytes</yields>
    private IEnumerable<byte[]> ReadFileChunks(string path, int start = 0, int end = 0)
    {
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
        {
            int chunkSize = 1024;
            end = (int)fs.Length - end;
            int counter = fs.Read(new byte[start], 0, start);

            while (counter < end)
            {
                int buffer = (end - counter > chunkSize) ? chunkSize : end - counter;
                byte[] data = new byte[buffer];
                counter += fs.Read(data, 0, buffer);
                yield return data;
            }
        }
    }

    /// <summary>
    /// An PBKDF2 algorithm implementation, with HMAC-SHA256.
    /// </summary>
    /// <param name="password">The password</param>
    /// <param name="salt">The salt</param>
    /// <returns>derived key</returns>
    public byte[] Pbkdf2Sha256(byte[] password, byte[] salt)
    {
        using (HMACSHA256 prf = new HMACSHA256(password))
        {
            byte[] dkey = new byte[this.keyLen * 2];
            for (int i = 0; i < this.keyLen * 2 / 32; i++)
            {
                byte[] b = BitConverter.GetBytes(i + 1);
                byte[] sb = new byte[salt.Length + 4];

                Array.Reverse(b);
                Array.Copy(salt, sb, salt.Length);
                Array.Copy(b, 0, sb, salt.Length, 4);

                byte[] u = prf.ComputeHash(sb);
                byte[] f = u;
                for (int j = 1; j < this.keyIterations; j++)
                {
                    u = prf.ComputeHash(u);
                    for (int k = 0; k < f.Length; k++)
                        f[k] ^= u[k];
                }
                Array.Copy(f, 0, dkey, i * 32, 32);
                ClearArrays(b, sb, u, f);
            }
            return dkey;
        }
    }
}

