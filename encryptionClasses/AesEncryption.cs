using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;

/// <summary>
/// Encrypts - decrypts data and files using AES CBC/CFB, 128/192/256 bits.
/// </summary>
class AesEncryption
{
	private Dictionary<string, CipherMode> modes = new Dictionary<string, CipherMode>()
	{
		{ "CBC", CipherMode.CBC },
		{ "CFB", CipherMode.CFB }
	};
	private int[] sizes = new int[] { 128, 192, 256 };
	private int blockSize = 128;
	private int size = 128;
	private string mode = "CBC";
	private int saltLen = 16;
	private int ivLen = 16;
	private int macLen = 32;
	private int keyLen = 16;
	public int keyIterations = 20000;
	public bool base64 = true;

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

	/// <summary>Encrypts data (raw bytes)</summary>
	/// <param name="data">The data.</param>
	/// <param name="password">The pasword to use.</param>
	/// <returns>Raw or base64 encoded bytes.</returns>
	public byte[] Encrypt(byte[] data, string password)
	{
		byte[] iv = RandomBytes(ivLen);
		byte[] salt = RandomBytes(saltLen);
		byte[][] keys = Keys(password, salt);
		byte[] aesKey = keys[0];
		byte[] macKey = keys[1];

		RijndaelManaged cipher = Cipher();
		byte[] ciphertext;
		using (ICryptoTransform ict = cipher.CreateEncryptor(aesKey, iv))
		{
			ciphertext = ict.TransformFinalBlock(data, 0, data.Length);
		}
		cipher.Dispose();

		List<byte> sicm = new List<byte>();
		sicm.AddRange(iv);
		sicm.AddRange(ciphertext);

		byte[] mac = Sign(sicm.ToArray(), macKey);
		sicm.InsertRange(0, salt);
		sicm.AddRange(mac);

		if (base64)
			return Encoding.ASCII.GetBytes(Convert.ToBase64String(sicm.ToArray()));
		return sicm.ToArray();
	}

	/// <summary>Encrypts data (string)</summary>
	public byte[] Encrypt(string data, string password)
	{
		return Encrypt(Encoding.UTF8.GetBytes(data), password);
	}

	/// <summary>Decrypts data (bytes)</summary>
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
			byte[] hmac = sicm.GetRange(sicm.Count - macLen, macLen).ToArray();

			byte[][] keys = Keys(password, salt);
			byte[] aesKey = keys[0];
			byte[] macKey = keys[1];

			byte[] iv_ct = sicm.GetRange(saltLen, sicm.Count - (saltLen + macLen)).ToArray();
			if (!Verify(iv_ct, hmac, macKey))
				throw new ArgumentException("MAC verification failed.");

			byte[] decrypted;
			RijndaelManaged cipher = Cipher();

			using (ICryptoTransform ict = cipher.CreateDecryptor(aesKey, iv))
			{
				decrypted = ict.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
			}
			cipher.Dispose();
			return decrypted;
		}
		catch (FormatException e)
		{
			Console.WriteLine(e.Message);
		}
		catch (ArgumentException e)
		{
			Console.WriteLine(e.Message);
		}
		return null;
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
		byte[] aesKey = keys[0];
		byte[] macKey = keys[1];
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
			Console.WriteLine(e);
		}
		catch (UnauthorizedAccessException e)
		{
			Console.WriteLine(e);
		}
		return null;
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
			byte[] aesKey = keys[0];
			byte[] macKey = keys[1];

			if (!VerifyFile(path, mac, macKey))
				throw new ArgumentException("MAC verification failed.");

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
			Console.WriteLine(e);
		}
		catch (UnauthorizedAccessException e)
		{
			Console.WriteLine(e);
		}
		catch (ArgumentException e)
		{
			Console.WriteLine(e);
		}
		return null;
	}

	/// <summary>Creates a pair of keys (one for AES, the other for MAC).</summary>
	/// <param name="password">The pasword.</param>
	/// <param name="salt">The salt.</param>
	/// <returns>keys</returns>
	private byte[][] Keys(string password, byte[] salt)
	{
		using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, keyIterations))
		{
			byte[] aesKey = kdf.GetBytes(keyLen);
			byte[] macKey = kdf.GetBytes(keyLen);
			return new byte[][] { aesKey, macKey };
		}
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
	/// RijndaelManaged is used because AesManaged doesn't accept unpadded blocks.
	/// </summary>
	private RijndaelManaged Cipher()
	{
		RijndaelManaged cipher = new RijndaelManaged
		{
			Mode = modes[mode],
			KeySize = size,
			Padding = (mode == "CFB") ? PaddingMode.None : PaddingMode.PKCS7,
			FeedbackSize = (mode == "CFB") ? 8 : blockSize,
			BlockSize = blockSize,
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
	/// <param name="mac">The MAC to verify.</param>
	/// <param name="key">The key.</param>
	/// <returns>True if the MAC is valid else false.</returns>
	private bool Verify(byte[] data, byte[] mac, byte[] key)
	{
		byte[] dataMac = Sign(data, key);
		return CompareMacs(mac, dataMac);
	}

	/// <summary>Verifies that the MAC of file is valid.</summary>
	/// <param name="path">The file path.</param>
	/// <param name="mac">The MAC to verify.</param>
	/// <param name="key">The key.</param>
	/// <returns>True if the MAC is valid else false.</returns>
	private bool VerifyFile(string path, byte[] mac, byte[] key)
	{
		byte[] fileMac = SignFile(path, key, saltLen, macLen);
		return CompareMacs(mac, fileMac);
	}

	/// <summary>
	/// Checks if the two MACs are equal, using constant time comparisson.
	/// </summary>
	/// <returns>True if MACs match else false.</returns>
	private bool CompareMacs(byte[] mac1, byte[] mac2)
	{
		if (mac1.Length == mac2.Length)
		{
			int result = 0;
			for (int i = 0; i < mac1.Length; i++)
			{
				result |= mac1[i] ^ mac2[i];
			}
			return result == 0;
		}
		return false;
	}

	/// <summary>
	/// A generator that yields file chunks. 
	/// Chunk size should be a multiple of 16 in CBC mode.
	/// </summary>
	/// <param name="path">The file path</param>
	/// <param name="start">The starting position in file</param>
	/// <param name="end">The ending position in file (file size - end)</param>
	/// <yields>bytes</yields>
	public static IEnumerable<byte[]> ReadFileChunks(string path, int start = 0, int end = 0)
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
}
