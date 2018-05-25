using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;

/// <summary>
/// Encrypts and decrypts data using AES CBC/CFB, 128/192/256 bits.
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
	private int keySize = 128;
	private string mode = "CBC";
	private int saltLen = 16;
	private int ivLen = 16;
	private int macLen = 32;
	public byte[] key = null;
	public int rounds = 100000;
	public bool base64 = true;

	/// <exception cref="ArgumentException">
	/// Thrown when the mode is not supported or the size is invalid.
	/// </exception>
	public AesEncryption(string mode = "CBC", int size = 128)
	{
		mode = mode.ToUpper();
		if(!modes.ContainsKey(mode))
			throw new ArgumentException("Unsupported mode selected: " + mode);
		if(Array.IndexOf(sizes, size) == -1)
			throw new ArgumentException("Key size must be 128, 192 or 256 bits.");
		this.mode = mode;
		this.keySize = size;
	}

	/// <summary>Encrypts data (bytes)</summary>
	/// <param name="data">The data to encrypt.</param>
	/// <param name="password">The pasword.</param>
	/// <returns>Raw or base64 encoded bytes.</returns>
	public byte[] Encrypt(byte[] data, string password)
	{
		byte[] iv = RandomBytes(ivLen);
		byte[] salt = RandomBytes(saltLen);
		byte[][] keys = Keys(password, salt);
		key = keys[0];
		byte[] ciphertext = Transformer(data, key, iv, true);

		List<byte> newData = new List<byte>();
		newData.AddRange(iv);
		newData.AddRange(ciphertext);
		byte[] hmac = Sign(newData.ToArray(), keys[1]);
		newData.InsertRange(0, salt);
		newData.InsertRange(newData.Count, hmac);

		if (base64)
			return Encoding.ASCII.GetBytes(Convert.ToBase64String(newData.ToArray()));
		return newData.ToArray();
	}

	/// <summary>Encrypts data (string)</summary>
	public byte[] Encrypt(string data, string password)
	{
		return Encrypt(Encoding.UTF8.GetBytes(data), password);
	}

	/// <summary>Decrypts data (bytes)</summary>
	/// <param name="data">Encrypted data</param>
	/// <param name="password">The pasword.</param>
	/// <returns>Decrypted bytes (or null)</returns>
	public byte[] Decrypt(byte[] data, string password)
	{
		try
		{
			if (base64)
				data = Convert.FromBase64String((Encoding.ASCII.GetString(data)));
			int minLen = Convert.ToInt32(mode == "CBC") * (blockSize / 8);
			if (data.Length < saltLen + ivLen + minLen + macLen)
				throw new Exception("Not enough data.");

			List<byte> decoded = new List<byte>(data);
			int ctSize = decoded.Count - (saltLen + ivLen + macLen);
			byte[] salt = decoded.GetRange(0, saltLen).ToArray();
			byte[] iv = decoded.GetRange(saltLen, ivLen).ToArray();
			byte[] ciphertext = decoded.GetRange(saltLen + ivLen, ctSize).ToArray();
			byte[] hmac = decoded.GetRange(decoded.Count - macLen, macLen).ToArray();
			byte[][] keys = Keys(password, salt);
			key = keys[0];
			byte[] iv_ct = decoded.GetRange(saltLen, decoded.Count - (saltLen + macLen)).ToArray();

			if (!Verify(iv_ct, hmac, keys[1]))
				throw new Exception("MAC verification failed.");
			byte[] decrypted = Transformer(ciphertext, key, iv, false);
			return decrypted;
		}
		catch (Exception e)
		{
			Console.WriteLine(e.Message);
			return null;
		}
	}

	/// <summary>Decrypts data (string, base64 encoded).</summary>
	public byte[] Decrypt(string data, string password)
	{
		return Decrypt(Encoding.ASCII.GetBytes(data), password);
	}

	/// <summary>Creates random bytes, used for IV and salt.</summary>
	/// <param name="size">The number of bytes.</param>
	/// <returns>Random bytes.</returns>
	public byte[] RandomBytes(int size = 16)
	{
		byte[] iv = new byte[size];
		using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
		{
			rng.GetBytes(iv);
		}
		return iv;
	}

	/// <summary>Encrypts and decrypts data.</summary>
	/// <param name="data">The data</param>
	/// <param name="key">The key</param>
	/// <param name="iv">The IV</param>
	/// <param name="encrypt">Flag</param>
	/// <returns>Eecrypted / derypted data.</returns>
	private byte[] Transformer(byte[] data, byte[] key, byte[] iv, bool encrypt)
	{
		using (RijndaelManaged cipher = new RijndaelManaged())
		{
			cipher.Mode = modes[mode];
			cipher.KeySize = keySize;
			cipher.Padding = (mode == "CFB") ? PaddingMode.None : PaddingMode.PKCS7;
			cipher.FeedbackSize = (mode == "CFB") ? 8 : blockSize;
			cipher.BlockSize = blockSize;
			using (ICryptoTransform ict = encrypt ? cipher.CreateEncryptor(key, iv) : cipher.CreateDecryptor(key, iv))
			{
				return ict.TransformFinalBlock(data, 0, data.Length);
			}
		}
	}

	/// <summary>Creates a pair of keys.</summary>
	/// <param name="password">The pasword.</param>
	/// <param name="salt">The salt.</param>
	/// <returns>keys</returns>
	private byte[][] Keys(string password, byte[] salt)
	{
		using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, rounds))
		{
			byte[] aesKey = kdf.GetBytes(keySize / 8);
			byte[] macKey = kdf.GetBytes(keySize / 8);
			return new byte[][] { aesKey, macKey };
		}
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

	/// <summary>Verifies that the MAC is valid.</summary>
	/// <param name="data">The data.</param>
	/// <param name="mac">The MAC to verify.</param>
	/// <param name="key">The key.</param>
	/// <returns>True if the MACs match else false.</returns>
	private bool Verify(byte[] data, byte[] mac, byte[] key)
	{
		byte[] data_mac = Sign(data, key);
		for (int i = 0; i < data_mac.Length; i++)
		{
			if (data_mac[i] != mac[i])
				return false;
		}
		return true;
	}
}

