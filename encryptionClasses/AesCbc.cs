using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;

/// <summary>
/// Encrypts and decrypts data using AES-CBC 128 / 256.
/// </summary>
class AesCbc
{
	private int[] sizes = new int[] { 128, 256 };
	private int ivSize = 16;
	private int macSize = 32;
	private int blockSize = 16;
	private int keySize = 128;
	public byte[] key = null;
	public int rounds = 100000;
	public bool b64 = true;

	/// <exception cref="ArgumentException">
	/// Thrown when invalid size is selected.
	/// </exception>
	public AesCbc(int size = 128)
	{
		if (Array.IndexOf(sizes, size) == -1)
			throw new ArgumentException("Key size must be 128 or 256 bits.");
		keySize = size;
	}

	/// <summary>Encrypts data (string)</summary>
	/// <param name="data">The data to encrypt.</param>
	/// <param name="password">The pasword.</param>
	/// <returns>Raw bytes or base64 encoded data.</returns>
	public byte[] Encrypt(string data, string password)
	{
		return Encrypt(Encoding.UTF8.GetBytes(data), password);
	}

	/// <summary>Encrypts data (bytes)</summary>
	public byte[] Encrypt(byte[] data, string password)
	{
		byte[] iv = IVGen();
		byte[] salt = IVGen();
		byte[][] keys = KeyGen(password, salt);
		key = keys[0];
		byte[] encrypted = Transformer(data, key, iv, true);

		List<byte> new_data = new List<byte>();
		new_data.AddRange(iv);
		new_data.AddRange(encrypted);
		byte[] hmac = Sign(new_data.ToArray(), keys[1]);
		new_data.InsertRange(0, salt);
		new_data.InsertRange(new_data.Count, hmac);

		if (this.b64)
			return Encoding.ASCII.GetBytes(Convert.ToBase64String(new_data.ToArray()));
		return new_data.ToArray();
	}

	/// <summary>Decrypts data (string)</summary>
	/// <param name="data">Encrypted data (base64 encoded)</param>
	/// <param name="password">The pasword.</param>
	/// <returns>Decrypted bytes.</returns>
	public byte[] Decrypt(string data, string password)
	{
		return Decrypt(Encoding.ASCII.GetBytes(data), password);
	}

	/// <summary>Decrypts data (bytes).</summary>
	public byte[] Decrypt(byte[] data, string password)
	{
		try
		{
			if (this.b64)
				data = Convert.FromBase64String((Encoding.ASCII.GetString(data)));
			if (data.Length < ivSize + ivSize + blockSize + macSize)
				throw new Exception("Not enough data.");

			List<byte> decoded = new List<byte>(data);
			byte[] salt = decoded.GetRange(0, ivSize).ToArray();
			byte[] iv = decoded.GetRange(ivSize, ivSize).ToArray();
			byte[] encrypted = decoded.GetRange(ivSize * 2, decoded.Count - (ivSize + ivSize + macSize)).ToArray();
			byte[] hmac = decoded.GetRange(decoded.Count - macSize, macSize).ToArray();
			byte[][] keys = KeyGen(password, salt);
			key = keys[0];
			byte[] iv_encrypted = decoded.GetRange(ivSize, decoded.Count - (ivSize + macSize)).ToArray();

			if (!Verify(iv_encrypted, hmac, keys[1]))
				throw new Exception("Verification failed.");
			byte[] decrypted = Transformer(encrypted, key, iv, false);
			return decrypted;
		}
		catch (Exception e)
		{
			Console.WriteLine(e.Message);
			return null;
		}
	}

	/// <summary>Encrypts / decrypts data.</summary>
	/// <param name="data">The data</param>
	/// <param name="key">The key</param>
	/// <param name="iv">The IV</param>
	/// <param name="encrypt">Flag</param>
	/// <returns>Eecrypted / ecrypted bytes.</returns>
	private byte[] Transformer(byte[] data, byte[] key, byte[] iv, bool encrypt)
	{
		using (Aes aes = Aes.Create())
		{
			aes.KeySize = keySize;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.PKCS7;
			using (ICryptoTransform ict = (encrypt ? aes.CreateEncryptor(key, iv) : aes.CreateDecryptor(key, iv)))
			{
				using (MemoryStream mstream = new MemoryStream())
				{
					using (CryptoStream cstream = new CryptoStream(mstream, ict, CryptoStreamMode.Write))
					{
						cstream.Write(data, 0, data.Length);
					}
					return mstream.ToArray();
				}
			}
		}
	}

	/// <summary>Creates a pair of keys.</summary>
	/// <param name="password">The pasword.</param>
	/// <param name="salt">The salt.</param>
	/// <returns>keys</returns>
	private byte[][] KeyGen(string password, byte[] salt)
	{
		using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt, rounds))
		{
			byte[] aesKey = kdf.GetBytes(keySize / 8);
			byte[] macKey = kdf.GetBytes(keySize / 8);
			return new byte[][] { aesKey, macKey };
		}
	}

	/// <summary>Creates random bytes.</summary>
	/// <param name="size">The number of bytes.</param>
	/// <returns>Random bytes.</returns>
	private byte[] IVGen(int size = 16)
	{
		byte[] iv = new byte[size];
		using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
		{
			rng.GetBytes(iv);
		}
		return iv;
	}

	/// <summary>Creates HMAC signature.</summary>
	/// <param name="data">The data.</param>
	/// <param name="key">The key.</param>
	/// <returns>HMAC</returns>
	private byte[] Sign(byte[] data, byte[] key)
	{
		using (HMACSHA256 hmac = new HMACSHA256(key))
		{
			return hmac.ComputeHash(data);
		}
	}

	/// <summary>Preforms HMAC verification.</summary>
	/// <param name="data">The data.</param>
	/// <param name="mac">The HMAC.</param>
	/// <param name="key">The key.</param>
	/// <returns>True if the HMACs match else false.</returns>
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

