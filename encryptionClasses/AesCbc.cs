using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;

/// <summary>
/// Encrypts and decrypts data using AES-CBC 128 - 256.
/// </summary>
class AesCbc
{
	private int[] sizes = new int[] { 128, 256 };
	private int ivSize = 16;
	private int macSize = 32;
	private int blockSize = 16;
	private int keySize;
	public int rounds;
	public bool b64;

	/// <exception cref="ArgumentException">
	/// Thrown when invalid size is selected.
	/// </exception>
	public AesCbc(int size = 128)
	{
		if (size != 128 && size != 256)
			throw new ArgumentException("Size must be 128 or 256 bits.");
		keySize = size;
		rounds = 1000;
		b64 = true;
	}

	/// <summary>Encrypts data (string)</summary>
	/// <param name="data">The data to encrypt.</param>
	/// <param name="password">The pasword.</param>
	/// <returns>Raw bytes or base64 encoded data.</returns>
	public byte[] Encrypt(string data, string password)
	{
		byte[] data_bytes = Encoding.UTF8.GetBytes(data);
		return Encrypt(data_bytes, password);
	}

	/// <summary>Encrypts data (bytes)</summary>
	public byte[] Encrypt(byte[] data, string password)
	{
		byte[] iv = IVGen();
		byte[] salt = IVGen();
		byte[][] keys = KeyGen(password, salt);
		byte[] encrypted = Transformer(data, keys[0], iv, true);

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
		byte[] bytes = Encoding.ASCII.GetBytes(data);
		return Decrypt(bytes, password);
	}

	/// <summary>Decrypts data (bytes).</summary>
	public byte[] Decrypt(byte[] data, string password)
	{
		try
		{
			if (this.b64)
				data = Convert.FromBase64String((Encoding.ASCII.GetString(data)));
			if (data.Length < ivSize + ivSize + blockSize + macSize)
				throw new Exception("Not enough data!");

			List<byte> decoded = new List<byte>(data);
			byte[] salt = decoded.GetRange(0, ivSize).ToArray();
			byte[] iv = decoded.GetRange(ivSize, ivSize).ToArray();
			byte[] encrypted = decoded.GetRange(ivSize + ivSize, decoded.Count - (ivSize + ivSize + macSize)).ToArray();
			byte[] hmac = decoded.GetRange(decoded.Count - macSize, macSize).ToArray();
			if (encrypted.Length % blockSize != 0)
				throw new Exception("Ciphertext must be a multiple of " + blockSize + " bytes in length.");

			byte[][] keys = KeyGen(password, salt);
			byte[] iv_encrypted = decoded.GetRange(ivSize, decoded.Count - (ivSize + macSize)).ToArray();

			if (!Verify(iv_encrypted, hmac, keys[1]))
				throw new Exception("Verification failed.");

			byte[] decrypted = Transformer(encrypted, keys[0], iv, false);
			return decrypted;
		}
		catch (Exception e)
		{
			Console.WriteLine(e.Message);
			return new byte[0];
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

	/// <summary>Creates random 0-9a-zA-Z strings.</summary>
	/// <param name="size">The string size.</param>
	/// <returns>Random string</returns>
	public string CreatePassword(int size = 24)
	{
		byte[] randomBytes = IVGen(size);
		string password = Convert.ToBase64String(randomBytes).Substring(0, size);
		return password;
	}
}