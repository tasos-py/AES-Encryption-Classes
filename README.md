# Encryption-Classes
AES encryption in Python, PHP, C#, Java, C++, F#

### Description  
The goal of this project is to provide simple, portable and compatible code (data encrypted in Python can be decrypted in PHP, and so on). The encryption algorithm used is AES in CBC and CFB mode. Other modes are not provided mostly for compatibility reasons. For example, CTR is not implemented in .NET, ECB is not secure in most cases, and AEAD algorithms are not implemented in .NET and earlier versions of PHP and Java. The encrypted data contains the salt, iv and mac, in this format: salt[16] + iv[16] + ciphertext[n] + mac[32].   
However, this code hasn't been revised by professional cryptographers, so the use of a better established library (like libsodium for example) would be preferable.

### Languages  
 - _Python_, versions 2.7, 3.6, requires [PyCryptodome](https://www.pycryptodome.org/en/latest/index.html)
 - _PHP_, versions 5.5, 7.1
 - _C#_, versions 4, 7.2, with .NET Framework 4, 4.6
 - _Java_, versions 7, 9. Only 128 bit keys are supported before Java 9
 - _C++_, versions 11, 17, requires [CryptoPP](https://www.cryptopp.com/)
 - _F#_, versions 3.0, 4.1, with .NET Framework 4, 4.6
 
 ### Features  
_Encryption:_  
AES with 128/192/256 bit key, in CBC and CFB mode.  

_Key:_  
PBKDF2 with SHA256, 20000 iterations by default.  

_Authentication:_  
HMAC with SHA256.

### Examples
_Python_
```
password = 'my super strong password'
data = 'my data'
ae = AesEncryption()
enc = ae.encrypt(data, password)

print(enc)
#b'f2ZGoGCburJe19m9V7i4Gl9fswV3gDSU+g4nrG2aPXPZXh2kozprYcrB80+nTBlpo17FaOEwMlVfThCtdvN/CtGc5mLAmvhuxKNSAg2pBow='
```

_PHP_
```
$password = "my super strong password";
$data = "f2ZGoGCburJe19m9V7i4Gl9fswV3gDSU+g4nrG2aPXPZXh2kozprYcrB80+nTBlpo17FaOEwMlVfThCtdvN/CtGc5mLAmvhuxKNSAg2pBow=";
$ae = new AesEncryption();
$dec = $ae->decrypt($data, $password);

echo $dec;
//my data
```

_C#_
```
string password = "my super strong password";
string data = "my data";
AesEncryption ae = new AesEncryption("cfb");
byte[] enc = ae.Encrypt(data, password);

Console.WriteLine(Encoding.ASCII.GetString(enc));
//FEBHssTudSBUJIHA+9M/cEpY+vjGRDWldgmDcsps4jmmftzMsTvUCRn7zoFSB+udZtOQLNPZKSu7YxdPE11cHGIiihcEMvQ=
```

_Java_
```
String password = "my super strong password";
String data = "FEBHssTudSBUJIHA+9M/cEpY+vjGRDWldgmDcsps4jmmftzMsTvUCRn7zoFSB+udZtOQLNPZKSu7YxdPE11cHGIiihcEMvQ=";
AesEncryption ae = new AesEncryption("cfb");
byte[] dec = ae.decrypt(data, password);

System.out.println(new String(dec));
//my data
```

_C++_
```
std::string password = "my super strong password";
std::string data = "my data";
AesEncryption ae("cbc", 256);
CryptoPP::SecByteBlock enc = ae.encrypt(data, password);

std::cout << std::string(enc.begin(), enc.end()) << std::endl;
//wyNf1cim1JIdj+0pRBEuiJcXMd/YCWlv6eHM0oKi0NZPm3BBcHGnWwDN5K5wCP28TWqL885woQOlXOlLrj67O+ZrbS0O38ky/pf0/vNyAo4=
```

_F#_
```
let password = "my super strong password"
let data = "wyNf1cim1JIdj+0pRBEuiJcXMd/YCWlv6eHM0oKi0NZPm3BBcHGnWwDN5K5wCP28TWqL885woQOlXOlLrj67O+ZrbS0O38ky/pf0/vNyAo4="
let ae = new AesEncryption("cbc", 256)
let d = ae.Decrypt(data, password)

printfn "%A" (Encoding.UTF8.GetString d)
#my data
```
