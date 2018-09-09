# Encryption-Classes
AES encryption in Python, PHP, C#, Java, C++, F#

### Description  
The goal of this project is to provide simple, portable and compatible code (data encrypted in Python can be decrypted in PHP, and so on). The encryption algorithm used is AES in CBC and CFB mode. Other modes are not provided mostly for compatibility reasons. For example, CTR is not implemented in .NET, ECB is not secure in most cases, and AEAD algorithms are not implemented in .NET and earlier versions of PHP and Java. The encrypted data contains the salt, iv and mac, in this format: salt[16] + iv[16] + ciphertext[n] + mac[32].   
However, this code hasn't been revised by professional cryptographers, so the use of a better established library (like libsodium for example) would be preferable.

### Languages  
 - Python - Tested versions 2.7, 3.6. Requires [PyCryptodome](https://www.pycryptodome.org/en/latest/index.html)
 - PHP - Tested versions 5.5, 7.1
 - C# - Tested versions 4, 7.2 with .NET Framework 4, 4.6
 - Java - Tested versions 7, 9. Only 128 bit keys are supported before Java 9
 - C++ - Tested versions 11, 17. Requires [CryptoPP](https://www.cryptopp.com/)
 - F# - Tested versions 3.0, 4.1 with .NET Framework 4, 4.6
 
 ### Features  
_Encryption:_  
AES 128/192/256, CBC and CFB mode.  

_Key:_  
PBKDF2 with SHA256, 20000 iterations by default.  

_Authentication:_  
HMAC with SHA256.

### Examples
_Python_
```
password = 'my super strong password'
data = 'my sensitive data'
ae = AesEncryption()
enc = ae.encrypt(data, password)

print(enc)
#b'ECiCwaGbfVPpmTdk6aBtkU2n3woz3PITSL4IltUa1rra+5N5LcN3zxe5K0F9E6h9RbswCjGFhpjCNINXEDT8fRr30+W08/m30BmOOjnkIqmOhglDQXhXDIHy4XPDhgrf'
```

_PHP_
```
$password = "my super strong password";
$data = "ECiCwaGbfVPpmTdk6aBtkU2n3woz3PITSL4IltUa1rra+5N5LcN3zxe5K0F9E6h9RbswCjGFhpjCNINXEDT8fRr30+W08/m30BmOOjnkIqmOhglDQXhXDIHy4XPDhgrf";
$ae = new AesEncryption();
$dec = $ae->decrypt($data, $password);

echo $dec;
//my sensitive data
```

_C#_
```
string password = "my super strong password";
string data = "my sensitive data";
AesEncryption ae = new AesEncryption("cfb");
byte[] enc = ae.Encrypt(data, password);

Console.WriteLine(Encoding.ASCII.GetString(enc));
//Ra75+3OYi7b7OaEOJyEDAKpJjIEevRmoBprUNDgWYz0CgMkvEltbL+lciXYKY36nnYkBdrfalG820GVnnwjJXKEhGbdHmbQMnMZ7hFGKttGU
```

_Java_
```
String password = "my super strong password";
String data = "Ra75+3OYi7b7OaEOJyEDAKpJjIEevRmoBprUNDgWYz0CgMkvEltbL+lciXYKY36nnYkBdrfalG820GVnnwjJXKEhGbdHmbQMnMZ7hFGKttGU";
AesEncryption ae = new AesEncryption("cfb");
byte[] dec = ae.decrypt(data, password);

System.out.println(new String(dec));
//my sensitive data
```

_C++_
```
std::string password = "my super strong password";
std::string data = "my sensitive data";
AesEncryption ae("cbc", 256);
CryptoPP::SecByteBlock enc = ae.encrypt(data, password);

std::cout << std::string(enc.begin(), enc.end()) << std::endl;
//CMnoj9iOZRGqhII7wLKrnvlT2C8bTOcKTe5p2uMPe8bpIkQdH/hgwcX2rxvePvG1jpAj3uCB6ZZSU5qNpw3Bv83p54SiIsRnbomVR5x2JsgdavlAUyzY0hAK/PBtCe6k
```

_F#_
```
let password = "my super strong password"
let data = "CMnoj9iOZRGqhII7wLKrnvlT2C8bTOcKTe5p2uMPe8bpIkQdH/hgwcX2rxvePvG1jpAj3uCB6ZZSU5qNpw3Bv83p54SiIsRnbomVR5x2JsgdavlAUyzY0hAK/PBtCe6k"
let ae = new AesEncryption("cbc", 256)
let d = ae.Decrypt(data, password)

printfn "%A" (Encoding.UTF8.GetString d)
#my sensitive data
```
