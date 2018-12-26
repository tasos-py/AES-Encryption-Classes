# AES Encryption Classes
AES encryption in Python, PHP, C#, Java, C++, F#, Ruby, Scala, Node.js

### Description  
The goal of this project is to provide simple, portable and compatible code (data encrypted in Python can be decrypted in PHP, and so on).  The encryption algorithm used is AES in CBC and CFB mode. Other modes are not provided mostly for compatibility reasons (.NET Framework). 
Ciphertext authenticity is verified with HMAC SHA256. 
The encrypted data contains the salt, iv and mac, in this format: salt[16] + iv[16] + ciphertext[n] + mac[32].  
Although the algorithms used are secure, this code hasn't been revised by professional cryptographers, so the use of a better established library may be preferable.  

### Languages  

 - _Python_, versions 2.7 - 3.6. Requires [PyCryptodome](https://www.pycryptodome.org/en/latest/index.html)
 - _PHP_, versions 5.5 - 7.2
 - _C#_, versions 4, 7.2, with .NET Framework 4, 4.6
 - _Java_, versions 8, 10. Only 128 bit keys are supported before Java 9
 - _C++_, versions 11, 17. Requires [CryptoPP](https://www.cryptopp.com/)
 - _F#_, versions 3.0, 4.1, with .NET Framework 4, 4.6  
 - _Ruby_, versions 1.9.2 - 2.5.1  
 - _Scala_, versions 2.12.6. Only 128 bit keys are supported before Java 9  
 - _Node.js_, versions 5.10.0 - 10.13.0

### Features  
_Encryption:_  
AES with 128/192/256 bit key, in CBC and CFB mode.  

_Keys:_  
Password-based: PBKDF2 with SHA512, 20000 iterations by default.  
Key-based: HKDF with SHA256.  

_Authentication:_  
HMAC with SHA256.

### Examples  

***Python*** _AES-128-CBC (the default) encryption, password-based._  
```
data = 'my data'
password = 'my super strong password'
aes = AesEncryption()
enc = aes.encrypt(data, password)

print(enc)
#b'jDY94lq4C84RXD4uPohrqUZvyZNJg3L+KBl7d9S6hPufBCBeUcrsYoialAR+M+nJt4rWwWvB41ScQQOrlc3OzKukLqlP0Zir/z7yaiYQwB4='
```

***PHP*** _AES-128-CBC (the default) decryption, password-based._  
```
$data = "jDY94lq4C84RXD4uPohrqUZvyZNJg3L+KBl7d9S6hPufBCBeUcrsYoialAR+M+nJt4rWwWvB41ScQQOrlc3OzKukLqlP0Zir/z7yaiYQwB4=";
$password = "my super strong password";
$aes = new AesEncryption();
$dec = $aes->decrypt($data, $password);

echo $dec;
//my data
```

***C#*** _AES-128-CFB encryption, password-based._  
```
string data = "my data";
string password = "my super strong password";
AesEncryption aes = new AesEncryption("cfb");
byte[] enc = aes.Encrypt(data, password);

Console.WriteLine(Encoding.ASCII.GetString(enc));
//NDVqzcBopFejULtlhK0vy66kFI2UiI3mEiu6XrfW0D3Qjf66cQES9PBk28Jhyc0QWk6XpBD4Fsth9EJStxXw7UgIerZ4OyM=
```

***Java*** _AES-128-CFB decryption, password-based._  
```
String data = "NDVqzcBopFejULtlhK0vy66kFI2UiI3mEiu6XrfW0D3Qjf66cQES9PBk28Jhyc0QWk6XpBD4Fsth9EJStxXw7UgIerZ4OyM=";
String password = "my super strong password";
AesEncryption aes = new AesEncryption("cfb");
byte[] dec = aes.decrypt(data, password);

System.out.println(new String(dec));
//my data
```

***C++*** _AES-256-CBC encryption, password-based._  
```
std::string data = "my data";
std::string password = "my super strong password";
AesEncryption aes("cbc", 256);
CryptoPP::SecByteBlock enc = aes.encrypt(data, password);

std::cout << std::string(enc.begin(), enc.end()) << std::endl;
//xDl8P0fKwL2pgi6WQPvd5iLUjT9IuBiZKBrH2DXdPT/wwKiQILnn/daaCYvu7cNv9894ap3HzgmgaOcIzT1TOWwUISAmMGqqOosLPl5Qu6o=
```

***F#*** _AES-256-CBC decryption, password-based._  
```
let data = "xDl8P0fKwL2pgi6WQPvd5iLUjT9IuBiZKBrH2DXdPT/wwKiQILnn/daaCYvu7cNv9894ap3HzgmgaOcIzT1TOWwUISAmMGqqOosLPl5Qu6o="
let password = "my super strong password"
let aes = new AesEncryption("cbc", 256)
let dec = aes.Decrypt(data, password)

printfn "%A" (Encoding.UTF8.GetString dec)
#my data
```

***Ruby*** _AES-128-CBC encryption, key-based._  
```
aes = AesEncryption.new()
key = aes.random_key_gen()
enc = aes.encrypt('my data')

puts key
#kC4y8+6dFS8uhPmIU0d+KjYT1nc7gGXiphT0p9Ax0as=
puts enc
#NXOjXel/xtIDgb+LMnIseCSQB6Mv/LRfMP1bMiqtCGRGd/t6uR0zSV8zDShmZhY4z4xFSX/hxGwGh/jQhvMA53qBnEyhquf3b7PEhdHvMKs=
```

***Scala***  _AES-128-CBC decryption, key-based._  
```
val data = "NXOjXel/xtIDgb+LMnIseCSQB6Mv/LRfMP1bMiqtCGRGd/t6uR0zSV8zDShmZhY4z4xFSX/hxGwGh/jQhvMA53qBnEyhquf3b7PEhdHvMKs="
val aes = new AesEncryption()
aes.setMasterKey("kC4y8+6dFS8uhPmIU0d+KjYT1nc7gGXiphT0p9Ax0as=")
val dec = aes.decrypt(data)

println(new String(dec))
//my data
```

**Node.js*** _AES-128-CBC, file encryption and decryption, key-based._  
```
const aes = new AesEncryption();
const key = aes.randomKeyGen();

var path = '/path/to/file.txt';
var encPath = aes.encryptFile(path);
var decPath = aes.decryptFile(encPath);
```

