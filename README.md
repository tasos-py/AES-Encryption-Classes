# Encryption-Classes
AES encryption in Python, PHP, C#, Java, C++, F#

### Description  
The main goal of this project is to provide simple, secure and compatible code (data encrypted in Python can be decrypted in PHP, and so on). For that reason AES in CBC and CFB mode is used, as CTR is not implemented in C#, GCM and EAX are not implemented in C# and earlier versions of PHP and Java, and ECB is not secure in most cases.  
However, this code hasn't been thoroughly tested or revised by professional cryptographers, so the use of a better established library (like libsodium for example) would be preferable.

### Languages  
 - Python - Tested versions 2.7, 3.6. Requires [pycryptodome](https://www.pycryptodome.org/en/latest/index.html)
 - PHP - Tested versions 5.5, 7.1
 - C# - Tested versions 4, 7.2
 - Java - Tested versions 7, 9. Only 128 bit keys are supported before Java 9
 - C++ - Tested versions 11, 17. Requires [CryptoPP](https://www.cryptopp.com/)
 - F# - Tested versions 4.1. Only CBC mode is supported
 
 ### Features  
_Encryption:_  
AES 128/192/256, CBC and CFB mode.  

_Key:_  
PBKDF2 with SHA256, 20000 iterations by default.  

_Authentication:_  
HMAC with SHA256.
