# Encryption-Classes
AES encryption in Python, PHP, C#, Java

### Description  
The main goal of this project is to provide simple, secure and compatible code (data encrypted in Python can be decrypted in PHP, and so on). For that reason AES in CBC and CFB mode is used, as CTR is not implemented in the builtin Cryptography namespace in C#, GCM is not yet widely available, and ECB is not secure in most cases.

### Languages  
 - Python (requires [pycryptodome](https://www.pycryptodome.org/en/latest/index.html))
 - PHP 
 - C# 
 - Java (256 bit keys not supported by default before Java9)
 
 ### Features  
_Encryption:_  
AES 128/192/256, CBC and CFB mode.  

_Key:_  
PBKDF2 with SHA1, 100000 iterations by default.  

_Authentication:_  
HMAC with SHA256.
