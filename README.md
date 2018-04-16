# Encryption-Classes
AES CBC encryption in Python, PHP, C#, Java

### Description  
The main goal of this project is to provide simple, secure and compatible code (data encrypted in Python can be decrypted in PHP, and so on).  
For that reason CBC mode is used, as GCM is not yet available without the use of third party libraries.

### Languages  
 - Python (requires [pycryptodome](https://www.pycryptodome.org/en/latest/index.html))
 - PHP 
 - C# 
 - Java (256 bit keys not supported by default before Java9)
 
 ### Features  
_Encryption:_  
AES 128/256, CBC mode.  

_Key:_  
PBKDF2 with SHA1, 100000 iterations by default.  

_Authentication:_  
HMAC with SHA256.
