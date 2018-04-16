# Encryption-Classes
AES CBC encryption in Python, PHP, C#, Java

### Description  
The main goal of this project is to provide secure and compatible code (messages encrypted in Python can be decrypted in PHP, and so on).  
For that reason CBC mode is used, as GCM is not yet available without the use of third party libraries.

### Languages  
 - Python (requires [pycryptodome](https://www.pycryptodome.org/en/latest/index.html))
 - PHP 
 - C# 
 - Java
 
 ### Features  
 Encryption: AES 128/256, CBC mode.  
 Key: PBKDF2 with SHA1, 100000 iterations by default.  
 Authentication: HMAC with SHA256.
