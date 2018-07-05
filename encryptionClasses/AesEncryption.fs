open System.Security.Cryptography
open System.Text
open System.IO
open System
open System.Text.RegularExpressions


/// Encrypts - decrypts data and files using AES CBC 128/192/256 bits.
/// Throws ArgumentException when mode is not supported or size is invalid.
type AesEncryption(?mode:string, ?size:int) = 
    let mode = (defaultArg mode "CBC").ToUpper()
    let keyLen = (defaultArg size 128) / 8
    let size = defaultArg size 128

    let modes = Map.empty.Add("CBC", CipherMode.CBC)
    let sizes = [| 128; 192; 256 |]
    let saltLen = 16
    let ivLen = 16
    let macLen = 32

    do
        if not (List.contains size sizes) then
            raise (ArgumentException "Invalid key size.")
        if not (modes.ContainsKey mode) then
            raise (ArgumentException (mode + " mode is not supported."))
    
    member val keyIterations = 20000 with get, set
    member val base64 = true with get, set

    /// Encrypts data (raw bytes) 
    member this.Encrypt(data:byte[], password:string):byte[] = 
        let iv = this.RandomBytes ivLen
        let salt = this.RandomBytes saltLen
        let aesKey, macKey = this.Keys (password, salt)

        use cipher = this.Cipher()
        use ict = cipher.CreateEncryptor(aesKey, iv)
        let ciphertext = ict.TransformFinalBlock(data, 0, data.Length)

        let iv_ct = Array.append iv ciphertext
        let mac = this.Sign(iv_ct, macKey)
        let encrypted = Array.append (Array.append salt iv_ct) mac

        if this.base64 then
            Encoding.ASCII.GetBytes (Convert.ToBase64String encrypted)
        else
            encrypted
    
    /// Encrypts data (string) 
    member this.Encrypt(data:string, password:string):byte[] = 
        this.Encrypt (Encoding.UTF8.GetBytes (data), password)
    
    /// Decrypts data (bytes) 
    member this.Decrypt(data:byte[], password:string):byte[] = 
        try
            let mutable data = data
            if this.base64 then 
                data <- Convert.FromBase64String(Encoding.ASCII.GetString data)
            
            let salt = data.[0..saltLen - 1]
            let iv = data.[saltLen..saltLen + ivLen - 1]
            let ciphertext = data.[saltLen + ivLen..data.Length - macLen - 1]
            let mac = data.[data.Length - macLen..data.Length - 1]

            let aesKey, macKey = this.Keys (password, salt)
            let iv_ct = Array.append iv ciphertext
            this.Verify(iv_ct, mac, macKey)

            use cipher = this.Cipher()
            use ict = cipher.CreateDecryptor(aesKey, iv)
            let cleartext = ict.TransformFinalBlock(ciphertext, 0, ciphertext.Length)
            cleartext
        with 
            | :? ArgumentException as e -> this.ErrorHandler e; Array.zeroCreate<byte> 0
            | :? IndexOutOfRangeException as e -> this.ErrorHandler e; Array.zeroCreate<byte> 0
    
    /// Decrypts data (string - base64 encoded bytes)
    member this.Decrypt(data:string, password:string):byte[] = 
        this.Decrypt (Encoding.UTF8.GetBytes (data), password)
    
    /// Encrypts files using the supplied password. 
    /// Doesn't modify the original file, but creates an encrypted copy.
    member this.EncryptFile(path:string, password:string):string = 
        let newPath = path + ".enc"
        let iv = this.RandomBytes ivLen
        let salt = this.RandomBytes saltLen
        let aesKey, macKey = this.Keys (password, salt)

        try
            use fs = new FileStream(newPath, FileMode.Create, FileAccess.Write) 
            fs.Write(salt, 0, saltLen)
            fs.Write(iv, 0, ivLen)

            use cipher = this.Cipher()
            use ict = cipher.CreateEncryptor(aesKey, iv)
            use hmac = new HMACSHA256(macKey)
            hmac.TransformBlock(iv, 0, iv.Length, null, 0) |> ignore

            let fileSize = (int)(new FileInfo(path)).Length
            let mutable counter = 0

            for data in this.ReadFileChunks(path) do
                counter <- counter + data.Length
                let mutable ciphertext = Array.create data.Length 0uy

                if counter = fileSize then
                    ciphertext <- ict.TransformFinalBlock(data, 0, data.Length)
                    hmac.TransformFinalBlock(ciphertext, 0, ciphertext.Length) |> ignore
                else
                    ict.TransformBlock(data, 0, data.Length, ciphertext, 0) |> ignore
                    hmac.TransformBlock(ciphertext, 0, ciphertext.Length, null, 0) |> ignore
                fs.Write(ciphertext, 0, ciphertext.Length)
            
            let mac = hmac.Hash
            fs.Write(mac, 0, mac.Length)
            newPath
        with 
            | :? UnauthorizedAccessException as e -> this.ErrorHandler e; ""
            | :? FileNotFoundException as e -> this.ErrorHandler e; ""
    
    /// Decrypts files using the supplied password. 
    /// Doesn't modify the encrypted file, but creates a decrypted copy.
    member this.DecryptFile(path:string, password:string):string = 
        let newPath = Regex.Replace(path, ".enc$", ".dec")
        let salt = Array.create saltLen 0uy
        let iv = Array.create ivLen 0uy
        let mac = Array.create macLen 0uy

        try
            let fileSize = (int)(new FileInfo(path)).Length
            use fs = new FileStream(path, FileMode.Open, FileAccess.Read)

            fs.Read(salt, 0, saltLen) |> ignore
            fs.Read(iv, 0, ivLen) |> ignore
            fs.Seek((int64)(fileSize - macLen), SeekOrigin.Begin) |> ignore
            fs.Read(mac, 0, macLen) |> ignore

            let aesKey, macKey = this.Keys (password, salt)
            this.VerifyFile(path, mac, macKey)
        
            use fs = new FileStream(newPath, FileMode.Create, FileAccess.Write)
            use cipher = this.Cipher()
            use ict = cipher.CreateDecryptor(aesKey, iv)
            let mutable counter = 0

            for data in this.ReadFileChunks(path, saltLen + ivLen, macLen) do
                counter <- counter + data.Length;
                let mutable cleartext = Array.create data.Length 0uy
                let mutable size = 0

                if (counter = fileSize - saltLen - ivLen - macLen) then
                    cleartext <- ict.TransformFinalBlock(data, 0, data.Length)
                    size <- cleartext.Length
                else
                    size <- ict.TransformBlock(data, 0, data.Length, cleartext, 0)
                fs.Write(cleartext, 0, size)
            newPath
        with 
            | :? UnauthorizedAccessException as e -> this.ErrorHandler e; ""
            | :? FileNotFoundException as e -> this.ErrorHandler e; ""
            | :? ArgumentException as e -> this.ErrorHandler e; ""
    
    /// Creates a pair of keys. 
    /// One key is used for encryption, the other for authentication.
    member private this.Keys(password:string, salt:byte[]) = 
        let hash = HashAlgorithmName.SHA256
        use kdf = new Rfc2898DeriveBytes(password, salt, this.keyIterations, hash)
        let aesKey = kdf.GetBytes keyLen
        let macKey = kdf.GetBytes keyLen
        aesKey, macKey
    
    /// Creates random bytes (used for IV and salt).
    member private this.RandomBytes(size:int) =
        let rb = Array.create size 0uy
        use rng = new RNGCryptoServiceProvider()
        rng.GetBytes rb
        rb
    
    /// Creates an AesManaged object for encryption.
    member private this.Cipher():AesManaged =
        let am =  new AesManaged()
        am.Mode <- modes.[mode]
        am.Padding <- PaddingMode.PKCS7
        am.KeySize <- size
        am
    
    /// Creates MAC signature.
    member private this.Sign(data:byte[], key:byte[]) = 
        use hmac = new HMACSHA256(key)
        hmac.ComputeHash data
    
    /// Creates a MAC signature of the file.
    member private this.SignFile(path:string, key:byte[], ?fstart:int, ?fend:int) = 
        use hmac = new HMACSHA256(key)
        for data in this.ReadFileChunks(path, (defaultArg fstart 0), (defaultArg fend 0)) do 
            hmac.TransformBlock(data, 0, data.Length, null, 0) |> ignore
        hmac.TransformFinalBlock((Array.create 0 0uy), 0, 0) |> ignore
        hmac.Hash
    
    /// Verifies that the MAC is valid.
    /// Throws ArgumentException if MAC is not valid.
    member private this.Verify(data, mac, key) = 
        let dataMac = this.Sign(data, key)
        if not (this.CompareMacs (mac, dataMac)) then
            raise (ArgumentException "MAC verification failed")
    
    /// Verifies that the MAC of file is valid.
    /// Throws ArgumentException if MAC is not valid.
    member private this.VerifyFile(path:string, mac:byte[], key:byte[]) = 
        let fileMac = this.SignFile(path, key, saltLen, macLen)
        if not (this.CompareMacs(mac, fileMac)) then
             raise (ArgumentException "MAC verification failed")
    
    /// Handles exceptions (prints the exception message by default).  
    member private this.ErrorHandler(e:Exception) =
        printfn "%s" e.Message
    
    /// Checks if the two MACs are equal, 
    /// using constant time comparison algorithm.
    member private this.CompareMacs(mac1:byte[], mac2:byte[]) =
        let mutable result = mac1.Length ^^^ mac2.Length
        for i in 0 .. (min mac1.Length mac2.Length) - 1 do
            result <- result ||| ((int)mac1.[i] ^^^ (int)mac2.[i])
        result = 0
     
    /// A generator that yields file chunks. 
    /// Chunk size should be a multiple of 16.
    member private this.ReadFileChunks(path:string, ?fstart:int, ?fend:int):seq<byte[]> = 
        let chunkSize = 1024
        let fs = new FileStream(path, FileMode.Open, FileAccess.Read)
        let fstart = defaultArg fstart 0
        let fend = (int)fs.Length - (defaultArg fend 0)
        let mutable counter = fs.Read(Array.create fstart 0uy, 0, fstart)

        seq { while counter < fend do
                let buffer = if fend - counter > chunkSize then chunkSize else fend - counter
                let data = Array.create buffer 0uy
                counter <- counter + fs.Read(data, 0, buffer)
                yield data 
        }



