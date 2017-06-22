' Preconfigured Encryption Parameters
Public Module AesOptions
    ' To be sure we get the correct IV size, set the block size
    Public Property AesBlockSize As Integer = 128
    Public Property KeySize As Integer = 256

    ' AES 256 bit key encryption
    ' Preconfigured Password Key Derivation Parameters
    Public Property KeySaltSize As Integer = 128
    Public Property HashIterations As Integer = 10000
End Module
