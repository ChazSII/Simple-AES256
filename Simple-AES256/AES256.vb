Imports System.IO
Imports System.Security.Cryptography

Public Class AES256
    Implements IDisposable

    Private Property KeyDerivationFunction As Rfc2898DeriveBytes
    Private Property AesManaged As AesManaged

    Private ReadOnly Property KeyBytes As Byte() = Nothing
    Private ReadOnly Property IvBytes As Byte() = Nothing
    Private ReadOnly Property SaltBytes As Byte() = Nothing

    Public Sub New(key As String,
                   Optional keySize As Integer = 256,
                   Optional keySaltSize As Integer = 128,
                   Optional hashIterations As Integer = 10000,
                   Optional aesBlockSize As Integer = 128)

        AesOptions.KeySize = keySize
        AesOptions.KeySaltSize = keySaltSize
        AesOptions.HashIterations = hashIterations
        AesOptions.AesBlockSize = aesBlockSize

        AesManaged = New AesManaged() With {.KeySize = keySize, .BlockSize = aesBlockSize}
        KeyDerivationFunction = New Rfc2898DeriveBytes(key, keySaltSize \ 8, hashIterations)
    End Sub

    Public Sub New(key As String, iv As Byte(), salt As Byte(),
                   Optional keySize As Integer = 256,
                   Optional keySaltSize As Integer = 128,
                   Optional hashIterations As Integer = 10000,
                   Optional aesBlockSize As Integer = 128)

        AesOptions.KeySize = keySize
        AesOptions.KeySaltSize = keySaltSize
        AesOptions.HashIterations = hashIterations
        AesOptions.AesBlockSize = aesBlockSize

        _IvBytes = iv
        AesManaged = New AesManaged() With {.KeySize = keySize, .BlockSize = aesBlockSize}
        KeyDerivationFunction = New Rfc2898DeriveBytes(key, salt, hashIterations)
    End Sub


    Public Function GetKeyBytes() As Byte()
        If KeyBytes Is Nothing Then
            _KeyBytes = KeyDerivationFunction.GetBytes(KeySize \ 8)
        End If

        Return KeyBytes
    End Function

    Public Function GetSaltBytes() As Byte()
        If SaltBytes Is Nothing Then
            _SaltBytes = KeyDerivationFunction.Salt
        End If

        Return SaltBytes
    End Function

    Public Function GetInitializationVector() As Byte()
        If IvBytes Is Nothing Then
            AesManaged.GenerateIV()
            _IvBytes = AesManaged.IV
        End If

        Return IvBytes
    End Function


    Public Function GetCipherBytes(plainText As String) As Byte()
        Dim saltBytes As Byte() = GetSaltBytes()
        Dim keyBytes As Byte() = GetKeyBytes()
        Dim ivBytes As Byte() = GetInitializationVector()

        ' Create an encryptor to perform the stream transform.
        ' Create the streams used for encryption.
        Using encryptor As ICryptoTransform = AesManaged.CreateEncryptor(keyBytes, ivBytes)
            Using cipherStream As New MemoryStream()
                Using cryptoStream As New CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write)
                    Using streamWriter As New StreamWriter(cryptoStream)
                        ' Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                        streamWriter.Write(plainText)
                    End Using
                End Using

                Return cipherStream.ToArray()
            End Using
        End Using
    End Function

    Public Function GetCipherBase64(plainText As String) As String
        Return Convert.ToBase64String(GetCipherBytes(plainText))
    End Function


    Public Function GetPlainBytes(cipherText As String) As Byte()
        Return Text.Encoding.UTF8.GetBytes(GetPlainText(cipherText))
    End Function

    Public Function GetPlainText(cipherText As String) As String
        Dim saltBytes As Byte() = GetSaltBytes()
        Dim keyBytes As Byte() = GetKeyBytes()
        Dim ivBytes As Byte() = GetInitializationVector()
        Dim ciphertextBytes As Byte() = Convert.FromBase64String(cipherText)

        ' Create a decrytor to perform the stream transform.
        ' Create the streams used for decryption.
        Using decryptor As ICryptoTransform = AesManaged.CreateDecryptor(keyBytes, ivBytes)
            Using cipherStream As New MemoryStream(ciphertextBytes)
                Using cryptoStream As New CryptoStream(cipherStream, decryptor, CryptoStreamMode.Read)
                    Using streamReader As New StreamReader(cryptoStream)
                        ' Return the decrypted bytes from the decrypting stream.
                        Return streamReader.ReadToEnd()
                    End Using
                End Using
            End Using
        End Using
    End Function


#Region "IDisposable Support"
    Private disposedValue As Boolean ' To detect redundant calls

    ' IDisposable
    Protected Overridable Sub Dispose(disposing As Boolean)
        If Not disposedValue Then
            If disposing Then
                ' TODO: dispose managed state (managed objects).

                KeyDerivationFunction.Dispose()
                AesManaged.Dispose()
            End If

            ' TODO: free unmanaged resources (unmanaged objects) and override Finalize() below.
            ' TODO: set large fields to null.

            _SaltBytes = Nothing
            _IvBytes = Nothing
            _KeyBytes = Nothing
        End If
        disposedValue = True
    End Sub

    ' TODO: override Finalize() only if Dispose(disposing As Boolean) above has code to free unmanaged resources.
    'Protected Overrides Sub Finalize()
    '    ' Do not change this code.  Put cleanup code in Dispose(disposing As Boolean) above.
    '    Dispose(False)
    '    MyBase.Finalize()
    'End Sub

    ' This code added by Visual Basic to correctly implement the disposable pattern.
    Public Sub Dispose() Implements IDisposable.Dispose
        ' Do not change this code.  Put cleanup code in Dispose(disposing As Boolean) above.
        Dispose(True)
        ' TODO: uncomment the following line if Finalize() is overridden above.
        ' GC.SuppressFinalize(Me)
    End Sub
#End Region

#Region "Legacy Shared Functions"
    <Obsolete("Kept for backwards compatability. Please use SimpleCipher or an instance of AES256.")>
    Public Shared Function Encrypt(plainText As String, key As String) As String
        Return SimpleCipher.Encrypt(plainText, key)
    End Function

    <Obsolete("Kept for backwards compatability. Please use SimpleCipher or an instance of AES256.")>
    Public Shared Function Decrypt(ciphertext As String, key As String) As String
        Return SimpleCipher.Decrypt(ciphertext, key)
    End Function
#End Region

End Class
