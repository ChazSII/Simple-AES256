''==================================================================''
''                                                                  ''
''      Forked and modified from jbubriski's Encryptamajig          ''
''          - https://github.com/jbubriski/Encryptamajig            ''
''                                                                  ''
''  Translated from C# to VB via Snippet Converter                  ''
''  - http://codeconverter.sharpdevelop.net/SnippetConverter.aspx   ''
''                                                                  ''
''==================================================================''

Imports System.IO
Imports System.Linq
Imports System.Security.Cryptography



''' <summary>
''' A simple wrapper to the AesManaged class and the AES algorithm.
''' Uses 256 bit key, 128 bit psuedo-random salt and a 16 bit
''' psuedo-randomly generated Initialization Vector 
''' </summary>
Public Class AES256
    ' Preconfigured Encryption Parameters
    Private Shared ReadOnly BlockBitSize As Integer = 128
    ' To be sure we get the correct IV size, set the block size
    Private Shared ReadOnly KeyBitSize As Integer = 256
    ' AES 256 bit key encryption
    ' Preconfigured Password Key Derivation Parameters
    Private Shared ReadOnly SaltBitSize As Integer = 128
    Private Shared ReadOnly Iterations As Integer = 10000

    ''' <summary>
    ''' Encrypts the plainText input using the given Key.
    ''' A 128 bit random salt will be generated and prepended to the ciphertext before it is base64 encoded.
    ''' A 16 bit random Initialization Vector will also be generated prepended to the ciphertext before it is base64 encoded.
    ''' </summary>
    ''' <param name="plainText">The plain text to encrypt.</param>
    ''' <param name="key">The plain text encryption key.</param>
    ''' <returns>The salt, IV and the ciphertext, Base64 encoded.</returns>
    Public Shared Function Encrypt(plainText As String, key As String) As String
        'User Error Checks
        If String.IsNullOrEmpty(key) Then
            Throw New ArgumentNullException("key")
        End If
        If String.IsNullOrEmpty(plainText) Then
            Throw New ArgumentNullException("plainText")
        End If

        ' Derive a new Salt and IV from the Key, using a 128 bit salt and 10,000 iterations
        Using keyDerivationFunction = New Rfc2898DeriveBytes(key, SaltBitSize \ 8, Iterations)
            Using aesManaged = New AesManaged() With {
                .KeySize = KeyBitSize,
                .BlockSize = BlockBitSize
            }
                ' Generate random IV
                aesManaged.GenerateIV()

                ' Retrieve the Salt, Key and IV
                Dim saltBytes As Byte() = keyDerivationFunction.Salt
                Dim keyBytes As Byte() = keyDerivationFunction.GetBytes(KeyBitSize \ 8)
                Dim ivBytes As Byte() = aesManaged.IV

                ' Create an encryptor to perform the stream transform.
                ' Create the streams used for encryption.
                Using encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes)
                    Using memoryStream = New MemoryStream()

                        Using cryptoStream = New CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)
                            Using streamWriter = New StreamWriter(cryptoStream)
                                ' Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                                streamWriter.Write(plainText)
                            End Using
                        End Using

                        ' Return the encrypted bytes from the memory stream in Base64 form.
                        Dim cipherTextBytes = memoryStream.ToArray()

                        ' Resize saltBytes and append IV
                        Array.Resize(saltBytes, saltBytes.Length + ivBytes.Length)
                        Array.Copy(ivBytes, 0, saltBytes, SaltBitSize \ 8, ivBytes.Length)

                        ' Resize saltBytes with IV and append cipherText
                        Array.Resize(saltBytes, saltBytes.Length + cipherTextBytes.Length)
                        Array.Copy(cipherTextBytes, 0, saltBytes, (SaltBitSize \ 8) + ivBytes.Length, cipherTextBytes.Length)

                        Return Convert.ToBase64String(saltBytes)
                    End Using
                End Using
            End Using
        End Using
    End Function


    ''' <summary>
    ''' Decrypts the ciphertext using the Key.
    ''' </summary>
    ''' <param name="ciphertext">The ciphertext to decrypt.</param>
    ''' <param name="key">The plain text encryption key.</param>
    ''' <returns>The decrypted text.</returns>
    Public Shared Function Decrypt(ciphertext As String, key As String) As String
        If String.IsNullOrEmpty(ciphertext) Then
            Throw New ArgumentNullException("cipherText")
        End If
        If String.IsNullOrEmpty(key) Then
            Throw New ArgumentNullException("key")
        End If

        ' Prepare the Salt and IV arrays
        Dim saltBytes As Byte() = New Byte(SaltBitSize \ 8 - 1) {}
        Dim ivBytes As Byte() = New Byte(BlockBitSize \ 8 - 1) {}

        ' Read all the bytes from the cipher text
        Dim allTheBytes As Byte() = Convert.FromBase64String(ciphertext)

        ' Extract the Salt, IV from our ciphertext
        Array.Copy(allTheBytes, 0, saltBytes, 0, saltBytes.Length)
        Array.Copy(allTheBytes, saltBytes.Length, ivBytes, 0, ivBytes.Length)

        ' Extract the Ciphered bytes
        Dim ciphertextBytes As Byte() = New Byte(allTheBytes.Length - saltBytes.Length - ivBytes.Length - 1) {}
        Array.Copy(allTheBytes, saltBytes.Length + ivBytes.Length, ciphertextBytes, 0, ciphertextBytes.Length)

        Using keyDerivationFunction = New Rfc2898DeriveBytes(key, saltBytes, Iterations)
            ' Get the Key bytes
            Dim keyBytes = keyDerivationFunction.GetBytes(KeyBitSize \ 8)

            ' Create a decrytor to perform the stream transform.
            ' Create the streams used for decryption.
            ' The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
            Using aesManaged = New AesManaged() With {
                .KeySize = KeyBitSize,
                .BlockSize = BlockBitSize
            }
                Using decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes)
                    Using memoryStream = New MemoryStream(ciphertextBytes)
                        Using cryptoStream = New CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)
                            Using streamReader = New StreamReader(cryptoStream)
                                ' Return the decrypted bytes from the decrypting stream.
                                Return streamReader.ReadToEnd()
                            End Using
                        End Using
                    End Using
                End Using
            End Using
        End Using
    End Function

End Class
