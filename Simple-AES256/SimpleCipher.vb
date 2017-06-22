''' <summary>
''' A simple wrapper to the AesManaged class and the AES algorithm.
''' Uses 256 bit key, 128 bit psuedo-random salt and a 16 bit
''' psuedo-randomly generated Initialization Vector 
''' </summary>
Public Class SimpleCipher
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

        Using aes256 As New AES256(key)
            With aes256
                Dim saltBytes As Byte() = .GetSaltBytes()
                Dim ivBytes As Byte() = .GetInitializationVector()
                Dim cipherBytes As Byte() = .GetCipherBytes(plainText)

                ' Resize saltBytes and append IV
                Array.Resize(saltBytes, saltBytes.Length + ivBytes.Length)
                Array.Copy(ivBytes, 0, saltBytes, KeySaltSize \ 8, ivBytes.Length)

                ' Resize saltBytes with IV and append cipherText
                Array.Resize(saltBytes, saltBytes.Length + cipherBytes.Length)
                Array.Copy(cipherBytes, 0, saltBytes, (KeySaltSize \ 8) + ivBytes.Length, cipherBytes.Length)

                Return Convert.ToBase64String(saltBytes)
            End With
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
        Dim saltBytes As Byte() = New Byte(KeySaltSize \ 8 - 1) {}
        Dim ivBytes As Byte() = New Byte(AesBlockSize \ 8 - 1) {}

        ' Read all the bytes from the cipher text
        Dim allTheBytes As Byte() = Convert.FromBase64String(ciphertext)

        ' Extract the Salt, IV from our ciphertext
        Array.Copy(allTheBytes, 0, saltBytes, 0, saltBytes.Length)
        Array.Copy(allTheBytes, saltBytes.Length, ivBytes, 0, ivBytes.Length)

        ' Extract the Ciphered bytes
        Dim ciphertextBytes As Byte() = New Byte(allTheBytes.Length - saltBytes.Length - ivBytes.Length - 1) {}
        Array.Copy(allTheBytes, saltBytes.Length + ivBytes.Length, ciphertextBytes, 0, ciphertextBytes.Length)

        Using aes256 As New AES256(key, ivBytes, saltBytes)
            With aes256
                Return .GetPlainText(Convert.ToBase64String(ciphertextBytes))
                ' Resize saltBytes and append IV
                Array.Resize(saltBytes, saltBytes.Length + ivBytes.Length)
                Array.Copy(ivBytes, 0, saltBytes, KeySaltSize \ 8, ivBytes.Length)

                ' Resize saltBytes with IV and append cipherText
                Array.Resize(saltBytes, saltBytes.Length + ciphertextBytes.Length)
                Array.Copy(ciphertextBytes, 0, saltBytes, (KeySaltSize \ 8) + ivBytes.Length, ciphertextBytes.Length)

                Return Convert.ToBase64String(saltBytes)
            End With
        End Using
    End Function

End Class
