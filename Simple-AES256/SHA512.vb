Public Class SHA512
    ''' <summary>
    ''' A simple method to hash a string using SHA512 hashing algorithm.
    ''' </summary>
    ''' <param name="inputString">The string to be hashed.</param>
    ''' <returns>The hashed text.</returns>
    Public Shared Function HashString(inputString As String) As String
        ' Create the object used for hashing
        Using hasher = Security.Cryptography.SHA512.Create()
            ' Get the bytes of the input string and hash them
            Dim inputBytes As Byte() = Text.Encoding.UTF8.GetBytes(inputString)
            Dim hashedBytes As Byte() = hasher.ComputeHash(inputBytes)

            Return Convert.ToBase64String(hashedBytes)
        End Using
    End Function

    ''' <summary>
    ''' A simple method to hash bytes using SHA512 hashing algorithm.
    ''' </summary>
    ''' <param name="inputBytes">The bytes to be hashed.</param>
    ''' <returns>The hashed bytes as Base64 encoded text.</returns>
    Public Shared Function HashBytes(inputBytes As Byte()) As String
        ' Create the object used for hashing
        Using hasher As Security.Cryptography.SHA512 = Security.Cryptography.SHA512.Create()
            ' Get the bytes of the input and hash them
            Dim hashedBytes As Byte() = hasher.ComputeHash(inputBytes)

            Return Convert.ToBase64String(hashedBytes)
        End Using
    End Function
End Class
