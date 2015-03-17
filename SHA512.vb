Imports System.Security.Cryptography

Public Class SHA512
    ''' <summary>
    ''' A simple method to hash a string using SHA512 hashing algorithm.
    ''' </summary>
    ''' <param name="inputString">The string to be hashed.</param>
    ''' <returns>The hashed text.</returns>
    Public Shared Function HashString(inputString As String) As String
        ' Create the object used for hashing
        Using hasher = SHA512Managed.Create()
            ' Get the bytes of the input string and hash them
            Dim inputBytes = System.Text.Encoding.UTF8.GetBytes(inputString)
            Dim hashedBytes = hasher.ComputeHash(inputBytes)

            Return Convert.ToBase64String(hashedBytes)
        End Using
    End Function
End Class
