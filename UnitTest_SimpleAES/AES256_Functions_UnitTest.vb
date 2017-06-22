Imports System.Text
Imports Microsoft.VisualStudio.TestTools.UnitTesting
Imports CS2Soft.SimpleAES256
Imports System.Security.Cryptography

<TestClass()> Public Class AES256_Functions_UnitTest
    Const SaltBase64 As String = "AP8zRQAKVLF6k6U4aQGw8A=="
    Const IvBase64 As String = "ThgnlRBBK9YqM7aNMwT1YA=="

    <TestMethod()> Public Sub TestGetKeyBytes()
        Using aes As New AES256(Key, Convert.FromBase64String(IvBase64), Convert.FromBase64String(SaltBase64))
            Dim KeyDerivationFunction1 = New Rfc2898DeriveBytes(Key,
                                                                Convert.FromBase64String(SaltBase64),
                                                                HashIterations)

            Dim KeyDerivationFunction2 = New Rfc2898DeriveBytes(Encoding.Default.GetBytes(Key),
                                                                Convert.FromBase64String(SaltBase64),
                                                                HashIterations)

            Dim aes_Key As Byte() = aes.GetKeyBytes()
            Dim kdf_Key1 As Byte() = KeyDerivationFunction1.GetBytes(KeySize \ 8)
            Dim kdf_Key2 As Byte() = KeyDerivationFunction2.GetBytes(KeySize \ 8)

            CollectionAssert.AreEqual(aes_Key, kdf_Key1)
            CollectionAssert.AreEqual(aes_Key, kdf_Key2)
        End Using
    End Sub

    <TestMethod()> Public Sub TestGetSaltBytes()
        Using aes As New AES256(Key, Convert.FromBase64String(IvBase64), Convert.FromBase64String(SaltBase64))
            Dim KeyDerivationFunction1 = New Rfc2898DeriveBytes(Key,
                                                                Convert.FromBase64String(SaltBase64),
                                                                HashIterations)

            Dim KeyDerivationFunction2 = New Rfc2898DeriveBytes(Encoding.Default.GetBytes(Key),
                                                                Convert.FromBase64String(SaltBase64),
                                                                HashIterations)

            Dim aes_Salt As Byte() = aes.GetSaltBytes()
            Dim kdf_Salt1 As Byte() = KeyDerivationFunction1.Salt
            Dim kdf_Salt2 As Byte() = KeyDerivationFunction2.Salt

            CollectionAssert.AreEqual(aes_Salt, kdf_Salt1)
            CollectionAssert.AreEqual(aes_Salt, kdf_Salt2)
        End Using
    End Sub

    <TestMethod()> Public Sub TestGetIvBytes()
        Using aes As New AES256(Key, Convert.FromBase64String(IvBase64), Convert.FromBase64String(SaltBase64))
            Dim aes_Salt As Byte() = aes.GetInitializationVector()

            CollectionAssert.AreEqual(aes_Salt, Convert.FromBase64String(IvBase64))
        End Using
    End Sub
End Class