Imports System.Text
Imports CS2Soft.SimpleAES256
Imports Microsoft.VisualStudio.TestTools.UnitTesting

<TestClass()> Public Class AES256_UnitTest

    <TestMethod()> Public Sub TestEncryptDecryptCycle()
        Using aes As New AES256(Key)
            Dim cipherText As String = aes.GetCipherBase64(PlainText)
            Dim new_PlainText As String = aes.GetPlainText(cipherText)

            Assert.AreEqual(PlainText, new_PlainText)
        End Using
    End Sub

    <TestMethod()> Public Sub TestEncryptDecryptSeperate()
        Dim SaltBytes As Byte()
        Dim IvBytes As Byte()
        Dim CipherTextBase64 As String
        Dim new_PlainText As String

        Using aes As New AES256(Key)
            SaltBytes = aes.GetSaltBytes()
            IvBytes = aes.GetInitializationVector()
            CipherTextBase64 = aes.GetCipherBase64(PlainText)
        End Using

        Using aes As New AES256(Key, IvBytes, SaltBytes)
            new_PlainText = aes.GetPlainText(CipherTextBase64)
        End Using

        Assert.AreEqual(PlainText, new_PlainText)
    End Sub

End Class