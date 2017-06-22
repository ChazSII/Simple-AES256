Imports System.Text
Imports CS2Soft.SimpleAES256
Imports Microsoft.VisualStudio.TestTools.UnitTesting

<TestClass()> Public Class SimpleCipher_UnitTest

    <TestMethod()> Public Sub TestSimpleCipher()
        Dim cipherText As String = SimpleCipher.Encrypt(PlainText, Key)
        Dim new_plaintext As String = SimpleCipher.Decrypt(cipherText, Key)

        Assert.AreEqual(PlainText, new_plaintext)
    End Sub


End Class