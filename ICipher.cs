namespace Yoikkuygulamasi2019.Security
{
    public interface ICipher
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
    }
}
