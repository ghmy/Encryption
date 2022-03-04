using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Yoikkuygulamasi2019.Security
{
    public class HybridCipher : ICipher
    {

        private const int ENTROPY_SIZE = 16;
        private static int KEY_SIZE = 16;

        private const string RSA_PRIVATE_KEY = "<RSAKeyValue><Modulus>xUG/V9BMmIaSq/76cJKPJ7q6iEfa8WjR39J2FOH9nAiLQZdyjZoKN6bqFH8dYFDP/xMQdqkx5lUFWls8By9SJuzxj+gpVIeTVwcxJNcmtTWLOwyd92d9FEEIaeXIVkGdwkuioOwHK+qTBM29nYW8QcMep9nY37qJUpTZY2bHGiCDYbrjTVoYQtQIGmiLTjRMx6IilzpPnHhKhbHNf9evOuaZaJgbI/aEdxV+r3xpHiRqEm5fg6lhvHJ1FAXPyqRabO1CSZIA9vwXFVa1Ya1zkx6k2g3ArNqNQCUzF8B+3sCKiqFm0O631OG4n4jiLbYW6MD4YYcx6iyUzV4Y3d7LUQ==</Modulus><Exponent>AQAB</Exponent><P>613lmKNuDA/zichh9Ab/inrmxEhNvBINTm95CCLTqrTyDdO2rK86LW78rKasVpNvRzd9aS5qOpjRG+xmKlVEPEKSgeuFt6UWWtbp/VN6gn/29ciLU6vWLXt3YM0RZzQPM+6c2JUsQ/EDmxFzH3Mzno9aRIUCQjmrVlvLxhpL9Ns=</P><Q>1oyWKx1EE3tpEaa1hj+bUaWNpS6baLdnhfiQ439LmajbuJXpR+AXD7SpyfxgOWmm4A+UlHmnQD5F58JjNZAoeIZnCZKo8mnPh3RnkuwYaCSMsqOhK0wfbHk2Yunu5T0E0uRES3jxNoco93qOjQ4GyYBLwbY/90FK7uDvR358AkM=</Q><DP>VGdxxJEnD7BQt6Jibi5sSW7VfqInLkCTAQO8tYw3t8n327mGktqr1Esu1YNX3hw1FabylFuOwMC4jHj0Ek5NkAaXn3ukkjzjjWPwuWXMUywslet6+2BuCBV0tAQWL5pdsVPqb0jffOXbUyqozCh15HCoAFZqfvFLXkbBBqO7hW0=</DP><DQ>OrUbfk6yyxXw6TiR4VtUV+ISQUngkqXk+P7MPsQdXr2a6gZzYAyMouqPr0qU1gD3/cWlpX8oaebgYAuL9CMvP9OfLDpqanLTq8AJe2WJRC4EJfmqZ1ucGaWNYUGb8jRhNofpvDEq5/3SEu4BRc25w7eMg0QoerLuGzGHqCuPKVs=</DQ><InverseQ>Ho5+kzy0s/c8l7yz/YXTwDe6+VCHJaKNob/iwk5LI8aAecWmQGs6VuOSfoZvuSKbRo9iPiSMJF5kna6JN0lbph7Ks+x8Di5oB9Wui/lGIUAsoOj5nOsf349p5zsGZQSbTWr/mKz7FgwxvqkKwZMK6fA7FAK4d6zYvlHUHCZTSiU=</InverseQ><D>FVASRYGrFPvNUyockxcywn8pcloZLOY/buiFe6IjTb2alj6v0N7o5bRyLD7DxMlWf9/mcnu7eYCMMIQVC02wmaYWP489D/YKFGghhjJ86y1a2sl1M+sJl6ujJhX+vFsgmYKkkrCN4c/ZjLZSG3f8rDpR0J74EMxN1A9jIZtUPd0+2AyI8yCe/eu4YRZEOcb5ZgbJrtU2RFBmbbPa8qLfYP4ypfvX502oVDp16yoWkrzAuMpFhH14JCXqLZ8HFAQcMIe/o2AbXr4ve/hsV6/4RZeXWKPy/oGSTAAel5yMlk8CeFMco4IKGD82WvvL79P5Q1nm+f2PvixnEmCbch6SVQ==</D></RSAKeyValue>";
        private const string RSA_PUBLIC_KEY = "<RSAKeyValue><Modulus>xUG/V9BMmIaSq/76cJKPJ7q6iEfa8WjR39J2FOH9nAiLQZdyjZoKN6bqFH8dYFDP/xMQdqkx5lUFWls8By9SJuzxj+gpVIeTVwcxJNcmtTWLOwyd92d9FEEIaeXIVkGdwkuioOwHK+qTBM29nYW8QcMep9nY37qJUpTZY2bHGiCDYbrjTVoYQtQIGmiLTjRMx6IilzpPnHhKhbHNf9evOuaZaJgbI/aEdxV+r3xpHiRqEm5fg6lhvHJ1FAXPyqRabO1CSZIA9vwXFVa1Ya1zkx6k2g3ArNqNQCUzF8B+3sCKiqFm0O631OG4n4jiLbYW6MD4YYcx6iyUzV4Y3d7LUQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        private byte[] RSAEncrypt(byte[] key)
        {
            using (var cipher = RSA.Create())
            {
                cipher.FromXmlStringExt(RSA_PUBLIC_KEY);

                byte[] cipherData = cipher.Encrypt(key, RSAEncryptionPadding.Pkcs1);
                return cipherData;
            }
        }

        public byte[] RSADecrypt(byte[] cipherBytes)
        {
            using (var cipher = RSA.Create())
            {
                cipher.FromXmlStringExt(RSA_PRIVATE_KEY);

                byte[] original = cipher.Decrypt(cipherBytes, RSAEncryptionPadding.Pkcs1);
                return original;
            }
        }

        private static byte[] GenerateRandomEntropy(int size)
        {
            var randomBytes = new byte[size];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
        public string Encrypt(string plainText)
        {
            byte[] key = GenerateRandomEntropy(KEY_SIZE);
            var encryptedKey = RSAEncrypt(key);

            using (Aes encryptor = Aes.Create())
            {
                encryptor.Mode = CipherMode.CBC;

                encryptor.Key = key;
                encryptor.IV = GenerateRandomEntropy(ENTROPY_SIZE);

                var saltStringBytes = GenerateRandomEntropy(ENTROPY_SIZE);
                var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cryptoStream.FlushFinalBlock();

                        var cipherTextBytes = setCipherTextBytes(encryptedKey, saltStringBytes, encryptor.IV, memoryStream.ToArray());

                        memoryStream.Close();
                        cryptoStream.Close();

                        return Convert.ToBase64String(cipherTextBytes);
                    }
                }
            }
        }
        private static byte[] setCipherTextBytes(byte[] encryptedKey, byte[] salt, byte[] iv, byte[] stream)
        {

            int encSize = encryptedKey.Length;
            int saltSize = salt.Length;
            int ivSize = iv.Length;
            int streamSize = stream.Length;
            int sum = encSize + saltSize + ivSize + streamSize;

            int byteCount = sum / 4;
            Random r = new Random();

            int extraCount = r.Next(1, 5);
            var extraEntropy = GenerateRandomEntropy(extraCount);
            List<byte> turnBytes = extraEntropy.ToList();

            int byteSize = 0;
            byte b = 0;

            while (sum > 0)
            {
                if (byteSize == 8)
                {
                    turnBytes.Add(b);
                    b = 0;
                    byteSize = 0;
                }

                int rNum = r.Next(0, sum);

                if (rNum < encSize)
                {
                    encSize--;
                }
                else if (rNum < encSize + saltSize)
                {
                    saltSize--;
                    b |= (byte)(0x01 << byteSize);
                }
                else if (rNum < encSize + saltSize + ivSize)
                {
                    ivSize--;
                    b |= (byte)(0x02 << byteSize);
                }
                else
                {
                    streamSize--;
                    b |= (byte)(0x03 << byteSize);
                }

                byteSize += 2;
                sum--;
            }

            // Sona kalan byte da ekleniyor
            turnBytes.Add(b);

            List<byte> cipherBytes = turnBytes;

            for (int i = 0; i < byteCount; i++)
            {
                for (int j = 0; j < 8; j += 2)
                {
                    b = (byte)((turnBytes[extraCount + i] >> j) & 0x03);

                    if (b == 0)
                        cipherBytes.Add(encryptedKey[encSize++]);
                    else if (b == 1)
                        cipherBytes.Add(salt[saltSize++]);
                    else if (b == 2)
                        cipherBytes.Add(iv[ivSize++]);
                    else
                        cipherBytes.Add(stream[streamSize++]);
                }
            }

            return cipherBytes.ToArray();
        }

        public string Decrypt(string cipherText)
        {
            // Instantiate a new Aes object to perform string symmetric encryption
            using (Aes encryptor = Aes.Create())
            {
                encryptor.Mode = CipherMode.CBC;

                var cipherBytes = Convert.FromBase64String(cipherText);
                var byteList = getCipherTextBytes(cipherBytes);

                var key = RSADecrypt(byteList[0]);
                // Set key and IV
                encryptor.Key = key;
                encryptor.IV = byteList[2];

                // Instantiate a new MemoryStream object to contain the encrypted bytes
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    // Instantiate a new encryptor from our Aes object
                    ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();

                    // Instantiate a new CryptoStream object to process the data and write it to the 
                    // memory stream
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write))
                    {
                        // Will contain decrypted plaintext
                        string plainText = String.Empty;

                        try
                        {
                            // Decrypt the input ciphertext string
                            cryptoStream.Write(byteList[3], 0, byteList[3].Length);

                            // Complete the decryption process
                            cryptoStream.FlushFinalBlock();

                            // Convert the decrypted data from a MemoryStream to a byte array
                            byte[] plainBytes = memoryStream.ToArray();

                            // Convert the decrypted byte array to string
                            plainText = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);
                        }
                        finally
                        {
                            // Close both the MemoryStream and the CryptoStream
                            memoryStream.Close();
                            cryptoStream.Close();
                        }

                        // Return the decrypted data as a string
                        return plainText;
                    }
                }
            }
        }
        private static List<byte[]> getCipherTextBytes(byte[] cipherBytes)
        {
            int count = cipherBytes.Length / 5;

            List<List<byte>> retVal = new List<List<byte>> { new List<byte>(), new List<byte>(), new List<byte>(), new List<byte>() };
            byte b;

            int mod = cipherBytes.Length % 5;
            int ind = count + mod;

            for (int i = 0; i < count; i++)
            {
                for (int j = 0; j < 8; j += 2)
                {
                    b = (byte)((cipherBytes[i + mod] >> j) & 0x03);
                    retVal[b].Add(cipherBytes[ind++]); 
                }
            }

            return new List<byte[]> { retVal[0].ToArray(), retVal[1].ToArray(), retVal[2].ToArray(), retVal[3].ToArray() };
        }
    }
}
