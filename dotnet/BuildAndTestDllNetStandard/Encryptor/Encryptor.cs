using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using Encryptor.Properties;
using System.Xml.Linq;

namespace Encryption
{
    public class Encryptor
    {
        private byte[] key = null;
        private byte[] iv = null;

        public Encryptor()
        { 
        }

        public string EncryptPassword(string password2Encrypt, string masterName)
        {
            byte[] salt = Encoding.Default.GetBytes(masterName);
            CreateKeyAndIV(Resources.EncryptPassword, salt);
            byte[] encryptedBytes = Encrypt(password2Encrypt);
            //return Encoding.Default.GetString(encryptedBytes, 0, encryptedBytes.Count());
            return ByteArrayToString(encryptedBytes);
        }

        public string DecryptPassword(string encryptedPasswordString, string masterName)
        {
            byte[] encryptedPassword = //Encoding.Default.GetBytes(encryptedPasswordString);
                StringToByteArray(encryptedPasswordString);
            byte[] salt = Encoding.Default.GetBytes(masterName);
            CreateKeyAndIV(Resources.EncryptPassword, salt);
            return Decrypt(encryptedPassword);
        }

        private void CreateKeyAndIV(string password, byte[] salt)
        {
            using (Aes aes = Aes.Create())
            {
                var r = new Rfc2898DeriveBytes(password, salt);
                key = r.GetBytes(aes.KeySize / 8);
                iv = r.GetBytes(aes.BlockSize / 8);
            }
        }

        private byte[] Encrypt(string plainText)
        {
            byte[] encrypted = null;
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter w = new StreamWriter(cs))
                        {
                            w.Write(plainText);
                        }
                        encrypted = ms.ToArray();
                    }
                }
            }
            return encrypted;
        }

        private string Decrypt(byte[] encryptedBytes)
        {
            string plainText = null;
            using (Aes aes = Aes.Create())
            {
                aes.IV = iv;
                aes.Key = key;
                ICryptoTransform encryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            plainText = sr.ReadToEnd();
                        }
                    }
                }
            }
            return plainText;
        }

        private string ByteArrayToString(byte[] bytes)
        {
            return System.Convert.ToBase64String(bytes);
        }

        private byte[] StringToByteArray(string byteString)
        {
            return System.Convert.FromBase64String(byteString);
        }
    }
}