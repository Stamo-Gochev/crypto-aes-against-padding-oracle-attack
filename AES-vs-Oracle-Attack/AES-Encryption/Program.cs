using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Security.Cryptography;

namespace AES_Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            var dataToEncrypt = "test";
            var encrypted = EncryptionHelper.EncryptString(dataToEncrypt);
            Console.WriteLine($"Encrypt: {dataToEncrypt}");
            Console.WriteLine($"Result: {encrypted}");

            var decrypted = EncryptionHelper.DecryptString(encrypted);
            Console.WriteLine($"Decrypted: {decrypted}");
        }
    }

    // See on https://blogs.msdn.microsoft.com/shawnfa/2009/03/17/authenticated-symmetric-encryption-in-net/
    class EncryptionHelper
    {
        // Do not change!
        // The size of the IV (Interval vector) should be 12 for GCM and CCM modes of the AES algorithm
        private static readonly int IV_LENGTH = 12;
        private static readonly int TAG_LENGTH = 16;

        // returns the encrypted string in the format [IV]-[TAG]-[DATA]
        public static string EncryptString(string str)
        {
            if (String.IsNullOrEmpty(str))
            {
                throw new ArgumentNullException("encryption string invalid");
            }

            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                byte[] message = Encoding.UTF8.GetBytes(str);
                aes.Key = GetEncryptionKey();
                aes.IV = GenerateIV();
                // use the GCM mode, which should prevent the Padding Oracle attack
                // https://en.wikipedia.org/wiki/Padding_oracle_attack
                aes.CngMode = CngChainingMode.Gcm;
                aes.AuthenticatedData = GetAdditionalAuthenticationData();

                using (MemoryStream memoryStream = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    // Write through and retrieve encrypted data.
                    cryptoStream.Write(message, 0, message.Length);
                    cryptoStream.FlushFinalBlock();
                    byte[] cipherText = memoryStream.ToArray();

                    // Retrieve tag and create array to hold encrypted data.
                    byte[] authenticationTag = encryptor.GetTag();
                    byte[] encrypted = new byte[cipherText.Length + aes.IV.Length + authenticationTag.Length];

                    // encrypt the data in the format [IV]-[TAG]-[DATA]
                    aes.IV.CopyTo(encrypted, 0);
                    authenticationTag.CopyTo(encrypted, IV_LENGTH);
                    cipherText.CopyTo(encrypted, IV_LENGTH + TAG_LENGTH);

                    // Store encrypted value in base 64.
                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        public static string DecryptString(string str)
        {
            if (String.IsNullOrEmpty(str))
            {
                throw new ArgumentNullException("decryption string invalid");
            }

            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                byte[] encrypted = Convert.FromBase64String(str);               // Convert string to bytes.
                aes.Key = GetEncryptionKey();                                   // Retrieve Key.
                aes.IV = GetIV(encrypted);                                      // Parse IV from encrypted text.
                aes.Tag = GetTag(encrypted);                                    // Parse Tag from encrypted text.
                encrypted = RemoveTagAndIV(encrypted);                          // Remove Tag and IV for proper decryption.
                aes.CngMode = CngChainingMode.Gcm;                              // Set Cryptographic Mode.
                aes.AuthenticatedData = GetAdditionalAuthenticationData();      // Set Authentication Data.

                using (MemoryStream memoryStream = new MemoryStream())
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                {
                    // Decrypt through stream.
                    cryptoStream.Write(encrypted, 0, encrypted.Length);

                    // If the authentication tag does not validate, this call will throw a CryptographicException.
                    try
                    {
                        cryptoStream.FlushFinalBlock();

                    }
                    catch (CryptographicException cryptoException)
                    {

                    }
                    catch (NotSupportedException notSupportedException)
                    {

                    }

                    // Remove from stream and convert to string.
                    byte[] decrypted = memoryStream.ToArray();
                    return Encoding.UTF8.GetString(decrypted);
                }
            }
        }

        private static byte[] GetEncryptionKey()
        {
            // Normally some magic to retrieve the key.
            // another option is to allow its injection from the user
            return new byte[] { 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 };
        }

        // The IV (called the nonce in many of the authenticated algorithm specs) is not sized for
        // the input block size. Instead its size depends upon the algorithm. 12 bytes works for both GCM and CCM.
        private static byte[] GenerateIV()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] nonce = new byte[IV_LENGTH];
                rng.GetBytes(nonce);
                return nonce;
            }
        }

        // This property is optional - leaving the value null means that the authentication tag is generated only from the plaintext.
        private static byte[] GetAdditionalAuthenticationData()
        {
            // hardcode for now
            return Encoding.UTF8.GetBytes("A promise that I know the key");
        }

        // parses authentication tag from the ciphertext.
        // Input: ciphertext
        private static byte[] GetTag(byte[] arr)
        {
            byte[] tag = new byte[TAG_LENGTH];
            Array.Copy(arr, IV_LENGTH, tag, 0, TAG_LENGTH);
            return tag;
        }

        // parses IV from ciphertext.
        // Input: Passed the ciphertext byte array.
        // Output: Returns byte array containing the IV.
        private static byte[] GetIV(byte[] arr)
        {
            byte[] IV = new byte[IV_LENGTH];
            Array.Copy(arr, 0, IV, 0, IV_LENGTH);
            return IV;
        }

        // removes the tag and IV from the byte array so it may be decrypted.
        // Input: Passed the ciphertext byte array.
        // Output: Peturns a byte array consisting of only encrypted data.
        private static byte[] RemoveTagAndIV(byte[] arr)
        {
            byte[] dataWithoutTagAndIV = new byte[arr.Length - TAG_LENGTH - IV_LENGTH];
            Array.Copy(arr, IV_LENGTH + TAG_LENGTH, dataWithoutTagAndIV, 0, arr.Length - IV_LENGTH - TAG_LENGTH);
            return dataWithoutTagAndIV;
        }
    }
}
