using System;

namespace ADFSEmailMFA
{
    class PINGenerator
    {
        public static string EncryptedPIN = GetEncryptedPIN();
        public static string DecryptedPIN = GetDecryptedPIN();

        private static string GetEncryptedPIN()
        {
            string EncryptedText = cryptoHelper.AESThenHMAC.SimpleEncryptWithPassword(GetPin, EmailAuthenticationProvider.AuthProviderSettings.pinEncryptionKey);
            return EncryptedText;
        }

        private static string GetDecryptedPIN()
        {
            string DecryptedText = cryptoHelper.AESThenHMAC.SimpleDecryptWithPassword(EncryptedPIN, EmailAuthenticationProvider.AuthProviderSettings.pinEncryptionKey);
            return DecryptedText;
        }

        private static string GetPin
        {
            get
            {
                Random Random = new Random();
                string RandomPinNumber = Random.Next(100000, 999999).ToString();
                return RandomPinNumber;
            }
        }
    }
}
