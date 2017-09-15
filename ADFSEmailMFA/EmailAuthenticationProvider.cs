using System;
using System.Net;
using System.Security.Claims;
using Microsoft.IdentityServer.Web.Authentication.External;
using System.DirectoryServices;
using System.Net.Mail;
using System.IO;
using Newtonsoft.Json;
using System.Runtime.InteropServices;

namespace ADFSEmailMFA
{
    class EmailAuthenticationProvider : IAuthenticationAdapter
    {
        public static Configuration.MFASettings AuthProviderSettings = new Configuration.MFASettings();
        public static bool AuthProviderSettingsLoaded;
        public static Guid AuthenticationRequestID;
        private static string _EmailAddress;
        public static string EmailAddress
        {
            get { return _EmailAddress; }
            set { _EmailAddress = value; }
        }

        public IAuthenticationAdapterMetadata Metadata
        {
            get
            {
                return new AuthenticationAdapterMetadata();
            }
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            if (AuthProviderSettingsLoaded == false)
            {
                LoadSettings(configData.Data);
                WriteLog("Loaded settings are:");
                foreach (var prop in AuthProviderSettings.GetType().GetProperties())
                {
                    if (prop.Name != "ldapBindPassword" || prop.Name != "pinEncryptionKey")
                    {
                        string var = prop.Name + '=' + prop.GetValue(AuthProviderSettings, null);
                        WriteLog(var);
                    }
                }
                AuthProviderSettingsLoaded = true;
            }
            else
            {
                WriteLog("Configuration file already loaded");
            }
        }

        public void OnAuthenticationPipelineUnload()
        {
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            return new AdapterPresentation(ex.Message, true, PINGenerator.EncryptedPIN);
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            AuthenticationRequestID = Guid.NewGuid();
            string mail = identityClaim.Value;
            SearchResultCollection Results = null;
            string path = AuthProviderSettings.ldapConnectionString;
            DirectoryEntry DirEntry = new DirectoryEntry(path, AuthProviderSettings.ldapBindUserName, AuthProviderSettings.ldapBindPassword, AuthenticationTypes.Secure);
            WriteLog("Checking to see if " + mail + " exist.", AuthenticationRequestID);
            DirectorySearcher DirSearcher = new DirectorySearcher(DirEntry)
            {
                Filter = "(&(objectClass=user)(mail=" + mail + "))"
            };
            DirSearcher.PropertiesToLoad.Add("SamAccountName");
            DirSearcher.PropertiesToLoad.Add("mail");

            Results = DirSearcher.FindAll();

            if (Results.Count != 1)
            {
                return false;
            }
            else
            {
                EmailAddress = mail;
                WriteLog("Found " + EmailAddress + ", Method is available", AuthenticationRequestID);
                return true;
            }
        }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
        {
            SendEmail(EmailAddress, AuthProviderSettings.emailSubject, PINGenerator.DecryptedPIN);
            WriteLog(EmailAddress + " - Sending OTP to user", AuthenticationRequestID);
            WriteLog(EmailAddress + " - PIN sent to user is: " + PINGenerator.DecryptedPIN, AuthenticationRequestID);
            return new AdapterPresentation(PINGenerator.EncryptedPIN, true);
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] claims)
        {
            claims = null;
            IAdapterPresentation result = null;
            string suppliedPin = proofData.Properties["PIN"].ToString();
            string authContext = proofData.Properties["authContext"].ToString();
            string decryptedAuthContext = cryptoHelper.AESThenHMAC.SimpleDecryptWithPassword(authContext, AuthProviderSettings.pinEncryptionKey);

            WriteLog(EmailAddress + " - provided the following PIN:" + " " + suppliedPin, AuthenticationRequestID);
            
            if (decryptedAuthContext == suppliedPin)
            {
                Claim claim = new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "http://schemas.microsoft.com/ws/2012/12/authmethod/otp");
                claims = new Claim[] { claim };
                WriteLog(EmailAddress + " - Authenticated Successfully", AuthenticationRequestID);
            }
            else
            {
                WriteLog(EmailAddress + " Authentication Failed", AuthenticationRequestID);
                result = new AdapterPresentation("Oops! That PIN doesn't match what we sent. Please try again.", false, PINGenerator.EncryptedPIN, false);
            }

            return result;
        }

        public void WriteLog(string LogMessage, [Optional]Guid AuthenticationRequest, [Optional]string EmailAddress)
        {
            string TextToWrite;
            DateTime CurrentDateTime = System.DateTime.UtcNow;
            if (AuthenticationRequest == null)
            {
                TextToWrite = CurrentDateTime.ToLocalTime().ToString() + " - " + LogMessage;
            }
            else
            {
                TextToWrite = CurrentDateTime.ToLocalTime().ToString() + " - " + AuthenticationRequest.ToString() + " - " + LogMessage;
            }

            string path = AuthProviderSettings.logFilePath;
            StreamWriter LogFile = new StreamWriter(path, true);
            LogFile.WriteLine(TextToWrite);
            LogFile.Close();
        }

        private static void LoadSettings(Stream FileToLoad)
        {
            StreamReader configFileStream = new StreamReader(FileToLoad);
            string configFile = configFileStream.ReadToEnd();
            AuthProviderSettings = JsonConvert.DeserializeObject<Configuration.MFASettings>(configFile); //deserialize the json string into object
            configFileStream.Close();
        }

        private void SendEmail(string sendToEmail, string emailSubject, string pin)
        {
            MailAddress fromAddress = new MailAddress( AuthProviderSettings.fromEmailAddress, AuthProviderSettings.fromEmailAddressName);
            MailAddress toAddress = new MailAddress(sendToEmail, sendToEmail);
            string fromPassword = AuthProviderSettings.fromEmailAddressPassword;
            string subject = emailSubject;
            string body = AuthProviderSettings.emailBody + pin;

            var smtp = new SmtpClient
            {
                Host = AuthProviderSettings.mailServer,
                Port = AuthProviderSettings.mailServerPort,
                EnableSsl = false,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
            };
            using (var message = new MailMessage(fromAddress, toAddress)
            {
                Subject = subject,
                Body = body
            })
            {
                smtp.Send(message);
            }
        }
    }
}
