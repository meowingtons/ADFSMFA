using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using Microsoft.IdentityServer.Web.Authentication.External;
using System.DirectoryServices;
using System.Net.Mail;
using System.IO;
using Newtonsoft.Json;

namespace ADFSEmailMFA
{
    class EmailAuthenticationProvider : IAuthenticationAdapter
    {
        public IAuthenticationAdapterMetadata Metadata
        {
            get
            {
                return new AuthenticationAdapterMetadata();
            }
        }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
        {
            RandomNumber = GetPin;
            SendEmail(EmailAddress, AuthProviderSettings.emailSubject , RandomNumber);
            WriteLog("BeginAuthentication - GetPin equals " + RandomNumber);
            return new AdapterPresentation();
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            //get identityclaim value
            string mail = identityClaim.Value;

            //if 'MultiFactorAuthMethod' attribute in AD equals 'email' and 'email' attribute in AD is populated return true, else false
            SearchResultCollection Results = null;
            string path = AuthProviderSettings.ldapConnectionString;
            DirectoryEntry DirEntry = new DirectoryEntry(path, AuthProviderSettings.ldapBindUserName, AuthProviderSettings.ldapBindPassword, AuthenticationTypes.Secure);
            WriteLog("Created DirEntry");
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
                WriteLog("Found User, Method is available");
                return true;
            }
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            if (AuthProviderSettingsLoaded == false)
            {
                WriteLog("Serializing json config file");
                LoadSettings(configData.Data);

                WriteLog("Loaded settings are:");
                foreach (var prop in AuthProviderSettings.GetType().GetProperties())
                {
                    string var = prop.Name + '=' + prop.GetValue(AuthProviderSettings, null);
                    WriteLog(var);
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
            File.WriteAllText(@"C:\testadfsconfig.json", JsonConvert.SerializeObject(AuthProviderSettings, Formatting.Indented));
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            return new AdapterPresentation(ex.Message, true);
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] claims)
        {
            //do actual MFA authentication
            //get email for user, generate OTP, send OTP to the email, verify OTP typed in equals what was generated
            claims = null;
            IAdapterPresentation result = null;

            WriteLog("TryEndAuthentication - GetPin equals " + RandomNumber);
            string suppliedPin = proofData.Properties["PIN"].ToString();
            WriteLog("TryEndAuthentication - suppliedPin equals " + suppliedPin);
            
            if (RandomNumber == suppliedPin)
            {
                Claim claim = new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "http://schemas.microsoft.com/ws/2012/12/authmethod/otp");
                claims = new Claim[] { claim };
            }
            else
            {
                result = new AdapterPresentation("Authentication Failed.", false);
            }
            return result;
        }

        public void WriteLog(string TextToWrite)
        {
            StreamWriter LogFile = new StreamWriter(@"C:\ADFSLogFile.txt", true);
            LogFile.WriteLine(TextToWrite);
            LogFile.Close();
        }

        /// private methods
        private static void LoadSettings(Stream FileToLoad)
        {
            //load stream and read entire thing as string
            StreamReader configFileStream = new StreamReader(FileToLoad);
            string configFile = configFileStream.ReadToEnd();

            //deserialize the json string into object
            AuthProviderSettings = JsonConvert.DeserializeObject<MFASettings>(configFile);

            //close the streamreader
            configFileStream.Close();
        }

        public static MFASettings AuthProviderSettings = new MFASettings();
        public static bool AuthProviderSettingsLoaded;
        private static string _EmailAddress;
        private static string EmailAddress
        {
            get { return _EmailAddress; }
            set { _EmailAddress = value; }
        }

        private static string _RandomNumber;
        private static string RandomNumber
        {
            get { return _RandomNumber; }
            set { _RandomNumber = value; }
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

        private void SendEmail(string sendToEmail, string emailSubject, string pin)
        {
            MailAddress fromAddress = new MailAddress( AuthProviderSettings.fromEmailAddress, AuthProviderSettings.fromEmailAddressName);
            MailAddress toAddress = new MailAddress(sendToEmail, "To Name");
            string fromPassword = AuthProviderSettings.fromEmailAddressPassword;
            string subject = emailSubject;
            string body = AuthProviderSettings.emailBody + pin;

            var smtp = new SmtpClient
            {
                Host = AuthProviderSettings.mailServer,
                Port = AuthProviderSettings.mailServerPort,
                EnableSsl = true,
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

        public class MFASettings
        {
                public string ldapConnectionString { get; set; }
                public string ldapBindUserName { get; set; }
                public string ldapBindPassword { get; set; }
                public string fromEmailAddress { get; set; }
                public string fromEmailAddressName { get; set; }
                public string fromEmailAddressPassword { get; set; }
                public string mailServer { get; set; }
                public int mailServerPort { get; set; }
                public string emailSubject { get; set; }
                public string emailBody { get; set; }
        }
    }

    class AuthenticationAdapterMetadata : IAuthenticationAdapterMetadata
    {
        public string AdminName
        {
            get
            {
                return "EmailAuthenticationMethod";
            }
        }

        public string[] AuthenticationMethods
        {
            get
            {
                return new string[] { "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" };
            }
        }

        public int[] AvailableLcids
        {
            get
            {
                return new int[] { 1033 };
            }
        }

        public Dictionary<int, string> Descriptions
        {
            get
            {
                Dictionary<int, string> result = new Dictionary<int, string>();
                result.Add(1033, "Email Authentication Provider");
                return result;
            }
        }

        public Dictionary<int, string> FriendlyNames
        {
            get
            {
                Dictionary<int, string> result = new Dictionary<int, string>();
                result.Add(1033, "Email Authentication Provider");
                return result;
            }
        }

        public string[] IdentityClaims
        {
            get
            {
                return new string[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" };
            }
        }

        public bool RequiresIdentity
        {
            get
            {
                return true;
            }
        }
    }

    class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        private string message;
        private bool isPermanentFailure;
        public string GetFormHtml(int lcid)
        {
            string result = "";
            if (!String.IsNullOrEmpty(this.message))
            {
                result += "<p>" + message + "</p>";
            }
            if (!this.isPermanentFailure)
            {
                result += "<form method=\"post\" id=\"loginForm\" autocomplete=\"off\">";
                result += "PIN: <input id=\"pin\" name=\"pin\" type=\"password\" />";
                result += "<input id=\"context\" type=\"hidden\" name=\"Context\" value=\"%Context%\"/>";
                result += "<input id=\"authMethod\" type=\"hidden\" name=\"AuthMethod\" value=\"%AuthMethod%\"/>";
                result += "<input id=\"continueButton\" type=\"submit\" name=\"Continue\" value=\"Continue\" />";
                result += "</form>";
            }
            return result;
        }

        public string GetFormPreRenderHtml(int lcid)
        {
            return string.Empty;
        }

        public string GetPageTitle(int lcid)
        {
            return "Email Authentication Provider";
        }

        public AdapterPresentation()
        {
            this.message = string.Empty;
            this.isPermanentFailure = false;
        }
        public AdapterPresentation(string message, bool isPermanentFailure)
        {
            this.message = message;
            this.isPermanentFailure = isPermanentFailure;
        }
    }
}
