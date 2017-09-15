using Microsoft.IdentityServer.Web.Authentication.External;
using System.Collections.Generic;

namespace ADFSEmailMFA
{
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


}
