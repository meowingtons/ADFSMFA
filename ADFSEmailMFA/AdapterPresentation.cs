using Microsoft.IdentityServer.Web.Authentication.External;
using System;

namespace ADFSEmailMFA
{
    class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        private string message;
        private bool isPermanentFailure;
        private bool isFirstTry;
        private string authContext;

        public string GetFormHtml(int lcid)
        {
            string result = "";
            if (!String.IsNullOrEmpty(this.message))
            {
                result += "<b style=\"color:red;\">" + message + "</b>";
                result += "<br><br>";
            }
            if (!this.isPermanentFailure & this.isFirstTry)
            {
                result += "We've sent a PIN to <b>" + EmailAuthenticationProvider.EmailAddress + "</b>. Please input that PIN below:</b>";
                result += "<br><br>";
            }

            if (!this.isPermanentFailure & !this.isFirstTry)
            {
                result += "<div>Look for an email from " + EmailAuthenticationProvider.AuthProviderSettings.fromEmailAddress + " and " + "\"" + EmailAuthenticationProvider.AuthProviderSettings.emailSubject + "\"" + " in the subject.</div>";
                result += "<br>";
            }

            if (!this.isPermanentFailure)
            {
                result += "<form method=\"post\" id=\"loginForm\" autocomplete=\"off\">";
                result += "PIN: <input id=\"pin\" name=\"pin\" type=\"password\" />";
                result += "<input id=\"context\" type=\"hidden\" name=\"Context\" value=\"%Context%\"/>";
                result += "<input id=\"authContext\" type=\"hidden\" name=\"authContext\" value=\"" + this.authContext + "\"/>";
                result += "<input id=\"authMethod\" type=\"hidden\" name=\"AuthMethod\" value=\"%AuthMethod%\"/>";
                result += "<input id=\"continueButton\" type=\"submit\" name=\"Continue\" value=\"Continue\" />";
                result += "</form>";
            }

            if (!this.isPermanentFailure & !this.isFirstTry & EmailAuthenticationProvider.AuthProviderSettings.contactPhoneNumber != null)
            {
                result += "<br><br>";
                result += "Need Help? Contact " + EmailAuthenticationProvider.AuthProviderSettings.contactPhoneNumber + ".";
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

        public AdapterPresentation(string authContext, bool isFirstTry)
        {
            this.message = string.Empty;
            this.isPermanentFailure = false;
            this.authContext = authContext;
            this.isFirstTry = isFirstTry;
        }

        public AdapterPresentation(string message, bool isPermanentFailure, string authContext)
        {
            this.message = message;
            this.isPermanentFailure = isPermanentFailure;
            this.authContext = authContext;
        }

        public AdapterPresentation(string message, bool isPermanentFailure, string authContext, bool isFirstTry)
        {
            this.message = message;
            this.isPermanentFailure = isPermanentFailure;
            this.authContext = authContext;
            this.isFirstTry = isFirstTry;
        }
    }
}
