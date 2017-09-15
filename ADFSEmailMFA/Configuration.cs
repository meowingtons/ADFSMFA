using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ADFSEmailMFA
{
    public class Configuration
    {
        public class MFASettings
        {
            public string ldapConnectionString { get; set; }
            public string ldapBindUserName { get; set; }
            public string ldapBindPassword { get; set; }
            public string pinEncryptionKey { get; set; }
            public string fromEmailAddress { get; set; }
            public string fromEmailAddressName { get; set; }
            public string fromEmailAddressPassword { get; set; }
            public string mailServer { get; set; }
            public int    mailServerPort { get; set; }
            public string emailSubject { get; set; }
            public string emailBody { get; set; }
            public string logFilePath { get; set; }
            public string contactPhoneNumber { get; set; }
        }
    }
}
