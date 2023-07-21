using Common.Logger;

namespace Sas.AADAuth.TokenProvider
{
    public enum ClientCredentialType
    {
        Unknown = 0,
        ClientSecret = 1,
        ClientCert=2
        
    }

    public class ClientCertCredential
    {
        public string SubjectName { get; set; }
        public string StoreName { get; set; }
        public string StoreLocation { get; set; }
        public string Thumbprint { get; set; }
        public bool ValidOnly { get; set; }
    }

    public class ApiAuthClientOptions
    {
        public string TenantId { get; set; }
        public string ApplicationId { get; set; }
        public string Authority { get; set; }
        public string Resource { get; set; }
        public ClientCredentialType CredentialType { get; set; }
        public ILogger Logger { get; set; }

        public string ClientSecret { get; set; }

        public ClientCertCredential ClientCertCredentials { get; set; }

    }
}
