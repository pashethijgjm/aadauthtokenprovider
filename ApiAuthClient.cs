using Microsoft.Graph.Auth;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AuthenticationResult = Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult;

namespace Sas.AADAuth.TokenProvider
{
    public class ApiAuthClient
    {
        private ApiAuthClientOptions _authOptions;

        public ApiAuthClient(ApiAuthClientOptions authOptions)
        {
            _authOptions = authOptions;
        }

        public string Token
        {
            get
            {
                var authenticationResult = ClientAppBuilder.AcquireTokenForClient(Scopes).ExecuteAsync();

                return authenticationResult.Result.AccessToken;
            }
        }

        private string TenantId
        {
            get
            {
                return _authOptions.TenantId;
            }
        }

        private string ClientId
        {
            get
            {
                return _authOptions.ApplicationId;
            }
        }

        private string Authority
        {
            get
            {
                return _authOptions.Authority;
            }
        }

        private string Resource
        {
            get
            {
                return _authOptions.Resource;
            }
        }

        private string[] Scopes
        {
            get
            {
                return new[] { Resource + "/.default" };
            }
        }

        private string ClientSecret
        {
            get
            {
                return _authOptions.ClientSecret;
            }
        }

        private ClientCertCredential ClientCertCredentials
        {
            get
            {
                return _authOptions.ClientCertCredentials;
            }
        }


        private IConfidentialClientApplication ClientAppBuilder
        {
            get
            {
                return GetConfidentialClientApplicationBuilder();
            }
        }

        public ClientCredentialProvider ClientCredentialProvider
        {
            get
            {
                return new Microsoft.Graph.Auth.ClientCredentialProvider(ClientAppBuilder, $"{Resource}/.default");
            }
        }

        private IConfidentialClientApplication GetConfidentialClientApplicationBuilder()
        {
            if (_authOptions == null) return null;

            IConfidentialClientApplication builder;
            switch (_authOptions.CredentialType)
            {
                case ClientCredentialType.ClientSecret:
                    builder = ConfidentialClientApplicationBuilder
                            .Create(ClientId)
                            .WithAuthority(Authority)
                            .WithTenantId(TenantId)
                            .WithClientSecret(ClientSecret)
                            .Build();
                    break;
                case ClientCredentialType.ClientCert:
                    var cert = LoadCertificateFromLocalMachineStore();

                    builder = ConfidentialClientApplicationBuilder
                        .Create(ClientId)
                        .WithTenantId(TenantId)
                        .WithAuthority(Authority)
                        .WithCertificate(cert)
                        .Build();
                    break;
                default:
                    throw new ArgumentException("Invalid Client Credentials.");
            }
            return builder;
        }

        private X509Certificate2 LoadCertificateFromLocalMachineStore()
        {
            using (X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                certStore.Open(OpenFlags.ReadOnly);
                X509FindType findType = X509FindType.FindByThumbprint;
                object findValue = ClientCertCredentials.Thumbprint;

                if (!string.IsNullOrEmpty(ClientCertCredentials.SubjectName))
                {
                    findType = X509FindType.FindBySubjectDistinguishedName;
                    findValue = new X500DistinguishedName($"CN={ClientCertCredentials.SubjectName}", X500DistinguishedNameFlags.None).Format(false);
                }

                X509Certificate2Collection certificateCollection = certStore.Certificates.Find(findType, findValue, ClientCertCredentials.ValidOnly);

                X509Certificate2 certificate = null;

                if (certificateCollection.Count > 0)
                {
                    certificate = certificateCollection.Cast<X509Certificate2>().OrderByDescending(x => x.NotAfter).FirstOrDefault();

                    _authOptions.Logger.Info($"Fetched certificate from local cert store. SubjectName: {ClientCertCredentials.SubjectName}, Thumbprint: {certificate?.Thumbprint}, Expiry: {certificate?.GetExpirationDateString()}.");
                }
                else 
                { 
                    _authOptions.Logger.Info($"No valid certificate present in local cert store. SubjectName: {ClientCertCredentials.SubjectName}.");
                }

                certStore.Close();

                return certificate;
            }
        }
    }
}
