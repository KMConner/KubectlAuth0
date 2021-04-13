using System;
using System.Threading.Tasks;
using System.Text;
using System.Diagnostics;
using IdentityModel.OidcClient;
using System.Security.Cryptography;

namespace KubectlAuth0
{

    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: kubectl-auth0 Authority ClientId");
                return -1;
            }

            string authority = args[0];
            string clientId = args[1];

            OidcClientOptions options = new OidcClientOptions()
            {
                Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode,
                Authority = authority,
                ClientId = clientId,
                ResponseMode = OidcClientOptions.AuthorizeResponseMode.Redirect,
                Browser = new SystemBrowser(8088),
                RedirectUri = "http://localhost:8088",
                Scope = "profile openid email offline_access",
                LoadProfile = true,
            };
            OidcClient client = new OidcClient(options);
            await client.PrepareLoginAsync();
            LoginResult result = await client.LoginAsync();
            string nameSuffix = Convert.ToBase64String(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(clientId))).Substring(0, 5);
            

            var info = new ProcessStartInfo
            {
                FileName = "kubectl",
                Arguments = $"config set-credentials auth0-{nameSuffix} "
            };
            info.Arguments += "--auth-provider=oidc ";
            info.Arguments += $"--auth-provider-arg=idp-issuer-url={authority} ";
            info.Arguments += $"--auth-provider-arg=client-id={clientId} ";
            info.Arguments += $"--auth-provider-arg=id-token={result.IdentityToken} ";
            info.Arguments += $"--auth-provider-arg=refresh-token={result.RefreshToken}";

            var p = Process.Start(info);
            p.WaitForExit();
            return 0;
        }
    }
}
