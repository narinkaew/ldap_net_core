using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ldap_net_core.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LdapController : ControllerBase
    {
        public Task<AuthenticateResult> ValidateUser(string username, string password)
        {
            const string LDAP_PATH = "EX://exldap.example.com:5555";
            const string LDAP_DOMAIN = "exldap.example.com:5555";

            using (var context = new PrincipalContext(ContextType.Domain, LDAP_DOMAIN, "service_acct_user", "service_acct_pswd"))
            {
                if (context.ValidateCredentials(username, password))
                {
                    using (var de = new DirectoryEntry(LDAP_PATH))
                    using (var ds = new DirectorySearcher(de))
                    {
                        // other logic to verify user has correct permissions

                        // User authenticated and authorized
                        var identities = new List<ClaimsIdentity> { new ClaimsIdentity("custom auth type") };
                        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identities), Options.DefaultName);
                        return Task.FromResult(AuthenticateResult.Success(ticket));
                    }
                }
            }

            // User not authenticated
            return Task.FromResult(AuthenticateResult.Fail("Invalid auth key."));
        }

        //Novel
        //public bool ValidateUserNovel(string domainName, string username, string password)
        //{
        //    string userDn = $"{username}@{domainName}";
        //    try
        //    {
        //        using (var connection = new LdapConnection())
        //        {
        //            connection.Connect(domainName, LdapConnection.DEFAULT_PORT);
        //            connection.Bind(userDn, password);
        //            if (connection.Bound)
        //                return true;
        //        }
        //    }
        //    catch (LdapException ex)
        //    {
        //        // Log exception
        //    }
        //    return false;
        //}
    }
}