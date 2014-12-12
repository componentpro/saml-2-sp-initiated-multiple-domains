using System.Security.Cryptography.X509Certificates;
using System.Web.Configuration;
using System;
using System.Web.Security;
using ComponentPro.Saml2;

namespace SamlSPInitiated.IdentityProvider
{
    public partial class SingleLogoutService : System.Web.UI.Page
    {
        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                #region Receive logout request

                X509Certificate2 x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                LogoutRequest logoutRequest = LogoutRequest.Create(Request, x509Certificate.PublicKey.Key);

                #endregion

                // Logout locally.
                FormsAuthentication.SignOut();
                Session.Abandon();

                // You can send a logout request to any other service providers here.
                // ...
                
                // Create a logout response
                LogoutResponse logoutResponse = new LogoutResponse();
                logoutResponse.Issuer = new Issuer(Util.GetAbsoluteUrl(this, "~/"));

                #region Send Logout Response

                // Look up for the appropriate logout SP url
                string referer = this.Request.UrlReferrer.AbsoluteUri;
                int i;
                for (i = 0; i < Services.AllowedServiceUrls.Length; i++)
                {
                    string url = Services.AllowedServiceUrls[i];

                    if (referer.StartsWith(url))
                        break;
                }

                if (i == Services.AllowedServiceUrls.Length)
                    throw new Exception("Your SP is not allowed");

                // Send the logout response over HTTP redirect.
                string logoutUrl = Services.LogoutServiceProviderUrls[i];
                x509Certificate = (X509Certificate2)Application[Global.SPCertKey];

                logoutResponse.Redirect(Response, logoutUrl, logoutRequest.RelayState, x509Certificate.PrivateKey);

                #endregion
            }

            catch (Exception exception)
            {
                Trace.Write("IdP", "Error in single logout service", exception);
            }
        }
    }
}