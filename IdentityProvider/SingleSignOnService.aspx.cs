using System;
using ComponentPro.Saml2;

namespace SamlSPInitiated.IdentityProvider
{
    public partial class SingleSignOnService : System.Web.UI.Page
    {
        // The session key for saving the SSO state during a local login.
        private const string SsoSessionKey = "sso";        

        

        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                // Look up for the SP ID
                string referer = this.Request.UrlReferrer.AbsoluteUri;
                int i = -1;
                if (!referer.StartsWith(Services.LocalUri))
                {
                    for (i = 0; i < Services.AllowedServiceUrls.Length; i++)
                    {
                        string url = Services.AllowedServiceUrls[i];

                        if (referer.StartsWith(url))
                            break;
                    }

                    if (i == Services.AllowedServiceUrls.Length)
                        throw new Exception("Your SP is not allowed");
                }

                // Get the saved SSO state, if any.
                // If there isn't saved state then receive the authentication request.
                // If there is saved state then we've just completed a local login in response 
                // to a prior authentication request.
                SsoAuthnState ssoState = (SsoAuthnState)Session[SsoSessionKey];

                // Receive the authentication request.
                AuthnRequest authnRequest = null;
                string relayState = null;

                if (i != -1)
                {
                    Util.ReceiveAuthnRequest(this, out authnRequest, out relayState);

                    if (authnRequest == null)
                    {
                        // No authentication request found.
                        return;
                    }
                }

                if (ssoState == null)
                {
                    // Process the authentication request.
                    bool forceAuthn = authnRequest.ForceAuthn;
                    bool allowCreate = false;

                    if (authnRequest.NameIdPolicy != null)
                    {
                        allowCreate = authnRequest.NameIdPolicy.AllowCreate;
                    }

                    ssoState = new SsoAuthnState();
                    ssoState.AuthnRequest = authnRequest;
                    ssoState.RelayState = relayState;
                    ssoState.IdpProtocolBinding = SamlBindingUri.UriToBinding(authnRequest.ProtocolBinding);
                    ssoState.AssertionConsumerServiceURL = authnRequest.AssertionConsumerServiceUrl;

                    // Determine whether or not a local login is required.
                    bool requireLocalLogin = false;
                    
                    if (forceAuthn)
                    {
                        requireLocalLogin = true;
                    }
                    else
                    {
                        if (!User.Identity.IsAuthenticated & allowCreate)
                        {
                            requireLocalLogin = true;
                        }
                    }

                    // If a local login is required then save the authentication request 
                    // and initiate a local login.
                    if (requireLocalLogin)
                    {
                        // Save the SSO state.
                        Session[SsoSessionKey] = ssoState;

                        // Initiate a local login.
                        System.Web.Security.FormsAuthentication.RedirectToLoginPage();
                        return;
                    }
                }

                // Create a SAML response with the user's local identity, if any.
                ComponentPro.Saml2.Response samlResponse = Util.CreateSamlResponse(this);

                if (i != -1)
                    // Update the Relay state before sending SAML response.
                    // Dynamically update the assertion consumer service URL corresponding to the service provider.
                    ssoState.AssertionConsumerServiceURL = authnRequest.AssertionConsumerServiceUrl;

                // Send the SAML response to the service provider.
                Util.SendSamlResponse(this, samlResponse, ssoState);
            }

            catch (Exception exception)
            {
                Trace.Write("IdentityProvider", "An Error occurred", exception);
            }
        }
    }
}