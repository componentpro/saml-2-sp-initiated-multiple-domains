using System;
using System.Web.Configuration;
using System.Diagnostics;
using System.Web.UI;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using ComponentPro.Saml;
using ComponentPro.Saml.Binding;
using ComponentPro.Saml2;
using ComponentPro.Saml2.Binding;

namespace SamlSPInitiated.IdentityProvider
{
    public class Util
    {
        // The query string parameter identifying the SP to IdP binding in use.
        private const string BindingQueryParameter = "binding";

        public static string GetAbsoluteUrl(Page page, string relativeUrl)
        {
            return new Uri(page.Request.Url, page.ResolveUrl(relativeUrl)).ToString();
        }

        // Receive the authentication request from the service provider.
        public static void ReceiveAuthnRequest(Page page, out AuthnRequest authnRequest, out string relayState)
        {
            // Determine the service provider to identity provider binding type.
            // We use a query string parameter rather than having separate endpoints per binding.
            string bindingType = page.Request.QueryString[BindingQueryParameter];

            switch (bindingType)
            {
                case SamlBindingUri.HttpRedirect:
                    X509Certificate2 x509Certificate = (X509Certificate2)page.Application[Global.SPCertKey];

                    authnRequest = AuthnRequest.Create(page.Request.RawUrl, x509Certificate.PublicKey.Key);
                    relayState = authnRequest.RelayState;
                    break;

                case SamlBindingUri.HttpPost:
                    authnRequest = AuthnRequest.CreateFromHttpPost(page.Request);
                    relayState = authnRequest.RelayState;
                    break;

                case SamlBindingUri.HttpArtifact:
                    // Receive the artifact.
                    Saml2ArtifactType0004 httpArtifact = Saml2ArtifactType0004.CreateFromHttpArtifactQueryString(page.Request);

                    // Create an artifact resolve request.
                    ArtifactResolve artifactResolve = new ArtifactResolve();
                    artifactResolve.Issuer = new Issuer(Util.GetAbsoluteUrl(page, "~/"));
                    artifactResolve.Artifact = new Artifact(httpArtifact.ToString());

                    // Look up for the appropriate artifact SP url
                    string referer = page.Request.UrlReferrer.AbsoluteUri;
                    int i;
                    for (i = 0; i < Services.AllowedServiceUrls.Length; i++)
                    {
                        string url = Services.AllowedServiceUrls[i];

                        if (referer.StartsWith(url))
                            break;
                    }

                    if (i == Services.AllowedServiceUrls.Length)
                        throw new Exception("Your SP is not allowed");

                    // Send the artifact resolve request and receive the artifact response.
                    string artifactServiceProviderUrl = Services.ArtifactServiceProviderUrls[i];

                    ArtifactResponse artifactResponse = ArtifactResponse.SendSamlMessageReceiveAftifactResponse(artifactServiceProviderUrl, artifactResolve);

                    // Extract the authentication request from the artifact response.
                    authnRequest = new AuthnRequest(artifactResponse.Message);
                    relayState = httpArtifact.RelayState;
                    break;

                default:
                    Trace.Write("IdentityProvider", "Invalid service provider to identity provider binding");
                    authnRequest = null;
                    relayState = null;
                    return;

            }

            // If using HTTP redirect the message isn't signed as the generated query string is too long for most browsers.
            if (bindingType != SamlBindingUri.HttpRedirect)
            {
                if (authnRequest.IsSigned())
                {
                    // Verify the request's signature.
                    X509Certificate2 x509Certificate = (X509Certificate2)page.Application[Global.SPCertKey];

                    if (!authnRequest.Validate(x509Certificate))
                    {
                        throw new ApplicationException("The authentication request signature failed to verify.");
                    }
                }
            }
        }

        // Create a SAML response with the user's local identity, if any, or indicating an error.
        public static ComponentPro.Saml2.Response CreateSamlResponse(Page page)
        {
            ComponentPro.Saml2.Response samlResponse = new ComponentPro.Saml2.Response();
            string issuerUrl = Util.GetAbsoluteUrl(page, "~/");

            samlResponse.Issuer = new Issuer(issuerUrl);

            if (page.User.Identity.IsAuthenticated)
            {
                samlResponse.Status = new Status(SamlPrimaryStatusCode.Success, null);

                Assertion samlAssertion = new Assertion();

                samlAssertion.Subject = new Subject(new NameId(page.User.Identity.Name));
                samlAssertion.Statements.Add(new AuthnStatement());
                samlResponse.Assertions.Add(samlAssertion);
            }
            else
            {
                samlResponse.Status = new Status(SamlPrimaryStatusCode.Responder, SamlSecondaryStatusCode.AuthnFailed, "The user is not authenticated at the identity provider");
            }

            return samlResponse;
        }

        // Send the SAML response over the specified binding.
        public static void SendSamlResponse(Page page, ComponentPro.Saml2.Response samlResponse, SsoAuthnState ssoState)
        {
            // Sign the SAML response 
            X509Certificate2 x509Certificate = (X509Certificate2)page.Application[Global.IdPCertKey];

            samlResponse.Sign(x509Certificate);

            // Send the SAML response to the service provider.
            switch (ssoState.IdpProtocolBinding)
            {
                case SamlBinding.HttpPost:
                    samlResponse.SendPostBindingForm(page.Response.OutputStream, ssoState.AssertionConsumerServiceURL, ssoState.RelayState);
                    break;

                case SamlBinding.HttpArtifact:
                    // Create the artifact.
                    string identificationUrl = Util.GetAbsoluteUrl(page, "~/");
                    Saml2ArtifactType0004 httpArtifact = new Saml2ArtifactType0004(SamlArtifact.GetSourceId(identificationUrl), SamlArtifact.GetHandle());

                    // Cache the authentication request for subsequent sending using the artifact resolution protocol. Sliding expiration time is 1 hour.
                    SamlSettings.CacheProvider.Insert(httpArtifact.ToString(), samlResponse.GetXml(), new TimeSpan(1, 0, 0));

                    // Send the artifact.
                    httpArtifact.SendPostForm(page.Response.OutputStream, ssoState.AssertionConsumerServiceURL,
                                              ssoState.RelayState);
                    break;

                default:
                    Trace.Write("IdentityProvider", "Invalid identity provider binding");
                    break;
            }
        }
    }
}