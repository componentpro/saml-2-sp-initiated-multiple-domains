using System.Xml;
using System;
using ComponentPro.Saml;
using ComponentPro.Saml2;
using ComponentPro.Saml2.Binding;

namespace SamlSPInitiated.IdentityProvider
{
    public partial class SamlArtifactResolve : System.Web.UI.Page
    {
        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                // Receive the artifact resolve request.
                ArtifactResolve artifactResolve = ArtifactResolve.Create(Request);

                // Get the artifact.
                Saml2ArtifactType0004 httpArtifact = new Saml2ArtifactType0004(artifactResolve.Artifact.ArtifactValue);

                // Remove the artifact state from the cache.
                XmlElement samlResponseXml = (XmlElement)SamlSettings.CacheProvider.Remove(httpArtifact.ToString());
                
                if (samlResponseXml == null) return;

                // Create an artifact response containing the cached SAML message.
                ArtifactResponse artifactResponse = new ArtifactResponse();
                artifactResponse.Issuer = new Issuer(new Uri(Request.Url, ResolveUrl("~/")).ToString());
                artifactResponse.Message = samlResponseXml;

                // Send the artifact response.
                artifactResponse.Send(Response);
            }
            catch (Exception exception)
            {
                Trace.Write("ServiceProvider", "An Error occurred", exception);
            }
        }
    }
}