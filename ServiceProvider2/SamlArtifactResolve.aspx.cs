using System.Xml;
using ComponentPro.Saml;
using ComponentPro.Saml2;
using ComponentPro.Saml2.Binding;

namespace SamlSPInitiated.ServiceProvider
{
    public partial class SamlArtifactResolve : System.Web.UI.Page
    {
        protected override void OnLoad(System.EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                // Process the artifact resolve request received from the identity provider in response
                // to the artifact sent by the service provider.
                
                ArtifactResolve artifactResolve = ArtifactResolve.Create(Request);

                // Get the artifact.
                Saml2ArtifactType0004 httpArtifact = new Saml2ArtifactType0004(artifactResolve.Artifact.ArtifactValue);

                // Remove the artifact state from the cache.
                XmlElement artifactXml = (XmlElement)SamlSettings.CacheProvider.Remove(httpArtifact.ToString());
                if (artifactXml == null)
                    return;

                // Create an artifact response containing the cached SAML message.
                ArtifactResponse artifactResponse = new ArtifactResponse();
                artifactResponse.Issuer = new Issuer(Util.GetAbsoluteUrl(this, "~/"));
                artifactResponse.Message = artifactXml;

                // Send the artifact response.
                artifactResponse.Send(Response);
            }

            catch (System.Exception exception)
            {
                Trace.Write("ServiceProvider", "Error in artifact responder", exception);
            }
        }
    }
}