using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;

/// <summary>
/// Summary description for Services
/// </summary>
public static class Services
{
#if LOCAL
    public static string LocalUri = "http://localhost:1425/"; // IdP local

    public static string[] AllowedServiceUrls = new string[]
        {
            "http://cfdev/", // Service Provider 1
            "http://localhost:1426" // Service Provider 2
        };

    public static string[] ArtifactServiceProviderUrls = new string[] 
        {
            "http://cfdev/SamlArtifactResolve.aspx", // SP1's Artifact Resolve uri
            "http://localhost:1426/SamlArtifactResolve.aspx" // SP2's Artifact Resolve uri
        };

    public static string[] LogoutServiceProviderUrls = new string[] 
        {
            "http://cfdev/SingleLogoutService.aspx", // SP1's single log out service uri
            "http://localhost:1426/SingleLogoutService.aspx"// SP2's single log out service uri
        };
#else
    public static string LocalUri = "http://idp.codeultimate.com/"; // IdP local

    public static string[] AllowedServiceUrls = new string[]
        {
            "http://sp.codeultimate.com/", // Service Provider 1
            "http://sp2.codeultimate.com/", // Service Provider 2
        };

    public static string[] ArtifactServiceProviderUrls = new string[] 
        {
            "http://sp.codeultimate.com/SamlArtifactResolve.aspx", // SP1's Artifact Resolve uri
            "http://sp2.codeultimate.com/SamlArtifactResolve.aspx", // SP2's Artifact Resolve uri
        };

    public static string[] LogoutServiceProviderUrls = new string[] 
        {
            "http://sp.codeultimate.com/SingleLogoutService.aspx", // SP1's single log out service uri
            "http://sp2.codeultimate.com/SingleLogoutService.aspx",// SP2's single log out service uri
        };
#endif
}
