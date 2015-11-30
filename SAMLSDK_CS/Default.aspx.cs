using System;
using System.Configuration;
using SAML_Interface;

public partial class Default : System.Web.UI.Page
{
    public static string ACSURL = ConfigurationManager.AppSettings["ACSUrl"].ToString();
    public static string Issuer = ConfigurationManager.AppSettings["Issuer"].ToString();
    public static string IdentityProviderSigninURL = ConfigurationManager.AppSettings["IdentityProviderSigninURL"].ToString();
    protected void Page_Load(object sender, EventArgs e)
    {
        SAMLRequest request = new SAMLRequest();
        Response.Redirect(IdentityProviderSigninURL + "?SAMLRequest=" + Server.UrlEncode(request.GetSAMLRequest(ACSURL, Issuer)));
    }
}
