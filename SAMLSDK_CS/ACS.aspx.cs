using System;
using System.Xml;
using SAML_Interface;

public partial class Default : System.Web.UI.Page 
{
    protected void Page_Load(object sender, EventArgs e)
    {
        SAMLResponse samlResponse = new SAMLResponse();
        XmlDocument xDoc = samlResponse.ParseSAMLResponse(Request.Form["SAMLResponse"]);

        if (samlResponse.IsResponseValid(xDoc))
        {
            Response.Write("SAML Response from IDP Was Accepted. Authenticated user is " + samlResponse.ParseSAMLNameID(xDoc));
        }
        else
        {
            Response.Write("SAML Response from IDP Was Not Accepted");
        }
    }
}
