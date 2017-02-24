# CentrifySAMLSDK_CS

This is an example on adding SAML to your ASP.NET/C# web application. To use this demo from Visual Studio you will need 
a Signing Certificate from a Centrify Generic SAML Application, and the endpoint URL's from the Centrify Generic SAML Application.

To use this example:

In the Centrify Cloud Manager, click on Apps, Add Web Apps, Custom, Generic SAML Application.

In the Centrify Cloud Manager, in the Generic SAML Application settings, click Download Signing Certificate under Application Settings.

In the Centrify Cloud Manager, in the Generic SAML Application settings, copy the Identity Provider URL under Application Settings.

In Visual Studio, remove the sample Signing Certificate in the project and replace it with the Certificate downloaded from the Generic SAML Application.

In Visual Studio, modify the SAML_Interface.cs file at line 35 (cSigningCertificate.Import(HttpContext.Current.Server.MapPath(".") + @"\Certificates\SignCertFromCentrify.cer");) and make the path to the cert file point to your file downloaded from Centrify.

In Visual Studio, modify the web.config file with your applications Issuer and Identity Provider Sign-in URL from the Generic SAML Application.

In the Centrify Cloud Manager, in the Generic SAML Application settings, make the ACS URL the URL to your localhost and the ACS.aspx page (example would be http://localhost:7180/ACS.aspx).

In the Centrify Cloud Manager, deploy the Generic SAML Application.

Click debug in Visual Studio. If you navigate to Default.aspx, you will start SP Initiated SAML SSO. If you go the User Portal and click the Generic SAML Application you will start IDP Initiated SAML SSO.
