using System;
using System.Web;
using System.IO;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace SAML_Interface 
{
    public class SAMLResponse
    {
        public XmlDocument ParseSAMLResponse(string strEncodedSAMLResponse)
        {
            System.Text.ASCIIEncoding encencoder = new System.Text.ASCIIEncoding();
            string strCleanResponse = encencoder.GetString(Convert.FromBase64String(strEncodedSAMLResponse));

            XmlDocument xDoc = new XmlDocument();
            xDoc.PreserveWhitespace = true;
            xDoc.XmlResolver = null;
            xDoc.LoadXml(strCleanResponse);

            return xDoc;
        }
        public bool IsResponseValid(XmlDocument xDoc)
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            XmlNodeList nodeList = xDoc.SelectNodes("//ds:Signature", manager);

            SignedXml signedXml = new SignedXml(xDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            X509Certificate2 cSigningCertificate = new X509Certificate2();

            cSigningCertificate.Import(HttpContext.Current.Server.MapPath(".") + @"\Certificates\SigningCertificate.cer");

            return signedXml.CheckSignature(cSigningCertificate, true);
        }

        public string ParseSAMLNameID(XmlDocument xDoc)
        {
            XmlNamespaceManager xManager = new XmlNamespaceManager(xDoc.NameTable);
            xManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            xManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            XmlNode node = xDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", xManager);
            return node.InnerText;
        }
    }

    public class SAMLRequest
    {
        public string GetSAMLRequest(string strACSUrl, string strIssuer)
        {
            using (StringWriter SWriter = new StringWriter())
            {
                XmlWriterSettings xWriterSettings = new XmlWriterSettings();
                xWriterSettings.OmitXmlDeclaration = true;

                using (XmlWriter xWriter = XmlWriter.Create(SWriter, xWriterSettings))
                {
                    xWriter.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xWriter.WriteAttributeString("ID", "_" + System.Guid.NewGuid().ToString());
                    xWriter.WriteAttributeString("Version", "2.0");
                    xWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
                    xWriter.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                    xWriter.WriteAttributeString("AssertionConsumerServiceURL", strACSUrl);

                    xWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xWriter.WriteString(strIssuer);
                    xWriter.WriteEndElement();

                    xWriter.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xWriter.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
                    xWriter.WriteAttributeString("AllowCreate", "true");
                    xWriter.WriteEndElement();

                    xWriter.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xWriter.WriteAttributeString("Comparison", "exact");
                    xWriter.WriteEndElement();

                    xWriter.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xWriter.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                    xWriter.WriteEndElement();

                    xWriter.WriteEndElement();
                }

                byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(SWriter.ToString());
                return System.Convert.ToBase64String(toEncodeAsBytes);           
            }
        }

        public string GetSAMLLogoutRequest(string destinationUrl,
                                            string issuer,
                                            string nameIDFormat,
                                            string nameID)
        {
            string SAML20_LogoutRequest_FORMAT =
                "<samlp:LogoutRequest " +
                        "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
                        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
                        "ID =\"_{0}\" " +
                        "Version =\"2.0\" " +
                        "IssueInstant =\"{1:yyyy-MM-ddTHH:mm:ss.000Z}\" " +
                        "Destination =\"{2}\" " +
                        "NotOnOrAfter=\"{3:yyyy-MM-ddTHH:mm:ss.000Z}\" " +
                        "Reason=\"urn:oasis:names:tc:SAML:2.0:logout:user\" " +
                        "Consent=\"urn:oasis:names:tc:SAML:2.0:consent:obtained\">" +
                    "<saml:Issuer>" +
                        "{4}" +
                    "</saml:Issuer>" +
                    "<saml:NameID " +
                        "Format=\"{5}\">" +
                        "{6}" +
                    "</saml:NameID>" +
                "</samlp:LogoutRequest>";

            var logoutRequest = string.Format(SAML20_LogoutRequest_FORMAT,
                    Guid.NewGuid().ToString(),
                    DateTime.UtcNow,
                    destinationUrl,
                    DateTime.UtcNow + TimeSpan.FromHours(1),
                    issuer,
                    nameIDFormat, //"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                    nameID //test@elections.ny.gov
                 );
            using (var ms = new MemoryStream())
            using (var ds = new DeflateStream(ms, CompressionMode.Compress))
            {
                var b = UTF8Encoding.UTF8.GetBytes(logoutRequest);
                ds.Write(b, 0, b.Length);
                logoutRequest = "SAMLRequest=" + HttpUtility.UrlEncode(Convert.ToBase64String(ms.ToArray()));
            }

            Console.WriteLine("Logout request payload is {0} ", logoutRequest);
            return logoutRequest;
        }
    }    
}
