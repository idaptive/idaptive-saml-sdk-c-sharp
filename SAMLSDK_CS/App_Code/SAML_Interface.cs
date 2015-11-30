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

            cSigningCertificate.Import(HttpContext.Current.Server.MapPath(".") + @"\Certificates\SignCertFromCentrify.cer");

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

                byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(SWriter.ToString());
                return System.Convert.ToBase64String(toEncodeAsBytes);           
            }
        }
    }    
}
