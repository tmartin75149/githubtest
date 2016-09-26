package com.jericho.sts.claims.handler;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import mil.osd.dmdc.ctis.eias.util.DOMUtil;
import mil.osd.dmdc.ctis.eias.util.SignUtils;

import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.sts.claims.Claim;
import org.apache.cxf.sts.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.RequestClaimCollection;
import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.jericho.helper.SSLUtils;
import com.jericho.helper.XMLHelper;

public class EiasCliamsHandler implements ClaimsHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(EiasCliamsHandler.class);
    private static final List<String> RFC_2253_ATTR_TYPE_KEYWORDS = Arrays.asList(new String[] { "CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID" });
//    private static final String DIGITAL_IDENTIFIER_CLAIM_TYPE = "DigitalIdentifier";
//    private static final String COUNTRY_OF_AFFILIATION_CLAIM_TYPE = "CountryOfAffiliation";
//    private static final String CLEARANCE_CLAIM_TYPE = "Clearance";
//    private static final String FINE_ACCESS_CONTROLS_CLAIM_TYPE = "FineAccessControls";
    
    private String externalAttributeStoreUrl;
    private String signCertPassword;
    private String signCertPathField;
    private String signCertAliasField;
    private String keyStoreFile;
    private String keyStorePassword;
    private String keyStoreType;
    private String trustStoreFile;
    private String trustStorePassword;
    private String trustStoreType;
    
    private String[] eiasAttributes = {"DOD_EDI_PN_ID", "US_CTZP_STAT_CD", "CTZP_CTRY_CD", "PERSONA_TYP_CD", "ADM_ORG_CD", "PAY_PLN_CD", "PG_CD", "DUTY_DOD_OCC_CD"};
    
    private String eiasEndpoint;
    
    public String getSignCertPassword() {
        return signCertPassword;
    }

    public void setSignCertPassword(String signCertPassword) {
        this.signCertPassword = signCertPassword;
    }

    public String getSignCertPathField() {
        return signCertPathField;
    }

    public void setSignCertPathField(String signCertPathField) {
        this.signCertPathField = signCertPathField;
    }

    public String getSignCertAliasField() {
        return signCertAliasField;
    }

    public void setSignCertAliasField(String signCertAliasField) {
        this.signCertAliasField = signCertAliasField;
    }


    
    
    public void setAttributeStoreUrl(String externalAttributeStoreUrl) {
        LOGGER.debug("Setting URL to {}", externalAttributeStoreUrl);
        this.externalAttributeStoreUrl = externalAttributeStoreUrl;
    }

    public String getAttributeStoreUrl() {
        return this.externalAttributeStoreUrl;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getTrustStoreFile() {
        return trustStoreFile;
    }

    public void setTrustStoreFile(String trustStoreFile) {
        this.trustStoreFile = trustStoreFile;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public String getEiasEndpoint() {
        return eiasEndpoint;
    }

    public void setEiasEndpoint(String eiasEndpoint) {
        this.eiasEndpoint = eiasEndpoint;
    }

    public EiasCliamsHandler() {
        // TODO Auto-generated constructor stub
    }

    @Override
    public List<URI> getSupportedClaimTypes() {
        LOGGER.debug("Getting supported claim types.");
        List<URI> supportedClaimTypes = new ArrayList();
        try {
//            supportedClaimTypes.add(new URI("CountryOfAffiliation"));
//            supportedClaimTypes.add(new URI("Clearance"));
//            supportedClaimTypes.add(new URI("FineAccessControls"));
//        	supportedClaimTypes.add(new URI("DOD_EDI_PN_ID"));
//        	supportedClaimTypes.add(new URI("US_CTZP_STAT_CD"));
//        	supportedClaimTypes.add(new URI("CTZP_CTRY_CD"));
//        	supportedClaimTypes.add(new URI("PERSONA_TYP_CD"));
//        	supportedClaimTypes.add(new URI("ADM_ORG_CD"));
//        	supportedClaimTypes.add(new URI("PAY_PLN_CD"));
//        	supportedClaimTypes.add(new URI("PG_CD"));
//        	supportedClaimTypes.add(new URI("DUTY_DOD_OCC_CD"));
        	
        	for (int i=0;i<eiasAttributes.length;i++) {
        		supportedClaimTypes.add(new URI(eiasAttributes[i]));
        	}
        	
        } catch (URISyntaxException e) {
            LOGGER.error("Error getting supported claim types for external attribute store.", e);
        }
        return supportedClaimTypes;
    }

    @Override
    public ClaimCollection retrieveClaimValues(RequestClaimCollection claims, ClaimsParameters parameters) {
        Principal principal = parameters.getPrincipal();
        String dn = null;

        if (principal == null) {
            LOGGER.debug("Returning empty Cliams since the principal is null");
            return new ClaimCollection();
        }

        LOGGER.debug("The principal is an instance of [{}].", principal.getClass().getName());
        if ((principal instanceof SAMLTokenPrincipal)) {
            SAMLTokenPrincipal samlTokenPrincipal = (SAMLTokenPrincipal) principal;
            AssertionWrapper samlAssertion = samlTokenPrincipal.getToken();
            if (LOGGER.isDebugEnabled()) {
                // LOGGER.debug("\nSAML Assertion:\n" +
                // DOM2Writer.nodeToString(samlAssertion.getElement()) + "\n");
                // SecurityLogger.logDebug("\nSAML Assertion:\n" +
                // DOM2Writer.nodeToString(samlAssertion.getElement()) + "\n" +
                // this.externalAttributeStoreUrl + ":" + this.diasPort);
            }
            Attribute dnAttribute = getDnAttributeFromSaml(samlAssertion);
            if (dnAttribute != null) {
                dn = getDnAttributeAsString(dnAttribute);
                LOGGER.debug("DN from SAML assertion [{}].", dn);
            } else {
                LOGGER.error("Unable to retrieve attributes from external attribute store.  Unable to find {} in SAML asssertion claims.", "DigitalIdentifier");
                // SecurityLogger.logWarn("Unable to retrieve attributes from external attribute store.  Unable to find DigitalIdentifier in SAML asssertion claims. "
                // + this.externalAttributeStoreUrl + ":" + this.diasPort);
            }
        } else if ((principal instanceof X500Principal)) {
            X500Principal x500Principal = (X500Principal) principal;
            try {
                dn = getRfc2253CompliantDn(x500Principal.getName()).toString();
                LOGGER.debug("RFC 2253 compliant LDAP DN from certificate [{}].", dn);
                // SecurityLogger.logInfo("RFC 2253 compliant LDAP DN from certificate ["
                // + dn + "]." + this.externalAttributeStoreUrl + ":" +
                // this.diasPort);
            } catch (InvalidNameException e) {
                LOGGER.error("Cannot construct RFC 2253 compliant LDAP DN from supplied LDAP DN [{}].", x500Principal.getName());
                // SecurityLogger.logWarn("Cannot construct RFC 2253 compliant LDAP DN from supplied LDAP DN ["
                // + x500Principal.getName() + "].");
            }
        } else {
            String name = principal.getName();
            dn = isValidLdapName(name) ? name : null;
        }
        
        String ediPI = "1000000000";
        StringTokenizer dnST = new StringTokenizer(",");
        if (dnST.countTokens()>0) {
            String cnToken = dnST.nextToken();
            StringTokenizer cnST = new StringTokenizer("=");
            if (cnST.countTokens()>0) {
                String cnValue = cnST.nextToken();
                StringTokenizer cnValueST = new StringTokenizer(".");
                if (cnST.countTokens()>0) {
                    while (cnValueST.hasMoreTokens()) {
                        ediPI = cnValueST.nextToken();
                    }
                }
            }
        }
        
        ClaimCollection claimCollection = null;
        try {
            if (!StringUtils.isEmpty(dn)) {
                claimCollection = retrieveExternalClaimValues(dn);
            }
        } catch (URISyntaxException e) {
            LOGGER.error("Error retrieving attributes from external attribute store [" + this.externalAttributeStoreUrl + "] for DN [" + dn + "].", e);
            // SecurityLogger.logError("Error retrieving attributes from external attribute store ["
            // + this.externalAttributeStoreUrl + "] for DN [" + dn + "].");
        }
        return claimCollection != null ? claimCollection : new ClaimCollection();
    }
    
    private ClaimCollection retrieveExternalClaimValues(String ediPI) throws URISyntaxException {
        ClaimCollection claimCollection = new ClaimCollection();

        ClaimCollection securityClaimCollection = getSecurityAttributes(ediPI);
        claimCollection.addAll(securityClaimCollection);

        return claimCollection;
    }
    
    private ClaimCollection getSecurityAttributes(String ediPI) throws URISyntaxException {
        LOGGER.debug("getSecurityAttributes-287: ediPI = " + ediPI);
        ClaimCollection claimCollection = new ClaimCollection();
        // TODO
        try {
            // Create a SAML Attribute Query Request (XML Document) to fetch user attributes from EIAS Attribute Service
            // Set the ediPI and the Subject NameID
            String requestStr = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xd=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xe=\"http://www.w3.org/2001/04/xmlenc#\"> <soapenv:Header/> <soapenv:Body> <samlp:AttributeQuery ID=\"1234\" Version=\"2.0\" IssueInstant=\"2013-10-31T12:13:14.156Z\" Destination=\"urn:mil:osd:dmdc:eias\"> <saml:Issuer>urn:mil:dod:test:deias</saml:Issuer> <saml:Subject> <saml:NameID>";
            requestStr += ediPI;
            requestStr += "</saml:NameID> </saml:Subject> </samlp:AttributeQuery> </soapenv:Body> </soapenv:Envelope>";
            LOGGER.debug("296:requestStr = " + requestStr);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document requestDoc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(requestStr.getBytes()));

            // Sign (XML Signature of the AttributeQuery element) the Request (Configure Keystore for Signing)
            String signedAttributeRequest = addSignature(requestDoc);
            
            // Post the request to EIAS endpoint (Configure Keystore/Truststore for Mutual AuthN SSL connection
            String responseFromEIAS = sendRequestToEIAS(signedAttributeRequest, eiasEndpoint);
            LOGGER.debug("311:responseFromEIAS = "+ responseFromEIAS);
//            DocumentBuilder db = dbf.newDocumentBuilder();
//            InputSource is = new InputSource();
//            is.setCharacterStream(new StringReader(responseFromEIAS));
//            Document responseEIASDoc = db.parse(is);
            Document responseEIASDoc = XMLHelper.loadXMLFrom(responseFromEIAS);
            responseEIASDoc.getDocumentElement().normalize();
            LOGGER.debug("317:Document built");
            
            // Populate claimCollection with each attribute in the incoming assertion as the requested claim
        	for (int i=0;i<eiasAttributes.length;i++) {
        		Claim claim = fetchClaim(responseEIASDoc,eiasAttributes[i]);
                if ( claim != null) {
                		//claimCollection.add((Claim)claimString);
                	claimCollection.add(claim);	
                }
        	}

        } catch (SAXException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return claimCollection;
    }
    
    
    private Claim fetchClaim(Document response, String claimType) throws URISyntaxException {
    	Claim claim = new Claim();
    	claim.setClaimType(new URI(claimType));
    	
    	Element root = response.getDocumentElement();
    	NodeList nodes = response.getElementsByTagName("saml:Attribute");
    	LOGGER.debug("353: Number of saml:Attribute tags found = "+ nodes.getLength());
    	LOGGER.debug("354 Iternate through all the nodes looking for claim type");
    	for( int i=0; i<nodes.getLength(); i++) {
    		Node node = nodes.item(i);
    		if(node.getNodeType() == Node.ELEMENT_NODE) {
    			Element eElement = (Element)node;
    			String docValue = eElement.getAttribute("Name");
    			if(claimType != docValue) {
    				continue;
    			}
    			else {
    				//claimType Found
    				int attributeLength = eElement.getElementsByTagName("saml:AttributeValue").getLength();
    				LOGGER.debug("363: Number of Attribute Values found for claimType "+ claimType + " = " + attributeLength);
    				NodeList attributeValue = eElement.getElementsByTagName("saml:AttributeValue");
    				for(int j=0; j< attributeLength; j++) {
    					// add each entry to the claim object
    					String attrData = eElement.getElementsByTagName("saml:AttributeValue").item(j).getTextContent();
    					claim.addValue(attrData);
    				}
    			}
    			
    		}
    	}
    	return claim;
    }
    
    
    private boolean isValidLdapName(String name) {
        boolean isValid = false;
        try {
            LdapName ldapName = new LdapName(name);
            LOGGER.debug("Supplied LDAP name of [{}] is valid.", ldapName.toString());
            // SecurityLogger.logInfo("Supplied LDAP name of [" +
            // ldapName.toString() + "] is valid.");
            isValid = true;
        } catch (InvalidNameException e) {
            LOGGER.warn("Cannot parse supplied LDAP name [{}].  It must be a username.", name);
            isValid = false;
        }
        return isValid;
    }
    
    private LdapName getRfc2253CompliantDn(String dn) throws InvalidNameException {
        LdapName ldapName = new LdapName(dn);
        List<Rdn> rdns = ldapName.getRdns();
        for (int i = 0; i < rdns.size(); i++) {
            if (!RFC_2253_ATTR_TYPE_KEYWORDS.contains(ldapName.getRdn(i).getType().toUpperCase())) {
                ldapName.remove(i);
            }
        }
        return ldapName;
    }
    
    private String getDnAttributeAsString(Attribute dnAttribute) {
        String dnAttributeValue = null;
        if (dnAttribute != null) {
            List<XMLObject> attributeValues = dnAttribute.getAttributeValues();
            if (attributeValues.size() == 1) {
                Element element = ((XMLObject) attributeValues.get(0)).getDOM();
                if (element != null) {
                    dnAttributeValue = element.getTextContent();
                    LOGGER.debug("DN to be used to search external attribute store [{}]. ", dnAttributeValue);
                }
            } else if (attributeValues.size() > 1) {
                LOGGER.warn("Found {} attribute values for {} attribute in SAML assertion. Unable to create string from attribute.", Integer.valueOf(attributeValues.size()), "DigitalIdentifier");
            } else if (attributeValues.size() == 0) {
                LOGGER.warn("Attribute {} of SAML assertion contains 0 attribute values. Unable to create string from attribute.", "DigitalIdentifier");
            }
        } else {
            LOGGER.debug("Supplied {} attribute is null. Unable to create string from attribute.", "DigitalIdentifier");
        }
        return dnAttributeValue;
    }
    
    private Attribute getDnAttributeFromSaml(AssertionWrapper samlAssertion) {
        LOGGER.debug("Number of attribute statements [{}].", Integer.valueOf(samlAssertion.getSaml2().getAttributeStatements().size()));

        List<Attribute> attributes = ((AttributeStatement) samlAssertion.getSaml2().getAttributeStatements().get(0)).getAttributes();
        boolean found = false;
        Attribute dnAttribute = null;

        LOGGER.debug("Searching for [{}]  atribute in SAML assertion.", "DigitalIdentifier");
        for (int i = 0; (i < attributes.size()) && (!found); i++) {
            Attribute attribute = (Attribute) attributes.get(i);
            if (attribute.getName().equals("DigitalIdentifier")) {
                found = true;
                dnAttribute = attribute;
                LOGGER.debug("DigitalIdentifier name [" + attribute.getName() + "]; value [" + ((XMLObject) attribute.getAttributeValues().get(0)).getDOM().getTextContent() + "].");
            }
            LOGGER.debug("Attribute [" + attribute.getName() + "]. Does it match " + "DigitalIdentifier" + "? " + found);
        }
        return dnAttribute;
    }
    
    private String addSignature(Document doc)
    {
      String resultStr = null;
      SignUtils su = null;
      String passwordStr = null;
      String signCertPathStr = null;
      try {
        passwordStr = new String(this.signCertPassword);
        signCertPathStr = this.signCertPathField;
        String signCertAliasStr = this.signCertAliasField;

        su = new SignUtils(signCertPathStr, passwordStr, signCertAliasStr);
        try
        {
          resultStr = DOMUtil.xmlToString(su.signAttributeQuery(doc));
        } catch (Exception e2) {
          System.err.println(e2.getMessage());
          e2.printStackTrace();
          String suplMessage = e2.getMessage();
          // InterfaceHelper.errorDialog(this, "Could not add digital signature to AttributeQuery.", suplMessage, "Signing Error", e2);
        }
      } catch (FileNotFoundException fnfe) {
        fnfe.printStackTrace();
        String suplMessage = fnfe.getMessage();
        // InterfaceHelper.errorDialog(this, "Key store file not found at " + signCertPathStr, suplMessage, "Signing Error", fnfe);
      } catch (IOException ioe) {
        if ((ioe.getCause() instanceof UnrecoverableKeyException)) {
          ioe.printStackTrace();
          // InterfaceHelper.errorDialog(this, "Incorrect password used for keystore.", "Password provided for " + signCertPathStr + " is incorrect.", "Signing Error", ioe);
        }
      }
      catch (Exception e) {
        e.printStackTrace();
        String suplMessage = e.getMessage();
        // InterfaceHelper.errorDialog(this, "Private key not found.", suplMessage, "Signing Error", e);
      }

      return resultStr;
    }
    
    public String sendRequestToEIAS(String request, String endpoint) {
        StringBuffer responseBuf = new StringBuffer();
        HttpURLConnection connection = null;
        try {
            URL serviceURL = new URL(endpoint);
            byte[] content = request.getBytes();
            URLConnection conn = serviceURL.openConnection();
            if (endpoint.startsWith("https")) {
                ((HttpsURLConnection)conn).setSSLSocketFactory(SSLUtils.createSSLContext(keyStoreFile, keyStorePassword, keyStoreType, trustStoreFile, trustStorePassword, trustStoreType).getSocketFactory());
                ((HttpsURLConnection)conn).setHostnameVerifier(new HostnameVerifier() {

                    @Override
                    public boolean verify(String arg0, SSLSession arg1) {
                        return true;
                    }
                });
            }
            connection = (HttpURLConnection)conn;
            connection.setRequestMethod("POST");          
            connection.setDoOutput(true);          
            connection.setReadTimeout(30000);
            connection.setRequestProperty("Content-type", "text/xml");
            connection.setRequestProperty("Realm-Action", "");
            connection.connect();
            OutputStream outStream = connection.getOutputStream();
            if (request != null) {
                outStream.write(content);
            }
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            
            String str = null;
            while ((str = in.readLine()) != null) {
                responseBuf.append(str);
            }
            in.close();         

        } catch (MalformedURLException e) {
            LOGGER.error("Exception:" + e.getMessage(), e);
        } catch (IOException e) {
            LOGGER.error("Exception:" + e.getMessage(), e);
        } finally      {          
            //close the connection, set all objects to null      
            if (connection!=null) {
                connection.disconnect();          
                connection = null;     
            }
        }
        return responseBuf.toString();
    }


    
    
    

}
