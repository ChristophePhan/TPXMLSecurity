/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package tpxmlsecurity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 *
 * @author phan5u
 */
public class SignatureEnveloppante {

    public static void main(String[] args) throws Exception {
        String path = "test.xml";
        
        // creation clés
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        
        // signature factory
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        // objets xpath
	XPathFactory xpathfactory = XPathFactory.newInstance();
	XPath xpath = xpathfactory.newXPath();
        
        // creation des documents et de la requete xpath
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document document = builder.parse(new FileInputStream(path));
        Document document2 = builder.newDocument();
        String requete = "/racine/encyclopedie/article";
        Node node = (Node) xpath.compile(requete).evaluate(document, XPathConstants.NODE);
        
        // creation reference
	Reference reference = signatureFactory.newReference("#object", signatureFactory.newDigestMethod(DigestMethod.SHA1, null));

        // creation signedInfo
        SignedInfo si = signatureFactory.newSignedInfo(signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
					(C14NMethodParameterSpec) null),signatureFactory.newSignatureMethod(SignatureMethod.DSA_SHA1, null),Collections.singletonList(reference));
        
        // creation keyInfo
        KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv)); 
	DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), document2);  
        
        // creation du noeud object
        XMLStructure content = new DOMStructure(node);
        XMLObject obj = signatureFactory.newXMLObject(Collections.singletonList(content), "object", null, null);

        // creation de la signature
        XMLSignature signature = signatureFactory.newXMLSignature(si, ki, Collections.singletonList(obj), null, null);
        signature.sign(dsc);
        
        // ecriture du fichier resultat
        FileOutputStream fos = new FileOutputStream("resultatEnveloppante.xml");
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(document2), new StreamResult(fos));


    }
}
