/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package tpxmlsecurity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author phan5u
 */
public class SignatureEnveloppee {

    public static void main(String[] args) throws Exception {
        String path = "test.xml";
        
        // creation des clés
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
   
        // signature factory
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        // creation objets xpath
	XPathFactory xpathfactory = XPathFactory.newInstance();
	XPath xpath = xpathfactory.newXPath();
        
        // lecture du fichier xml en entrée
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document document = builder.parse(new FileInputStream(path));
        
        // execution de la requete xpath
        String requete = "/racine/encyclopedie/article";
        XPathExpression expression = xpath.compile(requete);
        NodeList nodes = (NodeList) expression.evaluate(document, XPathConstants.NODESET);
        Node nodeSign = nodes.item(0);
        ArrayList<Transform> transforms = new ArrayList<Transform>();
        transforms.add(signatureFactory.newTransform(Transform.XPATH, new XPathFilterParameterSpec(requete)));
        transforms.add(signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
        
        // creation de la reference
 	Reference reference = signatureFactory.newReference("",signatureFactory.newDigestMethod(DigestMethod.SHA1, null),
			    transforms,null, null);

        // creation de signedInfo
        SignedInfo si = signatureFactory.newSignedInfo(signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
					(C14NMethodParameterSpec) null),signatureFactory.newSignatureMethod(SignatureMethod.DSA_SHA1, null),Collections.singletonList(reference));
        
        // creation de KeyInfo
        KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv)); 
        
        // creation de la signature
	DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), nodeSign);  
        XMLSignature signature = signatureFactory.newXMLSignature(si, ki);
        signature.sign(dsc);
        
        // ecriture du fichier resultat
        FileOutputStream fos = new FileOutputStream("resultatEnveloppee.xml");
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(document), new StreamResult(fos));

    }
}
