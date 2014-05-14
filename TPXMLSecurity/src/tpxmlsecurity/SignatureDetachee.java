/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package tpxmlsecurity;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
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
import org.w3c.dom.Document;

/**
 *
 * @author mathieu
 */
public class SignatureDetachee {
    public static void main(String[] args) throws Exception {
        String path = "http://www.w3.org/TR/xml-stylesheet";

        // creation des clés
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        // signature factory

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
	Document document = dbf.newDocumentBuilder().newDocument();
        
        // creation reference
	Reference reference = signatureFactory.newReference(path, signatureFactory.newDigestMethod(DigestMethod.SHA1, null));

        // creation signedinfo
        SignedInfo si = signatureFactory.newSignedInfo(signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
					(C14NMethodParameterSpec) null),signatureFactory.newSignatureMethod(SignatureMethod.DSA_SHA1, null),Collections.singletonList(reference));
        
        // creation KeyInfo
        KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv)); 
	DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), document);

        // creation signature
        XMLSignature signature = signatureFactory.newXMLSignature(si, ki);
        signature.sign(dsc);
        
        // ecriture du fichier resultat
        FileOutputStream fos = new FileOutputStream("resultatDetachee.xml");
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(document), new StreamResult(fos));
   
    }
    
}
