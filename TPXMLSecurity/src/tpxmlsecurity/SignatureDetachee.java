/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package tpxmlsecurity;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
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
        XMLSignatureFactory xmlFactory = XMLSignatureFactory.getInstance("DOM");
        
        Reference reference = xmlFactory.newReference("http://www.w3.org/TR/xml-stylesheet", xmlFactory.newDigestMethod(DigestMethod.SHA1, null));
        
        CanonicalizationMethod cm = xmlFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null);
        SignatureMethod sm = xmlFactory.newSignatureMethod(SignatureMethod.DSA_SHA1, null);
        List<Reference> listeRef = new ArrayList();
        listeRef.add(reference);
        SignedInfo signeInfo = xmlFactory.newSignedInfo(cm, sm, listeRef);
        
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(512);
        KeyPair keyPair = gen.generateKeyPair();
        
        KeyInfoFactory keyInfoFactory = xmlFactory.getKeyInfoFactory();
        KeyValue keyValue = keyInfoFactory.newKeyValue(keyPair.getPublic());
        
        List<KeyValue> listekv = new ArrayList();
        listekv.add(keyValue);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(listekv);
        XMLSignature signature = xmlFactory.newXMLSignature(signeInfo, keyInfo);
        
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
	docBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        
        Document document = docBuilder.newDocument();
        DOMSignContext domSignContext = new DOMSignContext(keyPair.getPrivate(), document);
 
        signature.sign(domSignContext);
        
        FileOutputStream fos = new FileOutputStream("resultat.xml");
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(document), new StreamResult(fos));
   
    }
    
}
