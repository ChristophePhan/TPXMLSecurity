/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package tpxmlsecurity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 *
 * @author phan5u
 */
public class SignatureEnveloppante {

    public static void main(String[] args) throws Exception {

        // First, create the DOM XMLSignatureFactory that will be used to
        // generate the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        
        String xpath = args[2];
        XPathType xpt = new XPathType(xpath, XPathType.Filter.UNION);
        List xpaths = new ArrayList();
        xpaths.add(xpt);

        // Next, create a Reference to a same-document URI that is an Object
        // element and specify the SHA1 digest algorithm
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);
        
        Transform xpathTransform = fac.newTransform(Transform.XPATH2, new XPathFilter2ParameterSpec(xpaths));
        List transforms = new ArrayList();
        transforms.add(xpathTransform);

        

        // Next, create the referenced Object
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        //Document doc = dbf.newDocumentBuilder().newDocument();
        Document docEntree = dbf.newDocumentBuilder().parse(new FileInputStream(args[0]));
        //doc.adoptNode(docEntree.getFirstChild()):
        
        XMLStructure content = new DOMStructure(docEntree.getDocumentElement());
        XMLObject obj = fac.newXMLObject(Collections.singletonList(content), "object", null, null);

        Reference ref = fac.newReference("#object", dm, transforms, null,null);
        
        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null),
                Collections.singletonList(ref));

        // Create a DSA KeyPair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        // Create a KeyValue containing the DSA PublicKey that was generated
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki,
                Collections.singletonList(obj), null, null);

        // Create a DOMSignContext and specify the DSA PrivateKey for signing
        // and the document location of the XMLSignature
        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), docEntree);

        // Lastly, generate the enveloping signature using the PrivateKey
        signature.sign(dsc);

        // output the resulting document
        OutputStream os;
        if (args.length > 0) {
            os = new FileOutputStream(args[1]);
        } else {
            os = System.out;
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(docEntree), new StreamResult(os));
    }
}
