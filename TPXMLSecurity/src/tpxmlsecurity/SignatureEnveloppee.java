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
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;

/**
 *
 * @author phan5u
 */
public class SignatureEnveloppee {

    public static void main(String[] args) throws Exception {

        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the SHA1 digest algorithm and the ENVELOPED Transform.
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);

        String xpath = args[2];
        XPathType xpt = new XPathType(xpath, XPathType.Filter.UNION);
        List xpaths = new ArrayList();
        xpaths.add(xpt);

        Transform xpathTransform = fac.newTransform(Transform.XPATH2, new XPathFilter2ParameterSpec(xpaths));
        Transform enveloppedTransform = fac.newTransform(Transform.ENVELOPED,(TransformParameterSpec) null);
        List transforms = new ArrayList();
        transforms.add(xpathTransform);
        transforms.add(enveloppedTransform);

        String uri = "";
        Reference ref = fac.newReference(uri, dm, transforms, null, null);
        List references = new ArrayList();
        references.add(ref);
        
        CanonicalizationMethod cm = fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                (C14NMethodParameterSpec) null);
        // Create the SignedInfo
        SignatureMethod sm = fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null);
        SignedInfo si = fac.newSignedInfo(cm, sm,references);

        // Create a DSA KeyPair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        // Create a KeyValue containing the DSA PublicKey that was generated
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        List kvs = new ArrayList();
        kvs.add(kv);
        KeyInfo ki = kif.newKeyInfo(kvs);

        // Instantiate the document to be signed
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(args[0]));

        // Create a DOMSignContext and specify the DSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        // output the resulting document
        OutputStream os;
        if (args.length > 1) {
            os = new FileOutputStream(args[1]);
        } else {
            os = System.out;
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
    }
}
