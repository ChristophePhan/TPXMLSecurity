/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tpxmlsecurity;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.util.List;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import static javax.xml.crypto.dsig.XMLSignature.XMLNS;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author mathieu
 */
public class Validation {

    public void validation(String path) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

    	XMLSignatureFactory xmlsignatureFactory = XMLSignatureFactory.getInstance("DOM");
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document document = builder.parse(new FileInputStream(path));

        NodeList nodeList = document.getElementsByTagNameNS(XMLNS, "Signature");
                
        // recuperation de la signature
        Node signature = nodeList.item(0);
        DOMValidateContext validateContext = new DOMValidateContext
            (new KeyValueKeySelector(), signature);
        // test de la signature
        XMLSignature xmlSignature = xmlsignatureFactory.unmarshalXMLSignature(validateContext);
        if(xmlSignature.validate(validateContext)) {
            System.out.println("Document valide");
        }
        else {
            System.out.println("Document non valide");
        }
    } 
    
     
    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
            throws KeySelectorException {
           
            // methode de signature
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();
            
            // parcours de la list KeyInfo, et obtention de la clé public
            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue)xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    return new ImplKeySelectorResult(pk);
                    
                }
            }
            throw new KeySelectorException("Pas de cle");
        }

    }

    private static class ImplKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;
        ImplKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }
        public Key getKey() { return pk; }
    }
}