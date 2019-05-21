package de.rub.nds.asn1.model;

import de.rub.nds.asn1.Asn1Encodable;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureInfo extends Asn1PseudoType {

    @XmlElements(value = {
            @XmlElement(name = "toBeSignedIdentifier", type = String.class)
    })
    private List<String> toBeSignedIdentifiers = new LinkedList<>();

    @XmlElement(name = "signatureValueTargetIdentifier")
    private String signatureValueTargetIdentifier = "";

    @XmlElement(name = "keyInfoIdentifier")
    private String keyInfoIdentifier = "";

    @XmlElement(name = "signatureAlgorithmOidValue")
    private String signatureAlgorithmOidValue = "";

    @XmlElement(name = "signatureAlgorithmOidIdentifier")
    private String signatureAlgorithmOidIdentifier = "";

    @XmlElement(name = "parametersIdentifier")
    private String parametersIdentifier = "";

    @XmlAnyElement(lax = true)
    private Asn1Encodable parameters = null;

    public SignatureInfo() {

    }

    public List<String> getToBeSignedIdentifiers() {
        return toBeSignedIdentifiers;
    }

    public void setToBeSignedIdentifiers(List<String> toBeSignedIdentifiers) {
        this.toBeSignedIdentifiers = toBeSignedIdentifiers;
    }

    public String getSignatureValueTargetIdentifier() {
        return signatureValueTargetIdentifier;
    }

    public void setSignatureValueTargetIdentifier(String signatureValueTargetIdentifier) {
        this.signatureValueTargetIdentifier = signatureValueTargetIdentifier;
    }

    public String getKeyInfoIdentifier() {
        return keyInfoIdentifier;
    }

    public void setKeyInfoIdentifier(String keyInfoIdentifier) {
        this.keyInfoIdentifier = keyInfoIdentifier;
    }

    public String getSignatureAlgorithmOidValue() {
        return signatureAlgorithmOidValue;
    }

    public void setSignatureAlgorithmOidValue(String signatureAlgorithmOidValue) {
        this.signatureAlgorithmOidValue = signatureAlgorithmOidValue;
    }

    public String getSignatureAlgorithmOidIdentifier() {
        return signatureAlgorithmOidIdentifier;
    }

    public void setSignatureAlgorithmOidIdentifier(String signatureAlgorithmOidIdentifier) {
        this.signatureAlgorithmOidIdentifier = signatureAlgorithmOidIdentifier;
    }

    public String getParametersIdentifier() {
        return parametersIdentifier;
    }

    public void setParametersIdentifier(String parametersIdentifier) {
        this.parametersIdentifier = parametersIdentifier;
    }

    public Asn1Encodable getParameters() {
        return parameters;
    }

    public void setParameters(Asn1Encodable parameters) {
        this.parameters = parameters;
    }
}
