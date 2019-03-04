package de.rub.nds.x509attacker.x509.model.types.authorityinformationaccess;

import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Sequence;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AccessDescription extends X509Asn1Sequence {

    public AccessDescription() {
        super();
    }
}