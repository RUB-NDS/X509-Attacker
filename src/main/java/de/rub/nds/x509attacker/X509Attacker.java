package de.rub.nds.x509attacker;

import de.rub.nds.asn1.*;
import de.rub.nds.asn1.encoder.*;
import de.rub.nds.asn1.encoder.typeprocessors.SubjectPublicKeyInfoTypeProcessor;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1tool.filesystem.HexFileWriter;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1PseudoType;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1.model.SignatureInfo;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.asn1.translator.defaultcontextcomponentoptions.Asn1SequenceCCO;
import de.rub.nds.asn1.util.AttributeParser;
import de.rub.nds.asn1tool.Asn1Tool;
import de.rub.nds.asn1tool.filesystem.BinaryFileReader;
import de.rub.nds.asn1tool.filesystem.TextFileReader;
import de.rub.nds.asn1tool.xmlparser.Asn1XmlContent;
import de.rub.nds.asn1tool.xmlparser.JaxbClassList;
import de.rub.nds.asn1tool.xmlparser.XmlConverter;
import de.rub.nds.asn1tool.xmlparser.XmlParser;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.encoder.typeprocessors.DefaultX509TypeProcessor;
import de.rub.nds.x509attacker.fileystem.CertificateFileReader;
import de.rub.nds.x509attacker.fileystem.CertificateFileWriter;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.linker.Linker;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngine;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;

public class X509Attacker {

    public static void main(String[] args) {
        // Parse program arguments
        if(args.length > 0) {
            switch(args[0]) {
                case "xml2cert":
                {
                    if(args.length == 4) {
                        xmlToCertificate(args[1], args[2], args[3]);
                    }
                    else {
                        printHelp();
                    }
                    break;
                }

                case "cert2xml":
                {
                    if(args.length == 3) {
                        certificateToXml(args[1], args[2]);
                    } else {
                        printHelp();
                    }
                    break;
                }

                default:
                {
                    printHelp();
                    break;
                }
            }
        }
        else {
            printHelp();
        }
    }

    private static void printHelp() {
        System.out.println("Usage: x509attacker xml2cert [input xml file] [key file directory] [output certificate directory]");
        System.out.println("   or: x509attacker cert2xml [input certificate file] [output xml file]");
        System.out.println();
        System.out.println("[input xml file]                the file name of the xml input file");
        System.out.println("[key file directory]            the directory where key files are stored");
        System.out.println("[output certificate directory]  the directory where output certificates are created");
        System.out.println();
        System.out.println("[input certificate file]        the input certificate file");
        System.out.println("[output xml file]               the output xml file");
    }

    public static void xmlToCertificate(final String xmlFile, final String keyDirectory, final String certificateOutputDirectory) {
        try {
            Asn1Sequence tbsRequest = createOcspRequest();
            List<Asn1Encodable> asn1Encodables = new LinkedList<>();
            asn1Encodables.add(tbsRequest);

            Asn1Encoder asn1Encoder = new Asn1Encoder(asn1Encodables);
            byte[] encodedAsn1 = asn1Encoder.encode();

            HexFileWriter hexFileWriter = new HexFileWriter(certificateOutputDirectory, xmlFile);
            hexFileWriter.write(encodedAsn1);

            System.out.println("Done.");
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public static void certificateToXml(final String certificateFile, final String xmlFile) {
        try {
            registerXmlClasses();
            registerTypes();
            registerContexts();
            registerContentUnpackers();

            // Read certificate file
            BinaryFileReader certificateFileReader = new BinaryFileReader(certificateFile);
            byte[] certificateContent = certificateFileReader.read();

            // Parse certificate
            Asn1Parser asn1Parser = new Asn1Parser(certificateContent, false);
            List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseOcspTypesContext.NAME);
            Asn1XmlContent asn1XmlContent = new Asn1XmlContent();
            asn1XmlContent.setAsn1Encodables(asn1Encodables);

            // Write XML file
            XmlConverter xmlConverter = new XmlConverter(asn1XmlContent, new File(xmlFile));

            System.out.println("Done.");
        } catch(IOException e) {
            e.printStackTrace();
        } catch(ParserException e) {
            e.printStackTrace();
        }
    }

    public static Asn1Sequence createOcspRequest()
    {
        Asn1Sequence tbsRequestWrapper = new Asn1Sequence();
        Asn1Sequence tbsRequest = new Asn1Sequence();
        Asn1Sequence requestList = new Asn1Sequence();
        Asn1Sequence request = new Asn1Sequence();
        Asn1Sequence reqCert1 = new Asn1Sequence();
        Asn1Sequence hashAlgorithm1 = new Asn1Sequence();
        Asn1Null hashAlgorithm1Filler = new Asn1Null();
        Asn1ObjectIdentifier hashAlgorithmId1 = new Asn1ObjectIdentifier();
        Asn1PrimitiveOctetString issuerNameHash = new Asn1PrimitiveOctetString();
        Asn1PrimitiveOctetString issuerKeyHash = new Asn1PrimitiveOctetString();
        Asn1Integer serialNumber = new Asn1Integer();


        serialNumber.setValue(new BigInteger("20930635207201806962935913731345174549"));
        issuerNameHash.setValue(new BigInteger("2B0413693DF1D33D7E89CBA055CF204F9C158C9D", 16).toByteArray());
        issuerKeyHash.setValue(new BigInteger("B15C470AD29FD096556051734F4DDE84795AE775", 16).toByteArray());
        hashAlgorithmId1.setValue("1.3.14.3.2.26");

        hashAlgorithm1.addChild(hashAlgorithmId1);
        hashAlgorithm1.addChild(hashAlgorithm1Filler);
        reqCert1.addChild(hashAlgorithm1);
        reqCert1.addChild(issuerNameHash);
        reqCert1.addChild(issuerKeyHash);
        reqCert1.addChild(serialNumber);

        request.addChild(reqCert1);
        requestList.addChild(request);
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);

        return tbsRequestWrapper;
    }

    public static void registerXmlClasses() {
        JaxbClassList jaxbClassList = JaxbClassList.getInstance();
        jaxbClassList.addClasses(Asn1Tool.getAsn1ToolJaxbClasses());
        jaxbClassList.addClasses(
                Asn1PseudoType.class,
                SignatureInfo.class,
                KeyInfo.class
        );
    }

    public static void registerTypes() {
        Asn1TypeRegister asn1TypeRegister = Asn1TypeRegister.getInstance();
        asn1TypeRegister.setDefaultTypeProcessorClass(DefaultX509TypeProcessor.class);
        asn1TypeRegister.register("SubjectPublicKeyInfo", SubjectPublicKeyInfoTypeProcessor.class);
    }

    public static void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(ParseNativeTypesContext.NAME, ParseNativeTypesContext.class);
        contextRegister.registerContext(ParseOcspTypesContext.NAME, ParseOcspTypesContext.class);

        // Todo: Implement X.509 contexts according to RFC 5280
    }

    public static void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }

    public static void writeCertificates(final String certificateOutputDirectory, final List<Asn1Encodable> certificates, final byte[][] encodedCertificates) throws IOException {
        CertificateFileWriter certificateChainFileWriter = new CertificateFileWriter(certificateOutputDirectory, "certificate_chain.pem");
        for(int i = 0; i < certificates.size(); i++) {
            Asn1Encodable certificate = certificates.get(i);
            if(certificate.getType().equalsIgnoreCase("Certificate") == false) {
                continue;
            }
            // Append certificate to certificate chain file
            if(AttributeParser.parseBooleanAttributeOrDefault(certificate, X509Attributes.ATTACH_TO_CERTIFICATE_LIST, false)) {
                certificateChainFileWriter.writeCertificate(encodedCertificates[i]);
            }
            // Write certificate in its own file
            writeSingleCertificate(certificateOutputDirectory, certificate, encodedCertificates[i]);
        }
        certificateChainFileWriter.close();
    }

    private static void writeSingleCertificate(final String certificateOutputDirectory, final Asn1Encodable certificate, final byte[] encodedCertificate) throws IOException {
        String certificateFileName = certificate.getIdentifier() + ".pem";
        CertificateFileWriter certificateFileWriter = new CertificateFileWriter(certificateOutputDirectory, certificateFileName);
        certificateFileWriter.writeCertificate(encodedCertificate);
        certificateFileWriter.close();
    }
}
