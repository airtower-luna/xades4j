//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 in JDK 6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2010.04.09 at 09:56:29 PM BST 
//


package xades4j.xml.bind.xmldsig;

import java.math.BigInteger;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlRegistry;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.namespace.QName;
import xades4j.xml.bind.Base64XmlAdapter;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the xades4j.xml.bind.xmldsig package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _PGPData_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "PGPData");
    private final static QName _SPKIData_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SPKIData");
    private final static QName _RetrievalMethod_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "RetrievalMethod");
    private final static QName _CanonicalizationMethod_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "CanonicalizationMethod");
    private final static QName _SignatureProperty_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SignatureProperty");
    private final static QName _Transforms_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Transforms");
    private final static QName _Manifest_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Manifest");
    private final static QName _SignatureMethod_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod");
    private final static QName _KeyInfo_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
    private final static QName _DigestMethod_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "DigestMethod");
    private final static QName _MgmtData_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "MgmtData");
    private final static QName _Reference_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Reference");
    private final static QName _RSAKeyValue_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "RSAKeyValue");
    private final static QName _Signature_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Signature");
    private final static QName _DSAKeyValue_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "DSAKeyValue");
    private final static QName _SignedInfo_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SignedInfo");
    private final static QName _Object_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Object");
    private final static QName _SignatureValue_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
    private final static QName _Transform_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Transform");
    private final static QName _X509Data_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509Data");
    private final static QName _DigestValue_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "DigestValue");
    private final static QName _SignatureProperties_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SignatureProperties");
    private final static QName _KeyName_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "KeyName");
    private final static QName _KeyValue_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "KeyValue");
    private final static QName _XmlX509DataTypeX509IssuerSerial_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509IssuerSerial");
    private final static QName _XmlX509DataTypeX509Certificate_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
    private final static QName _XmlX509DataTypeX509SKI_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509SKI");
    private final static QName _XmlX509DataTypeX509SubjectName_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509SubjectName");
    private final static QName _XmlX509DataTypeX509CRL_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509CRL");
    private final static QName _XmlSignatureMethodTypeHMACOutputLength_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "HMACOutputLength");
    private final static QName _XmlPGPDataTypePGPKeyID_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "PGPKeyID");
    private final static QName _XmlPGPDataTypePGPKeyPacket_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "PGPKeyPacket");
    private final static QName _XmlTransformTypeXPath_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "XPath");
    private final static QName _XmlSPKIDataTypeSPKISexp_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "SPKISexp");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: xades4j.marshalling.xmldsig
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link XmlSignaturePropertiesType }
     * 
     */
    public XmlSignaturePropertiesType createXmlSignaturePropertiesType() {
        return new XmlSignaturePropertiesType();
    }

    /**
     * Create an instance of {@link XmlX509DataType }
     * 
     */
    public XmlX509DataType createXmlX509DataType() {
        return new XmlX509DataType();
    }

    /**
     * Create an instance of {@link XmlKeyInfoType }
     * 
     */
    public XmlKeyInfoType createXmlKeyInfoType() {
        return new XmlKeyInfoType();
    }

    /**
     * Create an instance of {@link XmlObjectType }
     * 
     */
    public XmlObjectType createXmlObjectType() {
        return new XmlObjectType();
    }

    /**
     * Create an instance of {@link XmlManifestType }
     * 
     */
    public XmlManifestType createXmlManifestType() {
        return new XmlManifestType();
    }

    /**
     * Create an instance of {@link XmlSignatureValueType }
     * 
     */
    public XmlSignatureValueType createXmlSignatureValueType() {
        return new XmlSignatureValueType();
    }

    /**
     * Create an instance of {@link XmlSPKIDataType }
     * 
     */
    public XmlSPKIDataType createXmlSPKIDataType() {
        return new XmlSPKIDataType();
    }

    /**
     * Create an instance of {@link XmlTransformType }
     * 
     */
    public XmlTransformType createXmlTransformType() {
        return new XmlTransformType();
    }

    /**
     * Create an instance of {@link XmlCanonicalizationMethodType }
     * 
     */
    public XmlCanonicalizationMethodType createXmlCanonicalizationMethodType() {
        return new XmlCanonicalizationMethodType();
    }

    /**
     * Create an instance of {@link XmlKeyValueType }
     * 
     */
    public XmlKeyValueType createXmlKeyValueType() {
        return new XmlKeyValueType();
    }

    /**
     * Create an instance of {@link XmlDSAKeyValueType }
     * 
     */
    public XmlDSAKeyValueType createXmlDSAKeyValueType() {
        return new XmlDSAKeyValueType();
    }

    /**
     * Create an instance of {@link XmlSignatureType }
     * 
     */
    public XmlSignatureType createXmlSignatureType() {
        return new XmlSignatureType();
    }

    /**
     * Create an instance of {@link XmlTransformsType }
     * 
     */
    public XmlTransformsType createXmlTransformsType() {
        return new XmlTransformsType();
    }

    /**
     * Create an instance of {@link XmlSignaturePropertyType }
     * 
     */
    public XmlSignaturePropertyType createXmlSignaturePropertyType() {
        return new XmlSignaturePropertyType();
    }

    /**
     * Create an instance of {@link XmlDigestMethodType }
     * 
     */
    public XmlDigestMethodType createXmlDigestMethodType() {
        return new XmlDigestMethodType();
    }

    /**
     * Create an instance of {@link XmlPGPDataType }
     * 
     */
    public XmlPGPDataType createXmlPGPDataType() {
        return new XmlPGPDataType();
    }

    /**
     * Create an instance of {@link XmlRetrievalMethodType }
     * 
     */
    public XmlRetrievalMethodType createXmlRetrievalMethodType() {
        return new XmlRetrievalMethodType();
    }

    /**
     * Create an instance of {@link XmlRSAKeyValueType }
     * 
     */
    public XmlRSAKeyValueType createXmlRSAKeyValueType() {
        return new XmlRSAKeyValueType();
    }

    /**
     * Create an instance of {@link XmlX509IssuerSerialType }
     * 
     */
    public XmlX509IssuerSerialType createXmlX509IssuerSerialType() {
        return new XmlX509IssuerSerialType();
    }

    /**
     * Create an instance of {@link XmlSignatureMethodType }
     * 
     */
    public XmlSignatureMethodType createXmlSignatureMethodType() {
        return new XmlSignatureMethodType();
    }

    /**
     * Create an instance of {@link XmlReferenceType }
     * 
     */
    public XmlReferenceType createXmlReferenceType() {
        return new XmlReferenceType();
    }

    /**
     * Create an instance of {@link XmlSignedInfoType }
     * 
     */
    public XmlSignedInfoType createXmlSignedInfoType() {
        return new XmlSignedInfoType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlPGPDataType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "PGPData")
    public JAXBElement<XmlPGPDataType> createPGPData(XmlPGPDataType value) {
        return new JAXBElement<XmlPGPDataType>(_PGPData_QNAME, XmlPGPDataType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSPKIDataType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SPKIData")
    public JAXBElement<XmlSPKIDataType> createSPKIData(XmlSPKIDataType value) {
        return new JAXBElement<XmlSPKIDataType>(_SPKIData_QNAME, XmlSPKIDataType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlRetrievalMethodType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "RetrievalMethod")
    public JAXBElement<XmlRetrievalMethodType> createRetrievalMethod(XmlRetrievalMethodType value) {
        return new JAXBElement<XmlRetrievalMethodType>(_RetrievalMethod_QNAME, XmlRetrievalMethodType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlCanonicalizationMethodType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "CanonicalizationMethod")
    public JAXBElement<XmlCanonicalizationMethodType> createCanonicalizationMethod(XmlCanonicalizationMethodType value) {
        return new JAXBElement<XmlCanonicalizationMethodType>(_CanonicalizationMethod_QNAME, XmlCanonicalizationMethodType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSignaturePropertyType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SignatureProperty")
    public JAXBElement<XmlSignaturePropertyType> createSignatureProperty(XmlSignaturePropertyType value) {
        return new JAXBElement<XmlSignaturePropertyType>(_SignatureProperty_QNAME, XmlSignaturePropertyType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlTransformsType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "Transforms")
    public JAXBElement<XmlTransformsType> createTransforms(XmlTransformsType value) {
        return new JAXBElement<XmlTransformsType>(_Transforms_QNAME, XmlTransformsType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlManifestType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "Manifest")
    public JAXBElement<XmlManifestType> createManifest(XmlManifestType value) {
        return new JAXBElement<XmlManifestType>(_Manifest_QNAME, XmlManifestType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSignatureMethodType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SignatureMethod")
    public JAXBElement<XmlSignatureMethodType> createSignatureMethod(XmlSignatureMethodType value) {
        return new JAXBElement<XmlSignatureMethodType>(_SignatureMethod_QNAME, XmlSignatureMethodType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlKeyInfoType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "KeyInfo")
    public JAXBElement<XmlKeyInfoType> createKeyInfo(XmlKeyInfoType value) {
        return new JAXBElement<XmlKeyInfoType>(_KeyInfo_QNAME, XmlKeyInfoType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlDigestMethodType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "DigestMethod")
    public JAXBElement<XmlDigestMethodType> createDigestMethod(XmlDigestMethodType value) {
        return new JAXBElement<XmlDigestMethodType>(_DigestMethod_QNAME, XmlDigestMethodType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "MgmtData")
    public JAXBElement<String> createMgmtData(String value) {
        return new JAXBElement<String>(_MgmtData_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlReferenceType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "Reference")
    public JAXBElement<XmlReferenceType> createReference(XmlReferenceType value) {
        return new JAXBElement<XmlReferenceType>(_Reference_QNAME, XmlReferenceType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlRSAKeyValueType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "RSAKeyValue")
    public JAXBElement<XmlRSAKeyValueType> createRSAKeyValue(XmlRSAKeyValueType value) {
        return new JAXBElement<XmlRSAKeyValueType>(_RSAKeyValue_QNAME, XmlRSAKeyValueType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSignatureType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "Signature")
    public JAXBElement<XmlSignatureType> createSignature(XmlSignatureType value) {
        return new JAXBElement<XmlSignatureType>(_Signature_QNAME, XmlSignatureType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlDSAKeyValueType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "DSAKeyValue")
    public JAXBElement<XmlDSAKeyValueType> createDSAKeyValue(XmlDSAKeyValueType value) {
        return new JAXBElement<XmlDSAKeyValueType>(_DSAKeyValue_QNAME, XmlDSAKeyValueType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSignedInfoType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SignedInfo")
    public JAXBElement<XmlSignedInfoType> createSignedInfo(XmlSignedInfoType value) {
        return new JAXBElement<XmlSignedInfoType>(_SignedInfo_QNAME, XmlSignedInfoType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlObjectType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "Object")
    public JAXBElement<XmlObjectType> createObject(XmlObjectType value) {
        return new JAXBElement<XmlObjectType>(_Object_QNAME, XmlObjectType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSignatureValueType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SignatureValue")
    public JAXBElement<XmlSignatureValueType> createSignatureValue(XmlSignatureValueType value) {
        return new JAXBElement<XmlSignatureValueType>(_SignatureValue_QNAME, XmlSignatureValueType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlTransformType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "Transform")
    public JAXBElement<XmlTransformType> createTransform(XmlTransformType value) {
        return new JAXBElement<XmlTransformType>(_Transform_QNAME, XmlTransformType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlX509DataType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "X509Data")
    public JAXBElement<XmlX509DataType> createX509Data(XmlX509DataType value) {
        return new JAXBElement<XmlX509DataType>(_X509Data_QNAME, XmlX509DataType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "DigestValue")
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createDigestValue(byte[] value) {
        return new JAXBElement<byte[]>(_DigestValue_QNAME, byte[].class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlSignaturePropertiesType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SignatureProperties")
    public JAXBElement<XmlSignaturePropertiesType> createSignatureProperties(XmlSignaturePropertiesType value) {
        return new JAXBElement<XmlSignaturePropertiesType>(_SignatureProperties_QNAME, XmlSignaturePropertiesType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "KeyName")
    public JAXBElement<String> createKeyName(String value) {
        return new JAXBElement<String>(_KeyName_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlKeyValueType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "KeyValue")
    public JAXBElement<XmlKeyValueType> createKeyValue(XmlKeyValueType value) {
        return new JAXBElement<XmlKeyValueType>(_KeyValue_QNAME, XmlKeyValueType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link XmlX509IssuerSerialType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "X509IssuerSerial", scope = XmlX509DataType.class)
    public JAXBElement<XmlX509IssuerSerialType> createXmlX509DataTypeX509IssuerSerial(XmlX509IssuerSerialType value) {
        return new JAXBElement<XmlX509IssuerSerialType>(_XmlX509DataTypeX509IssuerSerial_QNAME, XmlX509IssuerSerialType.class, XmlX509DataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "X509Certificate", scope = XmlX509DataType.class)
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createXmlX509DataTypeX509Certificate(byte[] value) {
        return new JAXBElement<byte[]>(_XmlX509DataTypeX509Certificate_QNAME, byte[].class, XmlX509DataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "X509SKI", scope = XmlX509DataType.class)
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createXmlX509DataTypeX509SKI(byte[] value) {
        return new JAXBElement<byte[]>(_XmlX509DataTypeX509SKI_QNAME, byte[].class, XmlX509DataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "X509SubjectName", scope = XmlX509DataType.class)
    public JAXBElement<String> createXmlX509DataTypeX509SubjectName(String value) {
        return new JAXBElement<String>(_XmlX509DataTypeX509SubjectName_QNAME, String.class, XmlX509DataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "X509CRL", scope = XmlX509DataType.class)
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createXmlX509DataTypeX509CRL(byte[] value) {
        return new JAXBElement<byte[]>(_XmlX509DataTypeX509CRL_QNAME, byte[].class, XmlX509DataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link BigInteger }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "HMACOutputLength", scope = XmlSignatureMethodType.class)
    public JAXBElement<BigInteger> createXmlSignatureMethodTypeHMACOutputLength(BigInteger value) {
        return new JAXBElement<BigInteger>(_XmlSignatureMethodTypeHMACOutputLength_QNAME, BigInteger.class, XmlSignatureMethodType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "PGPKeyID", scope = XmlPGPDataType.class)
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createXmlPGPDataTypePGPKeyID(byte[] value) {
        return new JAXBElement<byte[]>(_XmlPGPDataTypePGPKeyID_QNAME, byte[].class, XmlPGPDataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "PGPKeyPacket", scope = XmlPGPDataType.class)
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createXmlPGPDataTypePGPKeyPacket(byte[] value) {
        return new JAXBElement<byte[]>(_XmlPGPDataTypePGPKeyPacket_QNAME, byte[].class, XmlPGPDataType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "XPath", scope = XmlTransformType.class)
    public JAXBElement<String> createXmlTransformTypeXPath(String value) {
        return new JAXBElement<String>(_XmlTransformTypeXPath_QNAME, String.class, XmlTransformType.class, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://www.w3.org/2000/09/xmldsig#", name = "SPKISexp", scope = XmlSPKIDataType.class)
    @XmlJavaTypeAdapter(Base64XmlAdapter .class)
    public JAXBElement<byte[]> createXmlSPKIDataTypeSPKISexp(byte[] value) {
        return new JAXBElement<byte[]>(_XmlSPKIDataTypeSPKISexp_QNAME, byte[].class, XmlSPKIDataType.class, value);
    }

}
