/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.production;

import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import org.apache.xml.security.utils.Constants;

import java.util.Map;

import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import xades4j.properties.DataObjectDesc;
import xades4j.utils.SignatureServicesTestBase;
import xades4j.utils.StringUtils;

import static org.junit.Assert.*;

/**
 * @author Luís
 */
public class SignedDataObjectsProcessorTest extends SignatureServicesTestBase
{
    @BeforeClass
    public static void setUpClass()
    {
        Init.initXMLSec();
    }

    @Test
    public void testProcess() throws Exception
    {
        System.out.println("process");

        Document doc = getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
                .withSignedDataObject(new DataObjectReference("uri").withTransform(new EnvelopedSignatureTransform()))
                .withSignedDataObject(new EnvelopedXmlObject(doc.createElement("test1")))
                .withSignedDataObject(new EnvelopedXmlObject(doc.createElement("test2"), "text/xml", null));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        AllwaysNullAlgsParamsMarshaller algsParamsMarshaller = new AllwaysNullAlgsParamsMarshaller();

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new TestAlgorithmsProvider(), algsParamsMarshaller);
        Map<DataObjectDesc, Reference> result = processor.process(dataObjsDescs, xmlSignature);

        assertEquals(dataObjsDescs.getDataObjectsDescs().size(), result.size());
        assertEquals(2, xmlSignature.getObjectLength());
        assertEquals(xmlSignature.getSignedInfo().getLength(), dataObjsDescs.getDataObjectsDescs().size());

        assertEquals(1, algsParamsMarshaller.getInvokeCount());
        Reference ref = xmlSignature.getSignedInfo().item(0);
        assertEquals(1, ref.getTransforms().getLength());

        ObjectContainer obj = xmlSignature.getObjectItem(1);
        assertEquals("text/xml", obj.getMimeType());
        assertTrue(StringUtils.isNullOrEmptyString(obj.getEncoding()));

    }

    @Test
    public void testAddManifest() throws Exception
    {
        Document doc = getNewDocument();

        SignedDataObjects signedObjects = new SignedDataObjects()
                .withSignedDataObject(new EnvelopedManifest()
                        .withSignedDataObject(new DataObjectReference("xades4j:1"))
                        .withSignedDataObject(new DataObjectReference("xades4j:2")))
                .withResourceResolver(new ResourceResolverSpi()
                {
                    @Override
                    public XMLSignatureInput engineResolveURI(ResourceResolverContext context)
                    {
                        return new XMLSignatureInput(context.uriToResolve.getBytes());
                    }

                    @Override
                    public boolean engineCanResolveURI(ResourceResolverContext context)
                    {
                        return context.uriToResolve.startsWith("xades4j:");
                    }
                });

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        AllwaysNullAlgsParamsMarshaller algsParamsMarshaller = new AllwaysNullAlgsParamsMarshaller();

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new TestAlgorithmsProvider(), algsParamsMarshaller);
        Map<DataObjectDesc, Reference> result = processor.process(signedObjects, xmlSignature);

        assertEquals(1, result.size());
        assertEquals(1, xmlSignature.getObjectLength());
        assertEquals(1, xmlSignature.getSignedInfo().getLength());

        Manifest manifest = new Manifest((Element)xmlSignature.getObjectItem(0).getElement().getFirstChild(), "");
        assertEquals(2, manifest.getLength());
        assertNotNull(manifest.getId());

        Reference ref1 = manifest.item(0);
        assertEquals("xades4j:1", ref1.getURI());
        assertNotEquals(0, ref1.getDigestValue());

        Reference ref2 = manifest.item(1);
        assertEquals("xades4j:2", ref2.getURI());
        assertNotEquals(0, ref2.getDigestValue());
    }

    @Test
    public void testAddNullReference() throws Exception
    {
        System.out.println("addNullReference");

        Document doc = SignatureServicesTestBase.getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
                .withSignedDataObject(new AnonymousDataObjectReference("data".getBytes()));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new TestAlgorithmsProvider(), new AllwaysNullAlgsParamsMarshaller());
        Map<DataObjectDesc, Reference> result = processor.process(dataObjsDescs, xmlSignature);

        assertEquals(1, result.size());
        assertEquals(0, xmlSignature.getObjectLength());
        assertEquals(1, xmlSignature.getSignedInfo().getLength());

        Reference r = xmlSignature.getSignedInfo().item(0);
        assertNull(r.getElement().getAttributeNodeNS(Constants.SignatureSpecNS, "URI"));
    }

    @Test(expected = IllegalStateException.class)
    public void testAddMultipleNullReferencesFails() throws Exception
    {
        System.out.println("addMultipleNullReferencesFails");

        Document doc = SignatureServicesTestBase.getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
                .withSignedDataObject(new AnonymousDataObjectReference("data1".getBytes()))
                .withSignedDataObject(new AnonymousDataObjectReference("data2".getBytes()));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new TestAlgorithmsProvider(), new AllwaysNullAlgsParamsMarshaller());
        processor.process(dataObjsDescs, xmlSignature);
    }
}
