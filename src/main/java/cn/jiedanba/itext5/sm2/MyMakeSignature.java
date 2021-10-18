package cn.jiedanba.itext5.sm2;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDeveloperExtension;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.TSAClient;

public class MyMakeSignature {
	/**
	 * Signs the document using the detached mode, CMS or CAdES equivalent.
	 * 
	 * @param sap
	 *            the PdfSignatureAppearance
	 * @param externalSignature
	 *            the interface providing the actual signing
	 * @param chain
	 *            the certificate chain
	 * @param crlList
	 *            the CRL list
	 * @param ocspClient
	 *            the OCSP client
	 * @param tsaClient
	 *            the Timestamp client
	 * @param externalDigest
	 *            an implementation that provides the digest
	 * @param estimatedSize
	 *            the reserved size for the signature. It will be estimated if 0
	 * @param sigtype
	 *            Either Signature.CMS or Signature.CADES
	 * @throws DocumentException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public static void signDetached(PdfSignatureAppearance sap, ExternalDigest externalDigest,
			ExternalSignature externalSignature, Certificate[] chain, Collection<CrlClient> crlList,
			OcspClient ocspClient, TSAClient tsaClient, int estimatedSize, CryptoStandard sigtype)
			throws IOException, DocumentException, GeneralSecurityException {
		signDetached(sap, externalDigest, externalSignature, chain, crlList, ocspClient, tsaClient, estimatedSize,
				sigtype, (SignaturePolicyIdentifier) null);
	}

	/**
	 * Signs the document using the detached mode, CMS or CAdES equivalent.
	 * 
	 * @param sap
	 *            the PdfSignatureAppearance
	 * @param externalSignature
	 *            the interface providing the actual signing
	 * @param chain
	 *            the certificate chain
	 * @param crlList
	 *            the CRL list
	 * @param ocspClient
	 *            the OCSP client
	 * @param tsaClient
	 *            the Timestamp client
	 * @param externalDigest
	 *            an implementation that provides the digest
	 * @param estimatedSize
	 *            the reserved size for the signature. It will be estimated if 0
	 * @param sigtype
	 *            Either Signature.CMS or Signature.CADES
	 * @param signaturePolicy
	 *            the signature policy (for EPES signatures)
	 * @throws DocumentException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public static void signDetached(PdfSignatureAppearance sap, ExternalDigest externalDigest,
			ExternalSignature externalSignature, Certificate[] chain, Collection<CrlClient> crlList,
			OcspClient ocspClient, TSAClient tsaClient, int estimatedSize, CryptoStandard sigtype,
			SignaturePolicyIdentifier signaturePolicy) throws IOException, DocumentException, GeneralSecurityException {
		Collection<byte[]> crlBytes = null;
		int i = 0;
		while (crlBytes == null && i < chain.length)
			crlBytes = MakeSignature.processCrl(chain[i++], crlList);
		if (estimatedSize == 0) {
			estimatedSize = 8192;
			if (crlBytes != null) {
				for (byte[] element : crlBytes) {
					estimatedSize += element.length + 10;
				}
			}
			if (ocspClient != null)
				estimatedSize += 4192;
			if (tsaClient != null)
				estimatedSize += 4192;
		}
		sap.setCertificate(chain[0]);
		if (sigtype == CryptoStandard.CADES) {
			sap.addDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL2);
		}
		PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE,
				sigtype == CryptoStandard.CADES ? PdfName.ETSI_CADES_DETACHED : PdfName.ADBE_PKCS7_DETACHED);
		dic.setReason(sap.getReason());
		dic.setLocation(sap.getLocation());
		dic.setSignatureCreator(sap.getSignatureCreator());
		dic.setContact(sap.getContact());
		dic.setDate(new PdfDate(sap.getSignDate())); // time-stamp will
														// over-rule this
		sap.setCryptoDictionary(dic);

		HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
		exc.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2));
		sap.preClose(exc);

		String hashAlgorithm = externalSignature.getHashAlgorithm();
		MyPdfPKCS7 sgn = new MyPdfPKCS7(null, chain, hashAlgorithm, null, externalDigest, false);
		if (signaturePolicy != null) {
			sgn.setSignaturePolicy(signaturePolicy);
		}
		InputStream data = sap.getRangeStream();
		byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest(hashAlgorithm));
		byte[] ocsp = null;
		if (chain.length >= 2 && ocspClient != null) {
			ocsp = ocspClient.getEncoded((X509Certificate) chain[0], (X509Certificate) chain[1], null);
		}
		byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, ocsp, crlBytes, sigtype);
		byte[] extSignature = externalSignature.sign(sh);
		sgn.setExternalDigest(extSignature, null, externalSignature.getEncryptionAlgorithm());

		byte[] encodedSig = sgn.getEncodedPKCS7(hash, tsaClient, ocsp, crlBytes, sigtype);

		if (estimatedSize < encodedSig.length)
			throw new IOException("Not enough space");

		byte[] paddedSig = new byte[estimatedSize];
		System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

		PdfDictionary dic2 = new PdfDictionary();
		dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
		sap.close(dic2);
	}
}
