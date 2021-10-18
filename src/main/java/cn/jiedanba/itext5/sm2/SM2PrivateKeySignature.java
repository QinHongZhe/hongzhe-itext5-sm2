package cn.jiedanba.itext5.sm2;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;

public class SM2PrivateKeySignature implements ExternalSignature {
	/** The private key object. */
	private PrivateKey pk;
	/** The hash algorithm. */
	private String hashAlgorithm;
	/** The encryption algorithm (obtained from the private key) */
	private String encryptionAlgorithm;
	/** The security provider */
	private String provider;

	public SM2PrivateKeySignature(PrivateKey pk, String provider) {
		this.pk = pk;
		this.provider = provider;
		this.hashAlgorithm = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigests("SM3"));
		encryptionAlgorithm = "SM2";
	}

	/**
	 * Returns the hash algorithm.
	 * 
	 * @return the hash algorithm (e.g. "SHA-1", "SHA-256,...")
	 * @see com.itextpdf.text.pdf.security.ExternalSignature#getHashAlgorithm()
	 */
	@Override
	public String getHashAlgorithm() {
		return hashAlgorithm;
	}

	/**
	 * Returns the encryption algorithm used for signing.
	 * 
	 * @return the encryption algorithm ("RSA" or "DSA")
	 * @see com.itextpdf.text.pdf.security.ExternalSignature#getEncryptionAlgorithm()
	 */
	@Override
	public String getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * Signs it using the encryption algorithm in combination with the digest
	 * algorithm.
	 * 
	 * @param message
	 *            the message you want to be hashed and signed
	 * @return a signed message digest
	 * @throws GeneralSecurityException
	 */
	@Override
	public byte[] sign(byte[] b) throws GeneralSecurityException {
		String signMode = hashAlgorithm + "with" + encryptionAlgorithm;
		Signature sig;
		if (provider == null)
			sig = Signature.getInstance(signMode);
		else
			sig = Signature.getInstance(signMode, provider);
		sig.initSign(pk);
		sig.update(b);
		return sig.sign();
	}
}
