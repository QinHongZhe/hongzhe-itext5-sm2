package cn.jiedanba.itext5.sm2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * RSA工具类
 * 
 * @author lenovo
 *
 */

public class CAUtil {

	private static final Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();

	static {
		Security.addProvider(BC);
	}

	/**
	 * 获取公钥
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getPublicKey(String encodedKey) {
		try {
			byte[] keyBytes = Base64.decodeBase64(encodedKey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	/**
	 * 获取公钥
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getPublicKey(byte[] encodedKey) {
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory keyFactory = KeyFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	/**
	 * 获取ECC公钥
	 * 
	 * @param pubStr
	 * @return
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws Exception
	 */
	public static ECPublicKey getECPublicKey(String publicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", BC);
		ECPublicKey pub = (ECPublicKey) keyFactory.generatePublic(keySpec);
		return pub;
	}

	/**
	 * 获取ECC私钥
	 * 
	 * @param priStr
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws Exception
	 */
	public static ECPrivateKey getECPrivateKey(String privateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", BC);
		ECPrivateKey pri = (ECPrivateKey) keyFactory.generatePrivate(keySpec);
		return pri;
	}

	/**
	 * 获取私钥
	 * 
	 * @param encodedKey
	 *            encoded according to the PKCS #8 standard
	 * @return
	 */
	public static PrivateKey getPrivateKey(String encodedKey) {
		PrivateKey privateKey = null;
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(encodedKey));
			KeyFactory keyFactory;
			keyFactory = KeyFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
			privateKey = keyFactory.generatePrivate(keySpec);
			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

	/**
	 * 获取私钥
	 * 
	 * @param encodedKey
	 *            encoded according to the PKCS #8 standard
	 * @return
	 */
	public static PrivateKey getPrivateKey(byte[] encodedKey) {
		PrivateKey privateKey = null;
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			KeyFactory keyFactory;
			keyFactory = KeyFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
			privateKey = keyFactory.generatePrivate(keySpec);
			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

	/**
	 * 读取X.509证书
	 * 
	 * @param crtPath
	 *            证书路径
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 */
	public static X509Certificate readX509Certificate(byte[] crtPath)
			throws CertificateException, IOException, NoSuchProviderException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(crtPath));
		return cert;
	}

	/**
	 * 获取公钥证书链
	 * 
	 * @param cer
	 * @return
	 */
	public static Certificate[] getCertificateChain(byte[] cer) {
		try {
			CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509",
					BouncyCastleProvider.PROVIDER_NAME);
			// 获取crt证书的证书链
			Collection<Certificate> chainList = new ArrayList<Certificate>(
					certificatefactory.generateCertificates(new ByteArrayInputStream(cer)));
			return chainList.toArray(new Certificate[] {});
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("获取公钥证书链出错！", e);
		}
	}

}
