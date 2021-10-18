package cn.jiedanba.itext5.sm2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfSignatureAppearance.RenderingMode;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.EncryptionAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

public class ITextUtil {
	/**
	 * 
	 * @param pdf
	 *            pdf文件
	 * @param stampImage
	 *            签名图片
	 * @param chain
	 *            证书链
	 * @param pk
	 *            私钥
	 * @param crlList
	 * @param ocspClient
	 * @param digestAlgorithm
	 *            签名算法 sha1 sha256
	 * @param reason
	 *            签名理由
	 * @param location
	 *            签名位置
	 * @param tsa
	 *            时间戳
	 * @param positionX
	 *            左下角 x坐标
	 * @param positionY
	 *            左下角 y坐标
	 * @param width
	 *            签名图片宽度
	 * @param height
	 *            签名图片高度
	 * @param pageNo
	 *            签名页数
	 * @return
	 */
	public static byte[] sign(byte[] pdf, byte[] stampImage, Certificate[] chain, PrivateKey pk,
			Collection<CrlClient> crlList, OcspClient ocspClient, String reason, String location, String tsa, float x,
			float y, float width, float height, int pageNo) {

		ByteArrayOutputStream tmpos = new ByteArrayOutputStream();
		try {

			PdfReader reader = new PdfReader(new ByteArrayInputStream(pdf));
			PdfStamper stamper = PdfStamper.createSignature(reader, tmpos, '\0', null, true);
			PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
			appearance.setReason(reason);
			appearance.setLocation(location);
			appearance.setVisibleSignature(new Rectangle(x, y, width, height), pageNo, UUID.randomUUID().toString());
			Image image = Image.getInstance(stampImage);
			appearance.setSignatureGraphic(image);
			appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
			appearance.setRenderingMode(RenderingMode.GRAPHIC);

			Field digestNamesField = DigestAlgorithms.class.getDeclaredField("digestNames");
			digestNamesField.setAccessible(true);
			HashMap<String, String> digestNames = (HashMap<String, String>) digestNamesField.get(null);
			digestNames.put("1.2.156.10197.1.401", "SM3");

			Field allowedDigests = DigestAlgorithms.class.getDeclaredField("allowedDigests");
			allowedDigests.setAccessible(true);
			HashMap<String, String> allowedDigestsNames = (HashMap<String, String>) allowedDigests.get(null);
			allowedDigestsNames.put("SM3", "1.2.156.10197.1.401");

			Field algorithmNamesField = EncryptionAlgorithms.class.getDeclaredField("algorithmNames");
			algorithmNamesField.setAccessible(true);
			HashMap<String, String> algorithmNames = (HashMap<String, String>) algorithmNamesField.get(null);
			algorithmNames.put("1.2.156.10197.1.501", "SM2");

			// SM3的摘要算法
			ExternalDigest digest = new ExternalDigest() {
				@Override
				public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
					return MessageDigest.getInstance("SM3", "BC");
				}
			};

			ExternalSignature signature = new SM2PrivateKeySignature(pk, null);

			TSAClient tsaClient = new TSAClientBouncyCastle(tsa);
			MyMakeSignature.signDetached(appearance, digest, signature, chain, crlList, ocspClient, tsaClient, 0,
					CryptoStandard.CMS);
			return tmpos.toByteArray();
		} catch (Exception e) {
			throw new RuntimeException("PDF签名异常！", e);
		}

	}

	public static void main(String[] args) throws CertificateException, NoSuchProviderException, IOException {

		byte[] pdf = IOUtil.fileToByte("E:\\1.pdf");

		byte[] stampImage = IOUtil.fileToByte("E:\\资料\\资料\\8b23a984922c9ae20217bd0a7aee4b42.png");

		PrivateKey pk = CAUtil.getPrivateKey(
				"MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgtMWubZw6xsbQCUozcxWtIPEN4b8dBbYE+48b3x1vsZ6gCgYIKoEcz1UBgi2hRANCAAS3JP8MpNtnixLD0tranVor1kJ6myULt/j9TxIKiigFveW6lLdNxtEfH5w9cALxV3vhc0aI0bjljUbeRk2xwhN2");

		X509Certificate cert = CAUtil.readX509Certificate(Base64.decodeBase64(
				"MIIDQDCCAuagAwIBAgIQdJXGFWu+QCq/+uzDw8honDAKBggqgRzPVQGDdTBTMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQ2hpbmEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxHDAaBgNVBAMME0NISU5BIFNNMiBQdWJsaWMgQ0EwHhcNMjExMDE4MDQyOTM1WhcNMjIxMDE4MDQyOTM1WjBkMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5bm/5Lic55yBMRIwEAYDVQQHDAnmt7HlnLPluIIxLTArBgNVBAMMJOa3seWcs+a1i+ivleS/oeaBr+aKgOacr+aciemZkOWFrOWPuDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABLck/wyk22eLEsPS2tqdWivWQnqbJQu3+P1PEgqKKAW95bqUt03G0R8fnD1wAvFXe+FzRojRuOWNRt5GTbHCE3ajggGJMIIBhTAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTvutUyPL3nji2IKbeyNmKqjZZfCDAdBgNVHQ4EFgQUNNPSLO02ekf9FXnzH3p2CWQazNYwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly9jcmwuamllZGFuYmEuY24vY3JsL0NISU5BU00yUFVCTElDQ0EuY3JsMH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL29jc3AuamllZGFuYmEuY24vb2NzcC9vY3NwUXVlcnkwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuamllZGFuYmEuY24vY3J0L0NISU5BU00yUFVCTElDQ0EuY3J0MEAGA1UdIAQ5MDcwNQYJYIZIAYb9bAEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMuamllZGFuYmEuY24vY3BzMAoGCCqBHM9VAYN1A0gAMEUCIQDz3qQcK7TVSCGjATcWKoyp4xyXz4pvCsr7M6aaYGxOzwIgBNbG2jZSUvAAraLpMys7hX+VzO1VU5e3BDOKJI4Ds2M="));

		String tsa = "http://159.75.41.25:8082/service/tsa?type=SM2";

		byte[] sign = sign(pdf, stampImage, CAUtil.getCertificateChain(cert.getEncoded()), pk, null, null, "数字签名，不可否认",
				"广东省深圳市南山区", tsa, 100, 100, 120 + 100, 120 + 100, 1);

		FileUtils.writeByteArrayToFile(new File("E:\\sign.pdf"), sign);
	}

}
