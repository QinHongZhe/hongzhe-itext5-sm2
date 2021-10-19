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
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfSignatureAppearance.RenderingMode;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.EncryptionAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
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
	public static byte[] sm2Sign(byte[] pdf, byte[] stampImage, Certificate[] chain, PrivateKey pk,
			Collection<CrlClient> crlList, OcspClient ocspClient, String reason, String location, String tsa, float x,
			float y, float width, float height, int pageNo) {

		ByteArrayOutputStream tmpos = new ByteArrayOutputStream();
		try {

			PdfReader reader = new PdfReader(new ByteArrayInputStream(pdf));
			PdfStamper stamper = PdfStamper.createSignature(reader, tmpos, '\0', null, true);
			PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
			appearance.setReason(reason);
			appearance.setLocation(location);
			appearance.setVisibleSignature(new Rectangle(x, y, width, height), pageNo, appearance.getNewSigName());
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

	public static byte[] rsaSign(byte[] pdf, byte[] stampImage, Certificate[] chain, PrivateKey pk,
			Collection<CrlClient> crlList, OcspClient ocspClient, String reason, String location, String tsa, float x,
			float y, float width, float height, int pageNo) {

		ByteArrayOutputStream tmpos = new ByteArrayOutputStream();
		try {

			PdfReader reader = new PdfReader(new ByteArrayInputStream(pdf));
			PdfStamper stamper = PdfStamper.createSignature(reader, tmpos, '\0', null, true);
			PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
			appearance.setReason(reason);
			appearance.setLocation(location);
			appearance.setVisibleSignature(new Rectangle(x, y, width, height), pageNo, appearance.getNewSigName());
			Image image = Image.getInstance(stampImage);
			appearance.setSignatureGraphic(image);
			appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
			appearance.setRenderingMode(RenderingMode.GRAPHIC);

			ExternalDigest digest = new BouncyCastleDigest();

			ExternalSignature signature = new PrivateKeySignature(pk, "SHA-256", null);

			TSAClient tsaClient = new TSAClientBouncyCastle(tsa);
			MyMakeSignature.signDetached(appearance, digest, signature, chain, crlList, ocspClient, tsaClient, 0,
					CryptoStandard.CMS);
			return tmpos.toByteArray();
		} catch (Exception e) {
			throw new RuntimeException("PDF签名异常！", e);
		}

	}

	public static void main(String[] args) throws CertificateException, NoSuchProviderException, IOException {
		// rsaSignTest();

		sm2SignTest();
	}

	public static void rsaSignTest() throws CertificateException, NoSuchProviderException, IOException {
		byte[] pdf = IOUtil.fileToByte("E:\\1.pdf");

		byte[] stampImage = IOUtil.fileToByte("E:\\资料\\资料\\8b23a984922c9ae20217bd0a7aee4b42.png");

		PrivateKey pk = CAUtil.getPrivateKey(
				"MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDJALDi0ozbUKSHVyE5D7SFsfLlEWRnuSphCqkLlOy8Zh9UtfD3s7ZWpnpRMivZD2iInSkaeqLJnPSXZ9RQQtT7YYAVIZ92ihQcfE7Eu0FvGhdYvh2BL9gEcNpjsmC6p2PQIxJuBuCFliyfwEQBQzrNJZNoGbK7kSX0pvYwPGP14XvFUuB/tu/5+LEQ8Bejaz1N3Z7EyIyC/1D4CA+pQC5JaRM3l17hqDoVcLgkoxWYd+haE52Y2COJLoOCHC1N2lo4QO4ISuGQCHhMSRDf5qEQHqCniDP/5mO3WVNlt1chWkFKAO57YsZ8WMxKI0FMuOituHfyDuONMESCuXxcIKGhAgMBAAECggEBAMPdjoCY13VnEcxoVRF7gle9XYll90czol5Juwx0JHQ5t1IesR9O2eF5/Dte/mdXom9tZf5Nfo+kCJv5K2TCmzQSgHMW/oLObmaLo14Fcu/GpvVs3OdkLcW2CrmXurZoItVRN8ZLoUHLYtSQ0DPCxWver9ODJy2rdScAA2phjq6rPVGN8IyN38YJx/xQkNkU3pqHJuJ4ZItr7ISVfO+KuYmIohj0GmRIDWKkm4Y0mrsnwox4egShYcO0EBG31xx2mPaMv6BwULbxOLh6L58cay+uVqFW4tuDiiLxrYqtjTqunOy4UZ0bxStwdjSwukecUIoNhiO/c2qN7gEF/TmSNIECgYEA9HpVNBsforH+7FfgJflg5vWW9AGrjVzgLJEr+HY6JLhxaZQ1UUeGCiNiHALS7FGiA3REQbJu4xo7CTdIt83ivD2SKGeGJxZPK7DnjoHv7k5fi+5zyBbqpYVHT/AqlG2ae3Z+MwULV5PSW7DJxpyNzqOI7gIKkRKkrLhBfh39g0kCgYEA0nnSpvilAperVdHC5rbJ+9kdZXpwgCv/Ft3YIctF8mUxPol0TZgzGNpbpbeuBRZu5bDDdZlZ9AAQjqxRC+UbQ6bhEE/ySTnsKYphb8s3D1LzDDnW3zy23iqlqG3x8GhjInPeEmdujdFv1R+H97VYW9QDPAlYWs8CkTaAbzEo05kCgYEAi7iqn1ftEZ+msM5cJXfLwNOVDSkzMVxmJjJlrd9rxXbAInX4rtYwrfSg6p9WiobxEAZPyDhBFXv1R4QYBCwfrDOIJ51a11Xxs2esPw7V4B1cj+2csDsgqa5tHiuFOkUVqAAFigUVAV1TOOHlv6PTi8h8xoHWJilAghHgJELhkzkCgYEAq6x//H8MoHuzXZF1ZperUke6KX5f6rt4Gl+inZXenKKbMwYMngnJi7j3TcjvIOk2VRUDqJUHgPTYjHbSuGAMB/dC1fpPhhi/nvZnGTdo1o/y/ILk1zr/cWDZs/LRhyStz3kwplRFIVm13OEWFx6MToI0jTCWJ6N31Zfd1FQFl+kCgYEAxfZITAS5m+Nbp8HoTeAXzXf3GfLP4dI1AGxUzKx4kUTgRSIoZUNw7XlD79HgGBHno5kLkEaNvOcifOjFhGRcF2vClCDOYQwZYzqW0tR2bBu0A4vwm+loIZSEJfyDcpPPQ49OD7JTi05zsxz+d2v6Ld8WvpxeaJAh50+7sPYgeH8=");

		X509Certificate cert = CAUtil.readX509Certificate(Base64.decodeBase64(
				"MIIE1zCCA7+gAwIBAgIKZ8PD4OpWojc1LjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQ2hpbmEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxGTAXBgNVBAMMEENOQ0EgSWRlbnRpdHkgQ0EwHhcNMjExMDE5MDgxMDQwWhcNMjMxMDE5MDgxMDQwWjCBhDELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeW5v+S4nOecgTESMBAGA1UEBwwJ5rex5Zyz5biCMRswGQYDVQQKDBI5MTQ0MDMwMDcwODQ2MTEzNlQxMDAuBgNVBAMMJ+a3seWcs+W4gua1i+ivleS/oeaBr+aKgOacr+aciemZkOWFrOWPuDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkAsOLSjNtQpIdXITkPtIWx8uURZGe5KmEKqQuU7LxmH1S18PeztlamelEyK9kPaIidKRp6osmc9Jdn1FBC1PthgBUhn3aKFBx8TsS7QW8aF1i+HYEv2ARw2mOyYLqnY9AjEm4G4IWWLJ/ARAFDOs0lk2gZsruRJfSm9jA8Y/Xhe8VS4H+27/n4sRDwF6NrPU3dnsTIjIL/UPgID6lALklpEzeXXuGoOhVwuCSjFZh36FoTnZjYI4kug4IcLU3aWjhA7ghK4ZAIeExJEN/moRAeoKeIM//mY7dZU2W3VyFaQUoA7ntixnxYzEojQUy46K24d/IO440wRIK5fFwgoaECAwEAAaOCAXwwggF4MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFFdW85WWZMLYHYxEJoHpUrhIolVTMB0GA1UdDgQWBBQ4/Qztu7HbbGWThEmmx8+M3n635TASBgZngQwBAgEECBYGVGVzdENBMCwGA1UdJQEB/wQiMCAGCCsGAQUFBwMCBgorBgEEAYI3CgMMBggrBgEFBQcDBDAqBgNVHR8EIzAhMB+gHaAbhhlodHRwOi8vMTI3LjAuMC4xL3Rlc3QuY3JsMFgGCCsGAQUFBwEBBEwwSjAhBggrBgEFBQcwAYYVaHR0cDovLzEyNy4wLjAuMS9vY3NwMCUGCCsGAQUFBzAChhlodHRwOi8vMTI3LjAuMC4xL3Rlc3QuY3J0MFAGA1UdIARJMEcwNwYGZ4EMAQICMC0wKwYIKwYBBQUHAgEWH2h0dHA6Ly8xMjcuMC4wLjEvcmVwb3NpdG9yeS9jcHMwDAYKUwYBBAHWeQIFAzANBgkqhkiG9w0BAQsFAAOCAQEANHBcvtBp1N6TEWOfc59xOewQOam8CpHy1gZwrtgq50YwQNAjzdocXV4RJrEvUMRVwLpWqTYM9kAd2nNKs4l7W4pi99GTPBp1+XwvNuzaqDrK1HzCT0RgBPxxsz8jvZDjJWcqFrjpMvoZJ3D17mS/ewMttC+se8WmbMciPNYC/wfhWSTTR5sz287e+QWB9hRCcOFPbFXexAiAG3EfgOJXdy5E9tVBF8u26nJxxjkUYtBeutCyxFZ0S7qvtzq9g3t8by+/Y50rn+YU1rfD8xd7xVK676tLZ21OnrLNWM6uEVKoXhEdiiQZfnYC0eLIfxxodqGarkiYzglqWdwu2RSeuQ=="));

		String tsa = "http://159.75.41.25:8082/service/tsa?type=RSA";

		byte[] sign = rsaSign(pdf, stampImage, CAUtil.getCertificateChain(cert.getEncoded()), pk, null, null,
				"数字签名，不可否认", "广东省深圳市南山区", tsa, 100, 100, 120 + 100, 120 + 100, 1);

		FileUtils.writeByteArrayToFile(new File("E:\\rsasign.pdf"), sign);
	}

	public static void sm2SignTest() throws CertificateException, NoSuchProviderException, IOException {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		byte[] pdf = IOUtil.fileToByte("E:\\1.pdf");

		byte[] stampImage = IOUtil.fileToByte("E:\\资料\\资料\\8b23a984922c9ae20217bd0a7aee4b42.png");

		PrivateKey pk = CAUtil.getPrivateKey(
				"ME0CAQAwEwYHKoZIzj0CAQYIKoEcz1UBgi0EMzAxAgEBBCDUQcmurIXuqrhx1o/vBOR8QFSRTAAOj8QVQ8boBYen2aAKBggqgRzPVQGCLQ==");

		X509Certificate cert = CAUtil.readX509Certificate(Base64.decodeBase64(
				"MIIDYjCCAwigAwIBAgIKITYNn6XXXzdfyTAKBggqgRzPVQGDdTBqMQswCQYDVQQGEwJDTjEmMCQGA1UECgwdQ2hpbmEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFDASBgNVBAsMC1NNMiBSb290IENBMR0wGwYDVQQDDBRDTkNBIEdsb2JhbCBSb290IENBMjAeFw0yMTEwMTkwODMwMjJaFw0yMzEwMTkwODMwMjJaMIGEMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5bm/5Lic55yBMRIwEAYDVQQHDAnmt7HlnLPluIIxGzAZBgNVBAoMEjkxNDQwMzAwNzA4NDYxMTM2VDEwMC4GA1UEAwwn5rex5Zyz5biC5rWL6K+V5L+h5oGv5oqA5pyv5pyJ6ZmQ5YWs5Y+4MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEhFu/0p933mdBn7vH2Ode0GATlvKFBnSqTOX//kkt7KIJTftYbB2B+sO8f7IMj74HsWTGgztDmoQE93yd8TVdiKOCAXkwggF1MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFLRr/7qwdSqYra2Rq5mfCTVhD0wHMB0GA1UdDgQWBBRkVtM+Di8FXiiJE+7iSwa59g3+izASBgZngQwBAgEECBYGVGVzdENBMCwGA1UdJQEB/wQiMCAGCCsGAQUFBwMCBgorBgEEAYI3CgMMBggrBgEFBQcDBDAqBgNVHR8EIzAhMB+gHaAbhhlodHRwOi8vMTI3LjAuMC4xL3Rlc3QuY3JsMFgGCCsGAQUFBwEBBEwwSjAhBggrBgEFBQcwAYYVaHR0cDovLzEyNy4wLjAuMS9vY3NwMCUGCCsGAQUFBzAChhlodHRwOi8vMTI3LjAuMC4xL3Rlc3QuY3J0ME0GA1UdIARGMEQwNAYGZ4EMAQICMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly8xMjcuMC4wLjEvcmVwb3NpdG9yeS8wDAYKKwYBBAHWeQIFAzAKBggqgRzPVQGDdQNIADBFAiAey0hcR3eBRtIjEDiLZttCTmuVQYtofjDLVbrXeKQklQIhAKAh4jrlfK/9WecB3TPcHaS/H+H5TOIH5JB4Tq3jW+tQ"));

		String tsa = "http://159.75.41.25:8082/service/tsa?type=SM2";

		byte[] sign = sm2Sign(pdf, stampImage, CAUtil.getCertificateChain(cert.getEncoded()), pk, null, null,
				"数字签名，不可否认", "广东省深圳市南山区", tsa, 100, 100, 120 + 100, 120 + 100, 1);

		FileUtils.writeByteArrayToFile(new File("E:\\sign.pdf"), sign);
	}

}
