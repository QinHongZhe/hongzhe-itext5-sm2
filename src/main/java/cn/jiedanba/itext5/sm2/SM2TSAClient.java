package cn.jiedanba.itext5.sm2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.provider.digest.SM3;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.text.pdf.security.TSAClient;

/**
 * SM2时间戳签名
 * 
 * @author dell
 *
 */
public class SM2TSAClient implements TSAClient {

	private final String url;
	private final String username;
	private final String password;

	public SM2TSAClient(String url) {
		this(url, null, null);
	}

	public SM2TSAClient(String url, String username, String password) {
		this.url = url;
		this.username = username;
		this.password = password;

	}

	@Override
	public int getTokenSizeEstimate() {
		return 4096;
	}

	@Override
	public MessageDigest getMessageDigest() throws GeneralSecurityException {
		MessageDigest digest = new SM3.Digest();
		return digest;
	}

	@Override
	public byte[] getTimeStampToken(byte[] imprint) throws Exception {

		// 32-bit cryptographic nonce
		SecureRandom random = new SecureRandom();
		int nonce = random.nextInt();

		// generate TSA request
		TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
		tsaGenerator.setCertReq(true);
		ASN1ObjectIdentifier oid = GMObjectIdentifiers.sm3;
		TimeStampRequest request = tsaGenerator.generate(oid, imprint, BigInteger.valueOf(nonce));

		// get TSA response
		byte[] tsaResponse = getTSAResponse(request.getEncoded());

		TimeStampResponse response;
		try {
			response = new TimeStampResponse(tsaResponse);
			response.validate(request);
		} catch (TSPException e) {
			throw new IOException(e);
		}

		TimeStampToken token = response.getTimeStampToken();
		if (token == null) {
			throw new IOException("Response does not have a time stamp token");
		}

		return token.getEncoded();
	}

	// gets response data for the given encoded TimeStampRequest data
	// throws IOException if a connection to the TSA cannot be established
	private byte[] getTSAResponse(byte[] request) throws IOException {

		URLConnection connection = new URL(url).openConnection();
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setRequestProperty("Content-Type", "application/timestamp-query");

		if (username != null && password != null && !username.isEmpty() && !password.isEmpty()) {
			connection.setRequestProperty(username, password);
		}

		// read response
		OutputStream output = null;
		try {
			output = connection.getOutputStream();
			output.write(request);
		} finally {
			IOUtils.closeQuietly(output);
		}

		InputStream input = null;
		byte[] response;
		try {
			input = connection.getInputStream();
			response = IOUtils.toByteArray(input);
		} finally {
			IOUtils.closeQuietly(input);
		}

		return response;
	}

}
