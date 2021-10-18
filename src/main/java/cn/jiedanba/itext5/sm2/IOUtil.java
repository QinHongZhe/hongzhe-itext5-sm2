package cn.jiedanba.itext5.sm2;

import java.awt.Image;
import java.awt.Label;
import java.awt.MediaTracker;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import org.apache.commons.io.IOUtils;

public class IOUtil extends IOUtils {

	public static byte[] fileToByte(String filePath) {
		byte[] buffer = null;
		try {
			File file = new File(filePath);
			FileInputStream fis = new FileInputStream(file);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] b = new byte[1024];
			int n;
			while ((n = fis.read(b)) != -1) {
				bos.write(b, 0, n);
			}
			fis.close();
			bos.close();
			buffer = bos.toByteArray();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return buffer;
	}

	/**
	 * 根据byte[] 数组生成文件 （在本地）
	 * 
	 * @param bfile
	 *            字节数组
	 * @param filePath
	 *            文件路径
	 * @param fileName
	 *            文件名
	 */
	public static void getFile(byte[] bfile, String filePath, String fileName) {
		BufferedOutputStream bos = null; // 带缓冲得文件输出流
		FileOutputStream fos = null; // 文件输出流
		File file = null;
		try {
			File dir = new File(filePath);
			if (!dir.exists() && dir.isDirectory()) {// 判断文件目录是否存在
				dir.mkdirs();
			}
			file = new File(filePath + "\\" + fileName); // 文件路径+文件名
			fos = new FileOutputStream(file);
			bos = new BufferedOutputStream(fos);
			bos.write(bfile);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (bos != null) {
				try {
					bos.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
			if (fos != null) {
				try {
					fos.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		}
	}

	/**
	 * 转换BufferedImage 数据为byte数组
	 * 
	 * @param image
	 *            Image对象
	 * @param format
	 *            image格式字符串.如"gif","png"
	 * @return byte数组
	 */
	public static byte[] imageToBytes(BufferedImage bImage, String format) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			ImageIO.write(bImage, format, out);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return out.toByteArray();
	}

	/**
	 * 转换byte数组为Image
	 * 
	 * @param bytes
	 * @return Image
	 */
	public static Image bytesToImage(byte[] bytes) {
		Image image = Toolkit.getDefaultToolkit().createImage(bytes);
		try {
			MediaTracker mt = new MediaTracker(new Label());
			mt.addImage(image, 0);
			mt.waitForAll();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		return image;
	}

	/**
	 * 
	 * byte[] --> BufferedImage
	 * 
	 * @param bytes
	 * @return
	 * @throws IOException
	 * @throws @author
	 *             chenlin
	 * @date Nov 7, 2017 7:46:59 PM
	 */
	public static BufferedImage copyToBufferedImage(byte[] bytes) throws IOException {
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		BufferedImage image = ImageIO.read(bis);
		bis.close();
		bis = null;
		return image;
	}

	/**
	 * byte转 InputSteam
	 * 
	 * @param b
	 * @return
	 */
	public static InputStream byteArrayInputStream(byte[] b) {
		return new ByteArrayInputStream(b);
	}

}
