package Keys;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.*;

public class PBEKeyGenerator {
	public static SecretKey derive_W(String password, String salt)
			throws GeneralSecurityException {
		int iterationCount = 1000;
		int keyLength = 128;
		PBEKeySpec password_spec = new PBEKeySpec(password.toCharArray(),
				salt.getBytes(), iterationCount, keyLength);
		SecretKeyFactory factory = SecretKeyFactory
				.getInstance("PBKDF2WithHmacSHA1");
		PBEKey key = (PBEKey) factory.generateSecret(password_spec);
		SecretKey encKey = new SecretKeySpec(key.getEncoded(), "AES");
		return encKey;

	}

	public static RSAPrivateKey read_Y_from_file(String pwd, String filename) {
		try {
			FileInputStream fileInputStream;
			fileInputStream = new FileInputStream(filename);
			DataInputStream dis = new DataInputStream(fileInputStream);
			SecretKey w_primeKey = derive_W(pwd, "calculateW2");
			int iv_length = dis.readInt();
			int text_size = dis.readInt();
			byte[] iv = new byte[iv_length];
			byte[] encrypted_key_data = new byte[text_size];
			dis.read(iv);
			dis.read(encrypted_key_data);

			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.DECRYPT_MODE, w_primeKey, new IvParameterSpec(iv)); 
			byte[] key_data = cipher.doFinal(encrypted_key_data);
			
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			bout.write(key_data);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec privateKeySpec = new PKCS8EncodedKeySpec(bout.toByteArray());
			RSAPrivateKey objKey = (RSAPrivateKey) keyFactory
					.generatePrivate(privateKeySpec);
			return objKey;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	public static void write_Y_to_file(String pwd, RSAPrivateKey key,
			String fileName) {
		try {
			FileOutputStream fileOutStream = new FileOutputStream(fileName);
			DataOutputStream dos = new DataOutputStream(fileOutStream);
			SecretKey w_primeKey = derive_W(pwd, "calculateW2");

			// do decryption
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, w_primeKey);
			byte[] iv = cipher.getIV();
			byte[] encrypted_tex = cipher.doFinal(key.getEncoded());
			dos.writeInt(iv.length);
			dos.writeInt(encrypted_tex.length);
			dos.write(iv);
			dos.write(encrypted_tex);
			dos.close();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void write_W_to_file(String pwd, String fileName)
			throws GeneralSecurityException, IOException {
		SecretKey w = derive_W(pwd, "calculateW");

		FileOutputStream fileOutStream = new FileOutputStream(fileName);

		try {
			fileOutStream.write(w.getEncoded());

		} finally {
			fileOutStream.close();
		}
	}

	public static SecretKey read_W_from_file(String fileName)
			throws IOException {
		File file = new File(fileName);
		FileInputStream fileInStream = new FileInputStream(fileName);
		byte[] input_buff = new byte[(int) file.length()];
		try {

			fileInStream.read(input_buff);

		} finally {
			fileInStream.close();
		}

		SecretKey w = new SecretKeySpec(input_buff, "AES");
		return w;

	}
}