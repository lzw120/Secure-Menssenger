package Messages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import Keys.DHKeyGenerator;

class VerificationMsg {
	String user_name;
	byte[] signature;
};

public class Verification implements Serializable {
	public byte[] encrypted_message;
	final public message_type type = message_type.Verify;

	/**
	 * get serialized user name and signature
	 */
	public VerificationMsg decryptMsg(SecretKey key) {
		try {
			Cipher cipher;
			cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return deserialize_msg(cipher.doFinal(encrypted_message));

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	public byte[] set_encrypted_message(RSAPrivateKey private_key,
			SecretKey session_key, int challenge) {
		// 1. generate signature
		Signature signature;
		try {
			signature = Signature.getInstance("MD5withRSA");
			signature.initSign(private_key);
			signature.update(session_key.getEncoded());
			signature.update(intToBytes(challenge));
			byte signatureData[] = signature.sign();

			// 2. encrypt with session key
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
			return cipher.doFinal(signatureData);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	VerificationMsg deserialize_msg(byte[] decrypted) {
		try {
			ByteArrayInputStream byte_input = new ByteArrayInputStream(
					decrypted);
			ObjectInputStream in;
			in = new ObjectInputStream(byte_input);
			return (VerificationMsg) in.readObject();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	static byte[] intToBytes(int my_int) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = new ObjectOutputStream(bos);
		out.writeInt(my_int);
		out.close();
		byte[] int_bytes = bos.toByteArray();
		bos.close();
		return int_bytes;
	}

	public boolean Verify(PublicKey public_key, SecretKey session_key,
			int challenge) {
		VerificationMsg verify_msg = decryptMsg(session_key);
		try {
			Signature signature = Signature.getInstance("MD5withRSA");
			signature.initVerify(public_key);
			signature.update(session_key.getEncoded());
			signature.update(intToBytes(challenge));
			// if verified correct
			return signature.verify(verify_msg.signature);

		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

};
