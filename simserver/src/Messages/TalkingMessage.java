package Messages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.sampled.AudioFormat.Encoding;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import Keys.DHKeyGenerator;
import Keys.PBEKeyGenerator;

public class TalkingMessage implements Serializable
{
	private byte[] encryptedMsg;
	private String hmac;
	private message_type type;
	byte[] iv;
	public int local_port;
	byte[] encrypted_aes;
	
	/**
	 * get serialized plain message
	 */
	public byte[] decryptMsg_session_key(SecretKey key)
	{
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));		
			return cipher.doFinal(encryptedMsg);
			
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
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	byte[] decryptMsg_rsa_key(RSAPrivateKey key)
	{
		Cipher rsacipher;
		try {
			rsacipher = Cipher.getInstance("RSA");
			rsacipher.init(Cipher.DECRYPT_MODE, key);		
			byte[] key_data = rsacipher.doFinal(encrypted_aes);
			
			SecretKeySpec aes_key = new SecretKeySpec(key_data, "AES");
			
			Cipher aes_cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			aes_cipher.init(Cipher.DECRYPT_MODE, aes_key, new IvParameterSpec(iv));		
			return aes_cipher.doFinal(encryptedMsg);
			
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
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	
	/**
	 * @return Object stands for
	 * TalkingRequestToServer
	 * TalkingReplyFromServer
	 * TalkingRequestOrReplyToClient
	 * String
	 * TalkingContent
	 * LogoutRequest
	 * LogoutACK
	 * 
	 */
	public Object deserializeMsg(byte[] decrypted)
	{
		try {
			ByteArrayInputStream byte_input =  new ByteArrayInputStream(decrypted);
			ObjectInputStream in;
			in = new ObjectInputStream(byte_input);
			return in.readObject();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	
	public void setEncrypted_message_rsa_key(TalkingRequestOrReplyToClient talk_req, RSAPublicKey public_key)
	{
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecureRandom random = new SecureRandom();
			keygen.init(random);
			SecretKey key = keygen.generateKey();
			
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(talk_req);
			byte[] serialized_msg = byte_output.toByteArray();
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			iv = cipher.getIV();
			byte[] encrypted = cipher.doFinal(serialized_msg);
			this.encryptedMsg = encrypted;
			
			hmac = generate_HMAC_rsa_key(serialized_msg, public_key);
			
			Cipher rsacipher = Cipher.getInstance("RSA");
			rsacipher.init(Cipher.ENCRYPT_MODE, public_key);
			byte[] encrypted_key = rsacipher.doFinal(key.getEncoded());
			
			encrypted_aes = encrypted_key;
//			this.encryptedMsg = encrypted;
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
	}
	
	public void setEncrypted_message_session_key(TalkingRequestToServer talk_req, SecretKey session_key)
	{
		try {
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(talk_req);
			out.flush();
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_session_key(serialized_msg, session_key);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
			iv = cipher.getIV();
			byte[] encrypted = cipher.doFinal(serialized_msg);
			this.encryptedMsg = encrypted;
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
	}
	
	public void setEncrypted_message_session_key(TalkingContent talking_content, SecretKey session_key)
	{
		try {
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(talking_content);
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_session_key(serialized_msg, session_key);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
			iv = cipher.getIV();
			byte[] encrypted = cipher.doFinal(serialized_msg);
			this.encryptedMsg = encrypted;
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public void setEncrypted_message_session_key(TalkingReplyFromServer talking_reply, SecretKey session_key)
	{
		try {
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(talking_reply);
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_session_key(serialized_msg, session_key);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
			iv = cipher.getIV();
			byte[] encrypted = cipher.doFinal(serialized_msg);
			this.encryptedMsg = encrypted;
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public void setEncrypted_message_session_key(LogoutRequest logout_req, SecretKey session_key)
	{
		try {
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(logout_req);
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_session_key(serialized_msg, session_key);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
			iv = cipher.getIV();
			byte[] encrypted = cipher.doFinal(serialized_msg);
			this.encryptedMsg = encrypted;
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public void setEncrypted_message_session_key(LogoutACK logout_ack, SecretKey session_key)
	{
		try {
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(logout_ack);
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_session_key(serialized_msg, session_key);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
			iv = cipher.getIV();
			byte[] encrypted = cipher.doFinal(serialized_msg);
			this.encryptedMsg = encrypted;
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public Object get_talking_request_to_server(SecretKey session_key) 
			throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg_session_key(session_key);
		return deserializeMsg(decrypted);
	}
	
	public LogoutRequest get_logout_request(SecretKey session_key)
	{
		byte[] decrypted = decryptMsg_session_key(session_key);
		return (LogoutRequest) deserializeMsg(decrypted);
	}
	
	public TalkingContent get_talking_content_object(SecretKey session_key) 
	throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg_session_key(session_key);
		return (TalkingContent)deserializeMsg(decrypted);
	}
	
	public TalkingReplyFromServer get_talking_reply_from_server(SecretKey session_key) 
	throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg_session_key(session_key);
		return (TalkingReplyFromServer)deserializeMsg(decrypted);
	}
	
	public TalkingRequestOrReplyToClient get_talking_request_or_reply_object(RSAPrivateKey private_key) 
			throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg_rsa_key(private_key);
		return (TalkingRequestOrReplyToClient) deserializeMsg(decrypted);
	}
	
	public String generate_HMAC_session_key(byte[] message, SecretKey key)
	{
		try {
			String result;
		    // Generate a key for the HMAC-MD5 keyed-hashing algorithm; see RFC 2104
			
			SecretKeySpec signingKey = new SecretKeySpec(key.getEncoded(), "HmacMD5");

			// get an hmac_sha1 Mac instance and initialize with the signing key
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(signingKey);

			// compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(message);

			// base64-encode the hmac
			return new HexBinaryAdapter().marshal(rawHmac);

	
		} 
		catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return null;
	}
	
	public String generate_HMAC_rsa_key(byte[] message, RSAPublicKey key)
	{
		try {
			String result;
		    // Generate a key for the HMAC-MD5 keyed-hashing algorithm; see RFC 2104
			
			SecretKeySpec signingKey = new SecretKeySpec(key.getEncoded(), "HmacMD5");

			// get an hmac_sha1 Mac instance and initialize with the signing key
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(signingKey);

			// compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(message);

			// base64-encode the hmac
			return new HexBinaryAdapter().marshal(rawHmac);
	
		} 
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}
	
	public Boolean verify_HMAC_session_key(SecretKey key) {
		
		String myHmac = generate_HMAC_session_key(decryptMsg_session_key(key), key);
		return myHmac.equals(hmac);
	}
	
	/**
	 * verify hmac
	 * @return 
	 */
	public Boolean verify_HMAC_rsa_key(RSAPublicKey public_key, RSAPrivateKey private_key) {
		
		String myHmac = generate_HMAC_rsa_key(decryptMsg_rsa_key(private_key), public_key);
		return myHmac.equals(hmac);
	}


	public byte[] get_partial_DHkey(DHKeyGenerator dh_key_gen)
	{
			// generate DH partial key
			try {
				byte[] partial_key = dh_key_gen.generate_gx_modp();
				return partial_key;
				
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		}

	public void setType(message_type type) {
		this.type = type;
	}

	public message_type getType() {
		return type;
	}
}