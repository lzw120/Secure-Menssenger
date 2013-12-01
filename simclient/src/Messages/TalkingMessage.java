package Messages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import Keys.DHKeyGenerator;
import Keys.PBEKeyGenerator;

public class TalkingMessage
{
	public byte[] encryptedMsg;
	public byte[] hmac;
	public message_type type;

	
	/**
	 * get serialized plain message
	 */
	public byte[] decryptMsg_session_key(SecretKey key)
	{
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);		
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
		}
		return null;
	}
	
	public byte[] decryptMsg_rsa_key(RSAPrivateKey key)
	{
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);		
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
		}
		return null;
	}
	
	
	/**
	 * @return Object stands for
	 * TalkingRequestToServer
	 * TalkingReplyFromServer
	 * TalkingRequestOrReplyToClient
	 * String
	 * 
	 */
	public Object deserializeMsg(byte[] decrypted)
	{
		try {
			ByteArrayInputStream byte_input =  new ByteArrayInputStream(decrypted);
			ObjectInputStream in;
			in = new ObjectInputStream(byte_input);
			return (TalkingRequestToServer)in.readObject();
			
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
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(talk_req);
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_rsa_key(serialized_msg, public_key);
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, public_key);
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
	
	public void setEncrypted_message_session_key(TalkingRequestToServer talk_req, SecretKey session_key)
	{
		try {
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out;
			out = new ObjectOutputStream(byte_output);
			out.writeObject(talk_req);
			byte[] serialized_msg = byte_output.toByteArray();
			
			hmac = generate_HMAC_session_key(serialized_msg, session_key);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
			cipher.init(Cipher.ENCRYPT_MODE, session_key);
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
	
	public Object get_talking_request_object(SecretKey session_key) 
			throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg_session_key(session_key);
		return deserializeMsg(decrypted);
	}
	
	
	public TalkingRequestOrReplyToClient get_talking_request_or_reply_object(RSAPrivateKey private_key) 
			throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg_rsa_key(private_key);
		return (TalkingRequestOrReplyToClient) deserializeMsg(decrypted);
	}
	
	
	public byte[] generate_HMAC_session_key(byte[] message, SecretKey key)
	{
		try {
		    // Generate a key for the HMAC-MD5 keyed-hashing algorithm; see RFC 2104
		    // In practice, you would save this key.
		    KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");

		    // Create a MAC object using HMAC-MD5 and initialize with key
		    Mac mac = Mac.getInstance(key.getAlgorithm());
		    mac.init(key);
			
		    return mac.doFinal(message);
	
		} 
		catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] generate_HMAC_rsa_key(byte[] message, RSAPublicKey key)
	{
		try {
		    // Generate a key for the HMAC-MD5 keyed-hashing algorithm; see RFC 2104
		    // In practice, you would save this key.
		    KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");

		    // Create a MAC object using HMAC-MD5 and initialize with key
		    Mac mac = Mac.getInstance(key.getAlgorithm());
		    mac.init(key);
			
		    return mac.doFinal(message);
	
		} 
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}
	
	public Boolean verify_HMAC_session_key(SecretKey key) {
		
		byte[] myHmac = generate_HMAC_session_key(decryptMsg_session_key(key), key);
		return myHmac.equals(hmac);
	}
	
	/**
	 * verify hmac
	 * @return 
	 */
	public Boolean verify_HMAC_rsa_key(RSAPublicKey public_key, RSAPrivateKey private_key) {
		
		byte[] myHmac = generate_HMAC_rsa_key(decryptMsg_rsa_key(private_key), public_key);
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
}