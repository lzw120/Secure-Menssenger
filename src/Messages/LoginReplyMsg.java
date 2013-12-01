package Messages;

import java.io.Serializable;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import Keys.PBEKeyGenerator;


public class LoginReplyMsg implements Serializable
{
	private byte[] encrypted_partial_key;
	private byte[] encrypted_Y;
	private int c;
	private byte[] iv;
	
	/**
	 * get gb mod p
	 * @throws GeneralSecurityException 
	 */
	public byte[] get_partial_DHkey(String password, String salt) throws GeneralSecurityException
	{
		// generate W from password and salt	
		SecretKey w = PBEKeyGenerator.derive_W(password, salt);	
		
		Cipher cipher = Cipher.getInstance("AES/EBC/ISO10126Padding");
		cipher.init(Cipher.DECRYPT_MODE , w);		
		return cipher.doFinal(encrypted_partial_key);
	}
	
	
	/**
	 *  get private key
	 * @throws GeneralSecurityException 
	 * @throws  
	 */
	public PrivateKey get_RSA_priv_key(String password, String salt, SecretKey dH_key) throws  GeneralSecurityException
	{
		// get Y using DH key
		SecretKey aes_key = new SecretKeySpec(dH_key.getEncoded(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
		cipher.init(Cipher.DECRYPT_MODE , aes_key);	
		byte[] y = cipher.doFinal(encrypted_Y);
		
		// get W2 and decrypt Y
		SecretKey w2 = PBEKeyGenerator.derive_W(password, salt);
		Cipher cipherY = Cipher.getInstance("AES/CBC/ISO10126Padding");
		cipherY.init(Cipher.DECRYPT_MODE , w2);
		byte[] priv_key_bytes  =  cipherY.doFinal(y);
			
		
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(priv_key_bytes);		
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePrivate(privateKeySpec);		
	}

	public void set_encryptedY(byte[] y, SecretKey dH_key) throws GeneralSecurityException
	{
		// encrypt Y using DH key
		SecretKey aes_key = new SecretKeySpec(dH_key.getEncoded(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
		cipher.init(Cipher.ENCRYPT_MODE , aes_key);	
		this.encrypted_Y = cipher.doFinal(y);

	}

	public void set_encrypted_partial_key(byte[] partial_key, SecretKey w) throws GeneralSecurityException
	{		
		Cipher cipher = Cipher.getInstance("AES/EBC/ISO10126Padding");
		cipher.init(Cipher.ENCRYPT_MODE , w);		
		this.encrypted_partial_key = cipher.doFinal(partial_key);
		
	}
	
	public void set_challenge(int c) {
		this.c = c;
	}


	public int get_challenge() {
		return c;
	}
}