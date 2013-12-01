package Messages;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import Keys.DHKeyGenerator;
import Keys.PBEKeyGenerator;



public class LoginReqMsg implements Serializable
{
	private byte[] encrypted_message;
	private byte[] encrypted_partial_dh_key;
	private byte[] cookie;
	private byte[] iv;
	
	final public message_type TYPE = message_type.Login_REQ;
	
	
	byte[] decryptMsg(RSAPrivateKey private_key) throws GeneralSecurityException
	{
		Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, private_key);		
		return cipher.doFinal(encrypted_message);
	}
	
	
	LoginRequest deserialize_msg(byte[] decrypted) throws IOException, ClassNotFoundException
	{
		ByteArrayInputStream byte_input =  new ByteArrayInputStream(decrypted);
		ObjectInputStream in = new ObjectInputStream(byte_input);
		return (LoginRequest)in.readObject();
	}

	public LoginRequest getLogin_request_object(RSAPrivateKey private_key) throws GeneralSecurityException, IOException, ClassNotFoundException
	{
		byte[] decrypted = decryptMsg(private_key);
		return deserialize_msg(decrypted);
	}
	
	public void setEncrypted_message(LoginRequest login_req, RSAPublicKey public_key) throws GeneralSecurityException, IOException 
	{
		ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(byte_output);
		out.writeObject(login_req);
		byte[] serialized_msg = byte_output.toByteArray();
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, public_key);
		byte[] encrypted = cipher.doFinal(serialized_msg);
		this.encrypted_message = encrypted;
	}

	public void setEncrypted_partial_dh_key(DHKeyGenerator dh_key_gen, String password) throws GeneralSecurityException 
	{
		// generate W from password and salt
		String salt = "calculateW";	
		SecretKey w = PBEKeyGenerator.derive_W(password, salt);	
		
		
		// generate DH partial key
		byte[] partial_key = dh_key_gen.generate_gx_modp();
		
		// do encryption
		Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
		cipher.init(Cipher.ENCRYPT_MODE, w);		
		iv = cipher.getIV();
		this.encrypted_partial_dh_key = cipher.doFinal(partial_key);
		
	}

	public byte[] getPartial_dh_key(SecretKey w) throws GeneralSecurityException 
	{
		
		// do decryption
		Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
		cipher.init(Cipher.DECRYPT_MODE, w, new IvParameterSpec(iv));			
		return cipher.doFinal(this.encrypted_partial_dh_key);
	}


	
	public void setCookie(byte[] cookie) 
	{
		this.cookie = cookie;
	}

	public byte[] getCookie() 
	{
		return cookie;
	}

	
	
}

