package Messages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;

import recordtable.*;

import Keys.DHKeyGenerator;

class Logintest
{
	private static String hash_algorithm = "SHA1";
	RecordTable record;
	
	public Logintest() {
		record = new RecordTable();
	}
	
	static public void main2(String[] args)
	{
		try
		{
			// generate p and g for diffie hellman key exchange
			//generate_DH_pg("DH_p_g");
			
			ByteArrayOutputStream byte_output = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byte_output);

			// instantiate LoginReqMsg
			LoginReqMsg login = new LoginReqMsg();
			login.setCookie("I want to talk".getBytes());
			
			LoginRequest request = new LoginRequest("aaa");
			
			
			// get public key of destination from .KEY file and instantiate public key
			RSAPublicKey public_key = (RSAPublicKey) read_in_public_keys(args[0]);
			byte []keybytes;// = readBytesFromFile(args[0]);
//			byte_output.write(keybytjes);
//			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(byte_output.toByteArray());		
			KeyFactory factory = KeyFactory.getInstance("RSA");
//			RSAPublicKey public_key=(RSAPublicKey) factory.generatePublic(publicKeySpec);		
			
			login.setEncrypted_message(request, public_key);
			
			DHKeyGenerator dh_key_gen1 = new DHKeyGenerator("DH_p_g");
			// to be finished
			//login.generatePartial_dh_key(dh_key_gen1);
			
			try
			{		
				
				// serialize			
				out.writeObject(login);					
			
			}
			finally
			{
				out.close();
			}
			
			
			ByteArrayInputStream byte_input = new ByteArrayInputStream(byte_output.toByteArray());
			ObjectInputStream in = new ObjectInputStream(byte_input);
			
			// get destination private key from file 
//			keybytes = readBytesFromFile(args[1]);		
//			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keybytes);		
//			factory=KeyFactory.getInstance("RSA");
//			PrivateKey private_key=factory.generatePrivate(privateKeySpec);	
			RSAPrivateKey private_key = (RSAPrivateKey) read_in_private_keys(args[1]);
			
			try
			{
				// deserialize
				
				LoginReqMsg msg = (LoginReqMsg)in.readObject();	
				
				
				// decrypt msg and deserialize it into obj
				LoginRequest deserialized_request = msg.getLogin_request_object(private_key);
				System.out.println(deserialized_request.user_name);
//				System.out.println(deserialized_request.timestamp);
				DHKeyGenerator dh_key_gen2 = new DHKeyGenerator("DH_p_g");
				
				// generate  DH secret key
				SecretKey dh_key1 = dh_key_gen1.generate_secret_key(dh_key_gen2.generate_gx_modp());
				
				
				// generate DH secret key
				// to be finished
				//SecretKey dh_key2 = dh_key_gen2.generate_secret_key(msg.getPartial_dh_key());
				
				MessageDigest hash = MessageDigest.getInstance(hash_algorithm);
			    System.out.println(new String(hash.digest(dh_key1.getEncoded())));
//			    to be finished
//			    System.out.println(new String(hash.digest(dh_key2.getEncoded())));

			}
			finally
			{
				in.close();
			}
			
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	static private byte[] readBytesFromFile(String fileName) throws IOException
	{
		File f = new File(fileName);
		FileInputStream infile = new FileInputStream(f);
		byte []bytes = new byte[(int)f.length()];
		try
		{
			infile.read(bytes);		
			return bytes;
		}
		finally
		{
			infile.close();
		}
	}
	
	// read public key from file
	public static Object read_in_public_keys(String keyFile) {
		try {
			File file = new File(keyFile);
			int fileLength = (int) file.length();
			byte[] keyData = new byte[fileLength];
			FileInputStream inFileStream = new FileInputStream(keyFile);
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			inFileStream.read(keyData);
			bout.write(keyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bout.toByteArray());
			RSAPublicKey objKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			return objKey;
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Error in read Key" + keyFile);
		return 0;		
	}
	
	// read private key from file	
	public static Object read_in_private_keys(String keyFile) {
		try {
			File file = new File(keyFile);
			int fileLength = (int) file.length();
			byte[] keyData = new byte[fileLength];
			FileInputStream inFileStream = new FileInputStream(keyFile);
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			inFileStream.read(keyData);
			bout.write(keyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec privateKeySpec = new PKCS8EncodedKeySpec(bout.toByteArray());
			RSAPrivateKey objKey = (RSAPrivateKey) keyFactory
					.generatePrivate(privateKeySpec);
			return objKey;
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Error in read Key" + keyFile);
		return 0;
	}
	
	
	static private void generate_DH_pg(String filename) throws GeneralSecurityException, IOException
	{
		DHKeyGenerator.generate_DH_params(filename);
	}
}