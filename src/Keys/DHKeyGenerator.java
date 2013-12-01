package Keys;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class DHKeyGenerator
{
	
	BigInteger g;
	BigInteger p;
	PrivateKey private_key = null;
	
	public DHKeyGenerator(String fileName) throws IOException
	{
		BufferedReader b_reader = null;
		try
		{
			b_reader = new BufferedReader(new FileReader(fileName));
			String string_p = b_reader.readLine();
			String string_g = b_reader.readLine();
			p = new BigInteger(string_p);
			g = new BigInteger(string_g);
		}
		finally
		{
			if(b_reader != null)
				b_reader.close();
		}
	}
	
	
	// write into file with 2 values.
	// The first number is the prime modulus P.
	// The second number is the base generator G.
	public static void generate_DH_params(String fileName) throws GeneralSecurityException, IOException 
	{
        // Create the parameter generator for a 1024-bit DH key pair
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);

        // Generate the parameters
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec
            = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

        BigInteger _p = dhSpec.getP();
        BigInteger _g = dhSpec.getG();
        
    	FileOutputStream fileOutStream=new FileOutputStream(fileName);
		
		try
		{
			fileOutStream.write(_p.toString().getBytes());
			fileOutStream.write("\r\n".getBytes());
			fileOutStream.write(_g.toString().getBytes());
		}
		catch(Exception e)
		{
			throw new IOException("Unexpected error", e);
		
		}
		finally
		{
			fileOutStream.close();
		}
		

	}
	
	public byte[] generate_gx_modp() throws GeneralSecurityException
	{
		// Use the values to generate a key pair
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
	    DHParameterSpec dhSpec = new DHParameterSpec(p, g);
	    keyGen.initialize(dhSpec, new SecureRandom());
	    KeyPair keypair = keyGen.generateKeyPair();

	    // Get the generated public and private keys
	    PublicKey publicKey = keypair.getPublic();
	    private_key = keypair.getPrivate();
	    return publicKey.getEncoded();
	}
	
	public SecretKey generate_secret_key(byte[] public_key_bytes) throws Exception
	{
		if(private_key == null)
			throw new Exception("exponent not generated yet.");
		
		// Convert the public key bytes into a PublicKey object
	    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(public_key_bytes);
	    KeyFactory keyFact = KeyFactory.getInstance("DH");
	    PublicKey publicKey = keyFact.generatePublic(x509KeySpec);
	    
	    // generate the secret key with the private key and public key of the other party
	    KeyAgreement ka = KeyAgreement.getInstance("DH");
	    ka.init(private_key);
	    ka.doPhase(publicKey, true);
	    SecretKey secret =  ka.generateSecret("AES");
	    return secret;
	}
}