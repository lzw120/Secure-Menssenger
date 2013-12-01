package Messages;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;

import javax.crypto.SecretKey;

public class TalkingRequestOrReplyToClient implements Serializable
{
	String source;
	String dest;
	byte[] partial_DH;
	byte[] signature;
	long timestamp1;
	long timestamp2;
	
	public TalkingRequestOrReplyToClient(String from, String to, byte[] a_mod_p,
			RSAPrivateKey key, long t1, long t2) {
		try {
			source = from;
			dest = to;
			partial_DH = a_mod_p;
			timestamp1 = t1;
			timestamp2 = t2;

			Signature sig;
			sig = Signature.getInstance("MD5withRSA");
			sig.initSign(key);
			sig.update(a_mod_p);
			signature = sig.sign();
			
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}
	
	public boolean verify_signature(RSAPublicKey public_key) throws GeneralSecurityException
	{
		Signature sig;
		sig = Signature.getInstance("MD5withRSA");
		sig.initVerify(public_key);
		sig.update(partial_DH);
		return sig.verify(signature);
		
	}
	
	public String getSource() {
		return source;
	}
	public String getDest() {
		return dest;
	}
	public byte[] getPartial_DH() {
		return partial_DH;
	}
	public byte[] getSignature() {
		return signature;
	}

	public void setSource(String source) {
		this.source = source;
	}
	public void setDest(String dest) {
		this.dest = dest;
	}
	public void setPartial_DH(byte[] partial_DH) {
		this.partial_DH = partial_DH;
	}
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public long getTimestamp1() {
		return timestamp1;
	}

	public long getTimestamp2() {
		return timestamp2;
	}

	public void setTimestamp1(long timestamp1) {
		this.timestamp1 = timestamp1;
	}

	public void setTimestamp2(long timestamp2) {
		this.timestamp2 = timestamp2;
	}
}
