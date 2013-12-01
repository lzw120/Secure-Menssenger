package Messages;

import java.math.BigInteger;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.sql.Timestamp;

public class TalkingRequestOrReplyToClient
{
	String source;
	String dest;
	byte[] partial_DH;
	byte[] signature;
	Timestamp timestamp;
	
	public TalkingRequestOrReplyToClient(String from, String to, byte[] a_mod_p,
			RSAPrivateKey key, Timestamp t) {
		try {
			source = from;
			dest = to;
			partial_DH = a_mod_p;
			timestamp = t;

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
	public Timestamp getTimestamp() {
		return timestamp;
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
	public void setTimestamp(Timestamp timestamp) {
		this.timestamp = timestamp;
	}
}
