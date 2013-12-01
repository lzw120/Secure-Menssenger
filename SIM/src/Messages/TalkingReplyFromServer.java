package Messages;

import java.io.Serializable;
import java.security.interfaces.RSAPublicKey;

public class TalkingReplyFromServer implements Serializable
{
	public String dest;
	public String ipaddress;
	public int port;
	public RSAPublicKey dest_publickey;
	
	public TalkingReplyFromServer (String to, String ip, int port, RSAPublicKey key)
	{
		dest = to;
		ipaddress =ip;
		this.port = port;
		dest_publickey = key;
	}

	public String getDest() {
		return dest;
	}

	public String getIpaddress() {
		return ipaddress;
	}

	public int getPort() {
		return port;
	}

	public RSAPublicKey getDest_publickey() {
		return dest_publickey;
	}

	public void setDest(String dest) {
		this.dest = dest;
	}

	public void setIpaddress(String ipaddress) {
		this.ipaddress = ipaddress;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void setDest_publickey(RSAPublicKey dest_publickey) {
		this.dest_publickey = dest_publickey;
	}
	
	
	
	
}