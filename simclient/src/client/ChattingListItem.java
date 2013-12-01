package client;

import java.math.BigInteger;
import java.security.Timestamp;
import java.security.interfaces.RSAPublicKey;

class ChattingListItem
{
	String user_name;
	String ipaddr;
	int port;
	BigInteger sessionKey;
	RSAPublicKey public_key;
	Timestamp expir_time;
	
	public Boolean is_expried()
	{
		return false;
	}
	
}