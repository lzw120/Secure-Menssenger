package recordtable;

import java.math.BigInteger;
import java.sql.Timestamp;

import javax.crypto.SecretKey;



// on line record
public class onlineitem {
	String user_name;
	String ipaddr;
	int port;
	SecretKey session_key;
	Timestamp create_date;
	Timestamp last_update = new Timestamp(-1);
	
	// create an entry
	public onlineitem (String username, String ip, int port, SecretKey sessionKey) {
		this.user_name = username;
		this.ipaddr = ip;
		this.session_key = sessionKey;
		this.port = port;
		create_date = new Timestamp(System.currentTimeMillis());

	}
	
	public String getUser_name() {
		return user_name;
	}
	public String getIpaddr() {
		return ipaddr;
	}
	public int getPort() {
		return port;
	}
	public SecretKey getSession_key() {
		return session_key;
	}
	public Timestamp getCreate_date() {
		return create_date;
	}
	public Timestamp getLast_update() {
		return last_update;
	}
	
	public void setUser_name(String user_name) {
		this.user_name = user_name;
	}
	public void setIpaddr(String ipaddr) {
		this.ipaddr = ipaddr;
	}
	public void setPort(int port) {
		this.port = port;
	}
	public void setSession_key(SecretKey session_key) {
		this.session_key = session_key;
	}
	public void setCreate_date(Timestamp create_date) {
		this.create_date = create_date;
	}
	public void setLast_update(Timestamp last_update) {
		this.last_update = last_update;
	}
	

}
