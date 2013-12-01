package Messages;

import java.io.Serializable;
import java.security.Timestamp;

public class LogoutACK  implements Serializable
{
	private String iniciator;
	private String replyer;	
	private long timestamp;
	
	public LogoutACK(String iniciator, String replyer)
	{
		this.iniciator = iniciator;
		this.replyer = replyer;
		
	}
	
	public String getIniciator() {
		return iniciator;
	}
	
	public String getReplyer() {
		return replyer;
	}
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	public long getTimestamp() {
		return timestamp;
	}
	
}