package Messages;

import java.io.Serializable;
import java.security.Timestamp;

public class LogoutRequest  implements Serializable
{
	private String iniciator;
	private long timestamp;
	
	public LogoutRequest(String iniciator)
	{
		this.iniciator = iniciator;
	}
	
	public String getIniciator() {
		return iniciator;
	}
	
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	
	public long getTimestamp() {
		return timestamp;
	}
	
	
}