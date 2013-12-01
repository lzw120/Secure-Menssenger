package Messages;

import java.io.Serializable;
import java.util.Date;

public class TalkingContent implements Serializable
{
	private String content;
	private long timestamp;
	
	public TalkingContent(String content, long timestamp)
	{
		this.content = content;
		this.timestamp = timestamp; 
	}

	public String getContent() {
		return content;
	}

	public long getTimestamp() {
		return timestamp;
	}
	
}