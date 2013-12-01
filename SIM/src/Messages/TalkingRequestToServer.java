package Messages;

import java.io.Serializable;

public class TalkingRequestToServer implements Serializable
{
	String source;
	String dest;
	public TalkingRequestToServer(String from, String to)
	{
		source = from;
		dest = to;
	}
	public String getSource() {
		return source;
	}
	public String getDest() {
		return dest;
	}
	public void setSource(String source) {
		this.source = source;
	}
	public void setDest(String dest) {
		this.dest = dest;
	}
}