package Messages;

import java.io.*;
import java.util.Date;

public class LoginRequest implements Serializable
{
	public String user_name;
	//public long timestamp;

	public String getUser_name() {
		return user_name;
	}

	public void setUser_name(String user_name) {
		this.user_name = user_name;
	}

	
	

}