package Messages;

import java.io.*;
import java.util.Date;

public class LoginRequest implements Serializable
{
	public String user_name;
	//public long timestamp;

	public LoginRequest(String name)
	{
		user_name = name;
		//timestamp = new Date().getTime();
		
	}
	

}