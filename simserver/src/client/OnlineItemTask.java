package client;


import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.TimerTask;

import recordtable.*;

import recordtable.onlineitem;

class OnlineItemTask extends TimerTask
{
	RecordTable recordtable;
	HashMap<String, onlineitem> online_items;
	
	// delete an entry if it is created for 5min
	long DURATION ;
	
	/**
	 * set a TimerTask instance to delete online clients 
	 * stay longer than a duration in memory
	 * @param recordtable
	 * @param duration
	 */
	public OnlineItemTask(RecordTable recordtable, long duration)
	{
		this.recordtable = recordtable;
		this.DURATION =  duration * 60 *1000;
	}

	public void run() {
		Set set = recordtable.online_table.keySet();
		Iterator iterator = set.iterator();
		while (iterator.hasNext()) {
			String usr_name = (String)iterator.next();
			onlineitem item = recordtable.online_table.get(usr_name);
			long current_time = new Date().getTime();
			if(item.getCreate_date().getTime() + DURATION <= current_time)
			{
				recordtable.delete_user(usr_name);
				System.out.println(usr_name + " entry time out, delete from memmory");
			}
		}
		
		
	}
	
	
	
}