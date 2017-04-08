import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.PriorityQueue;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileScratch {

	private static Map<String, Integer> dnsip_hitcount = new HashMap<String, Integer>();
	private static Map<String, Integer> resource_bytes = new HashMap<String, Integer>();
	private static TreeMap<Long, Integer> minute_IPCnt = new TreeMap<Long, Integer>();

	private static Map<String, Long> blocked_5min_IPMap = new HashMap<String, Long>();
	// so that in a sec if n diff IP's have made failed attempt to check it.
	// {sec1 : [ip1,ip2,ip3]},{sec2 : [ip1,ip2,ip3]}
	// every 20secs using this we will delete/decrease counts from
	// ip_failurecount_inlast20secs
	private static TreeMap<Long, List<String>> last20sec_failed_ip = new TreeMap<Long, List<String>>();
	// chk this for failure count in last 20 secs
	private static Map<String, Integer> ip_failurecount_inlast20secs = new HashMap<String, Integer>();
	
	
	
	// Create PQ of 10 elts only bcoz sost of whole map will take Onlogn whereas
	// PQ will only take log10 to decide its in top 10 or not
	private static PriorityQueue<Map.Entry<String, Integer>> pq = new PriorityQueue<>(10,
			new Comparator<Map.Entry<String, Integer>>() {
				@Override
				public int compare(Map.Entry<String, Integer> a, Map.Entry<String, Integer> b) {
					return b.getValue() - a.getValue();
				}
			});

	// Heap of Size 10 for Top10 busiest hours. Size 10 reduces the search to
	// log10 to determine if the value should be stored or not
	private static PriorityQueue<Map.Entry<Long, Integer>> pqlong = new PriorityQueue<>(10,
			new Comparator<Map.Entry<Long, Integer>>() {
				@Override
				public int compare(Map.Entry<Long, Integer> a, Map.Entry<Long, Integer> b) {
					return b.getValue() - a.getValue();
				}
			});
	
	public static SimpleDateFormat formatter = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss");
	
	public static void main(String[] args) {

		String inputfilepath = args[0];
		String hostsfilepath = args[1];
		String rscrsfilepath = args[2];
		String busyhoursfilepath = args[3];
		String blockedfilepath = args[4];
		Writer writer=null;
		try{
		 writer = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(blockedfilepath), StandardCharsets.UTF_8));

		BufferedReader br = new BufferedReader(new FileReader(inputfilepath)); 
			String line;
			while ((line = br.readLine()) != null) {
				processLine(line, writer);

			}
			System.out.println("Completed Processing lines");
			
			getTop10_IP(hostsfilepath);
			getTop10_RscrsConsumers(rscrsfilepath);
			getTop10BusiestPeriods(busyhoursfilepath);
			writer.close();
			System.out.println("Completed Processing and output files are ready");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			dnsip_hitcount.clear();
			resource_bytes.clear();
			
		}

	}

	/*
	 * Iterate over each entry in TreeMap use submap api to egt entries in next
	 * 60 mins hours.txt: 01/Jul/1995:00:00:01 -0400,100
	 * 
	 */
	private static void getTop10BusiestPeriods(String busyhoursfilepath) {
		System.out.println("Entering getTop10BusiestPeriods");
		if (!minute_IPCnt.isEmpty()) {
			// get entries for last 60 mins
			// iterate over them n put in max heap i.e. pq of size 10

			for (Entry<Long, Integer> e : minute_IPCnt.entrySet()) {
				// get all entries in 60 min range, sliding window
				NavigableMap<Long, Integer> map = minute_IPCnt.subMap(e.getKey(), true, e.getKey()+59, true);
				//System.out.println("RangeMap size:" + map.size() + "for hour begng minute" + (e.getKey() - 59));
				if (!map.isEmpty()) {
					// sum over values of map and put entry in max heap
					Integer cnt = map.values().stream().reduce(0, Integer::sum);
					if (cnt != null) {
						Entry<Long, Integer> min_cnt = new AbstractMap.SimpleEntry<Long, Integer>(e.getKey(), cnt);
						pqlong.add(min_cnt);
					}
				}

			}

			int k = 1;
			try (Writer writer = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(busyhoursfilepath), StandardCharsets.UTF_8))) {
				while (k < 11 && !pqlong.isEmpty()) {
					Entry<Long, Integer> e = pqlong.poll();
					
					Long epochtime=e.getKey()*60000L;
					writer.write( formatter.format(new Date(epochtime)) +","+e.getValue() +"\n" );
					
					//System.out.println("Top10BusiestPeriods" + k + " ip:" + e.getKey() + " Count:" + e.getValue());
					k++;
				}
			}

			catch (IOException ex) {
				System.out.println("Error occurred while writing to Hosts.txt");
				ex.printStackTrace();
			}
			pqlong.clear();
			System.out.println("Exiting getTop10BusiestPeriods");

		}

	}

	private static void processLine(String line, Writer writer) {
		Data d = null;

		try {
			d = lineToData(line);
			// preprocessing put data entries
			if (d != null) {
				putDNS_IP(d.getIp_dns());
				putIP_to_BandWidthEntries(d.getResource(), d.getBytes());
				putMinute_IPCnt(d.getIp_dns(), d.getStatus_code(), d.getEntry_time(), line, writer);

			}

		}

		finally {
			// to release ref so that it can be garbage collected
			d = null;
		}
	}

	// Put and update per min entry for since epoch min e.g in a min der r 5
	// hits, next min der r 15 hits.. {x,5}, {x+1,15}
	private static void putMinute_IPCnt(String Ip_dns, int status_code, String entry_time, String line, Writer writer) {
		// System.out.println("Entered putMinute_IPCnt");
		String str = entry_time.substring(1, 21);
		long[] secs_minute = getMinuteFromTime(str);

		if (secs_minute[1] != 0)
			minute_IPCnt.put(secs_minute[1], minute_IPCnt.getOrDefault(secs_minute[1], 0) + 1);

		failurechk(Ip_dns, status_code, secs_minute[0], line, writer);
		// System.out.println("ended putMinute_IPCnt ");
	}

	/*
	 * private Map<String, Long> blocked_5min_IPMap=new HashMap<String,Long>();
	 * //so that in a sec if n diff IP's have made failed attempt to check it.
	 * {sec1 : [ip1,ip2,ip3]},{sec2 : [ip1,ip2,ip3]} // every 20secs using this
	 * we will delete/decrease counts from ip_failurecount_inlast20secs private
	 * Map<Long, List<String>>last20sec_failed_ip=new
	 * HashMap<Long,List<String>>(); //chk this for failure count in last 20
	 * secs private Map<String,Integer> ip_failurecount_inlast20secs= new
	 * HashMap<String,Integer>();
	 */
	// Feature 4 : 20 secs failure logging blocking logic
	// as of now logic has time chk.. timer tasks can be written to remove vaues
	// older than 5 mins
	private static void failurechk(String ip_dns, int status_code, long timeinsecs, String line,Writer writer) {
		// System.out.println("Entered failurechk");

		// clear and recalculate entries in map every sec remove entries older
		// than 20secs.
		try{
		Map<Long, List<String>> olderthan_20_entries = last20sec_failed_ip.headMap(timeinsecs - 20);
		if (!olderthan_20_entries.isEmpty()) {
			// System.out.println("Cleaning failure maps");
			for (Entry<Long, List<String>> e : olderthan_20_entries.entrySet()) {
				// System.out.println("older keys"+e.getKey() +"older
				// ips:"+e.getValue().toString());
				for (String ip : e.getValue()) {
					int prevfailurecnt = ip_failurecount_inlast20secs.getOrDefault(ip, 0);

					if (prevfailurecnt == 1) {
						// System.out.println("as CNT==0 Removed entyr from
						// cache for ip:"+ip);
						ip_failurecount_inlast20secs.remove(ip);
					} else {
						// System.out.println("Decremented entyr from cache for
						// ip:"+ip);
						ip_failurecount_inlast20secs.put(ip, prevfailurecnt - 1);
					}

				}
			}
			// remove older entries based on time
			olderthan_20_entries.clear();
		}
		// clearing old than 20secs entries completes

		// ---------------------------------------------------------blocked.txt
		Long blocktiming = blocked_5min_IPMap.get(ip_dns);
		if (blocktiming != null) {
			// System.out.println("entry found in blocking");
			if ((timeinsecs - blocktiming) / (5 * 60) == 0) {
				// log to file
				writer.write(line+ "\n");
			}

		} else if (status_code == 401) {

			int past20secs_failure_cnt = ip_failurecount_inlast20secs.getOrDefault(ip_dns, 0);
			// for 0,1 so after adding here entry becomes 1,2 else condition
			// entry is 3 so add to blocklist
			ip_failurecount_inlast20secs.put(ip_dns, ++past20secs_failure_cnt);
			List<String> failedipsinsec = last20sec_failed_ip.getOrDefault(timeinsecs, new ArrayList<String>());
			failedipsinsec.add(ip_dns);
			last20sec_failed_ip.put(timeinsecs, failedipsinsec);
			// on 3rd time it will be put in blocking list n in next 5 mins it
			// wont be allowed
			// so any status code entry will not come here in 401else in above
			// if itself it will be logged
			if (past20secs_failure_cnt > 2) {
				blocked_5min_IPMap.put(ip_dns, timeinsecs);
			}
		}
		}
		catch(IOException ex){
			System.out.println("Error occurred in failure checking");
			ex.printStackTrace();
		}

		// System.out.println("Ended failurechk");
	}

	private static long[] getMinuteFromTime(String entry_time) {
		
		Date date = null;
		// 0 secs ,1 mins
		long[] timeInsecs_MinutesSinceEpoch = new long[2];

		try {
			date = formatter.parse(entry_time);
			timeInsecs_MinutesSinceEpoch[0] = date.getTime() / 1000;
			timeInsecs_MinutesSinceEpoch[1] = date.getTime() / (60000);
		} catch (ParseException e) {
			System.out.println("Error Occurred for parsing string_date" + entry_time);
			e.printStackTrace();
		}

		return timeInsecs_MinutesSinceEpoch;
	}

	// resources.txt /images/USA-logosmall.gif
	private static void getTop10_RscrsConsumers(String top10rscrsfilepath) {
		// TODO Auto-generated method stub
		pq.addAll(resource_bytes.entrySet());
		int k = 1;
		try (Writer writer = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(top10rscrsfilepath), StandardCharsets.UTF_8))) {
			while (k < 11 && !pq.isEmpty()) {
				Entry<String, Integer> e = pq.poll();
				String[] rarr=e.getKey().split("\\s+");
				writer.write(rarr[1] + "\n");
				//System.out.println("Top" + k + " Resource:" + e.getKey() + " Count:" + e.getValue()+ "exact rsrc"+ rarr[1]);
				k++;
			}
		} catch (IOException ex) {
			System.out.println("Error occurred while writing to Hosts.txt");
			ex.printStackTrace();
		}
		pq.clear();

	}

	// hosts.txt example.host.com,1000000
	private static void getTop10_IP(String hostsfilepath) {
		// TODO Auto-generated method stub
		pq.addAll(dnsip_hitcount.entrySet());
		try (Writer writer = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(hostsfilepath), StandardCharsets.UTF_8))) {
			int k = 1;
			while (k < 11 && !pq.isEmpty()) {
				Entry<String, Integer> e = pq.poll();
				writer.write(e.getKey() + "," + e.getValue() +"\n");
				//System.out.println("Top" + k + " ip:" + e.getKey() + " Count:" + e.getValue());
				k++;
			}
		} catch (IOException ex) {
			System.out.println("Error occurred while writing to Hosts.txt");
			ex.printStackTrace();
		}
		pq.clear();
	}

	private static void putIP_to_BandWidthEntries(String resource, int bytes) {
		if (resource == null)
			return;
		resource_bytes.put(resource, resource_bytes.getOrDefault(resource, 0) + bytes);
	}

	private static void putDNS_IP(String ip_dns) {
		// put an entry in Hashmap to maintina count, if entry is already der
		// den increase count by 1
		if (ip_dns == null)
			return;
		dnsip_hitcount.put(ip_dns, dnsip_hitcount.getOrDefault(ip_dns, 0) + 1);
	}

	private static Data lineToData(String line) {
		Data dataline = new Data();

		String re1 = "((?:[a-z][a-z\\.\\d\\-]+)\\.(?:[a-z][a-z\\-]+))(?![\\w\\.])"; // Fully
																					// Qualified
																					// Domain
																					// Name
																					// 1
		String re2 = ".*?"; // Non-greedy match on filler
		String re3 = "(\\[.*?\\])"; // Square Braces 1
		String re4 = ".*?"; // Non-greedy match on filler
		String re5 = "(\".*?\")"; // Double Quote String 1
		String re6 = ".*?"; // Non-greedy match on filler
		String re7 = "(\\d+)"; // Integer Number 1
		String re8 = ".*?"; // Non-greedy match on filler
		String re9 = "(\\d+)"; // Integer Number 2

		Pattern p = Pattern.compile(re1 + re2 + re3 + re4 + re5 + re6 + re7 + re8 + re9,
				Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
		Matcher m = p.matcher(line);
		String ip = "(\\d+\\.\\d+\\.\\d+\\.\\d+)";
		String re82 = ".*?"; // Non-greedy match on filler
		String re92 = "(\\[.*?\\])"; // Square Braces 1
		String re10 = ".*?"; // Non-greedy match on filler
		String re11 = "(\".*?\")"; // Double Quote String 1
		String re12 = ".*?"; // Non-greedy match on filler
		String re13 = "(\\d+)"; // Integer Number 5
		String re14 = ".*?"; // Non-greedy match on filler
		String re15 = "(\\d+)"; // Integer Number 6

		Pattern pmine = Pattern.compile(ip + re82 + re92 + re10 + re11 + re12 + re13 + re14 + re15,
				Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
		Matcher mmine = pmine.matcher(line);
		if (m.find()) {
			String fqdn1 = m.group(1);
			String sbraces1 = m.group(2);
			String string1 = m.group(3);
			String int1 = m.group(4);
			String int2 = m.group(5);
			// System.out.print("("+fqdn1.toString()+")"+"("+sbraces1.toString()+")"+"("+string1.toString()+")"+"("+int1.toString()+")"+"("+int2.toString()+")"+"\n");
			dataline.setIp_dns(fqdn1);
			dataline.setEntry_time(sbraces1);
			dataline.setResource(string1);
			dataline.setStatus_code(Integer.parseInt(int1));
			dataline.setBytes(Integer.parseInt(int2));
		} else if (mmine.find()) {
			String int1 = mmine.group(1);
			String c1 = mmine.group(2);
			String int2 = mmine.group(3);
			String c2 = mmine.group(4);
			String int3 = mmine.group(5);
			// System.out.print("("+int1.toString()+")"+"("+c1.toString()+")"+"("+int2.toString()+")"+"("+c2.toString()+")"+"("+int3.toString()+")"+"\n");
			dataline.setIp_dns(int1);
			dataline.setEntry_time(c1);
			dataline.setResource(int2);
			dataline.setStatus_code(Integer.parseInt(c2));
			dataline.setBytes(Integer.parseInt(int3));
			// System.out.println("-----------------------------------");
		} else {
			// System.out.println("Pattern Not FOund Not Processed:"+line );
			return null;
		}
		return dataline;
	}

}


 class Data{
		String ip_dns;
		String entry_time;
		String resource;
		
		int  status_code ;
		int bytes;
		
		public String getIp_dns() {
			return ip_dns;
		}
		public void setIp_dns(String ip_dns) {
			this.ip_dns = ip_dns;
		}
		public String getEntry_time() {
			return entry_time;
		}
		public void setEntry_time(String entry_time) {
			this.entry_time = entry_time;
		}
		public String getResource() {
			return resource;
		}
		public void setResource(String resource) {
			this.resource = resource;
		}
		public int getStatus_code() {
			return status_code;
		}
		public void setStatus_code(int status_code) {
			this.status_code = status_code;
		}
		public int getBytes() {
			return bytes;
		}
		public void setBytes(int bytes) {
			this.bytes = bytes;
		}
	}


