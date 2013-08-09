/**
 * 
 */
package gov.ornl.cda.orca.pcap;

import gov.ornl.cda.orca.pcap.processors.CapInfosProcessor;
import gov.ornl.cda.orca.pcap.processors.TcpDumpProcessor;
import gov.ornl.cda.orca.pcap.utils.IpCountComparator;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.lang3.SystemUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;


/**
 * @author gillenre
 *
 */
public class AttackProjector {
	
	// set up logging
	static Logger logger = LogManager.getLogger(AttackProjector.class.getName());
	
	// setup properties 
	private String editcapPath = "/usr/sbin/editcap";
	private String bittwistePath = "/usr/bin/bittwiste";
	private String mergecapPath = "/usr/sbin/mergecap";
	private String capinfosPath = "/usr/sbin/capinfos";
	private String tcpdumpPath = "/usr/sbin/tcpdump";
	private String tsharkPath = "/usr/sbin/tshark";
	private String windumpPath = "C:\\program files\\wireshark\\windump.exe";
	
	private String sourcePcapPath = "";
	private String targetPcapPath = "";
	private String outputPcapPath = "";
	
	private ExecutorService executor = Executors.newFixedThreadPool(10);
	
	public void cleanUp() {
		executor.shutdownNow();
	}
		
    public PcapData getPcapDetails(String filePath) {

    	List<String> details = new ArrayList<String>();

    	CapInfosProcessor processor = new CapInfosProcessor(this.capinfosPath, filePath);
    	
    	Future<List<String>> pendingDetails = executor.submit(processor);

    	while (!pendingDetails.isDone()) {
    		try {
    			logger.info("Processing...");
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				logger.error(e.getMessage());
			}
    	}

		try {
			details = pendingDetails.get();
		} catch (InterruptedException e) {
			logger.error(e.getMessage());
		} catch (ExecutionException e) {
			logger.error(e.getMessage());
		}

		processor.stop();
		PcapData data = new PcapData(details);
		return data;		
	}
    
    public List<IpCountData> getFileTopTalkers(String filePath, int maxValues) {
    	List<String> details = new ArrayList<String>();

    	TcpDumpProcessor processor = new TcpDumpProcessor(
    			(SystemUtils.IS_OS_WINDOWS ? this.windumpPath : this.tcpdumpPath), filePath);
    	
    	Future<List<String>> pendingDetails = executor.submit(processor);

    	while (!pendingDetails.isDone()) {
    		try {
    			logger.info("Reading File...");
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				logger.error(e.getMessage());
			}
    	}

		try {
			details = pendingDetails.get();
		} catch (InterruptedException e) {
			logger.error(e.getMessage());
		} catch (ExecutionException e) {
			logger.error(e.getMessage());
		}

		processor.stop();
		
		logger.info("Finished the list from the file...");
		// now we need to...
		// 1. get the list into just the sending IPs
		// 2. sort the list by IP
		// 3. get a list of unique IPs and the counts
		// IP 10.78.26.47.25882 > 10.78.12.45.49229: Flags [P.], seq 1:2, 

		logger.info("Identifying distinct IPs and counts...");
		HashMap<String, Integer> ips = new HashMap<String, Integer>();

		for (String line : details) {
			try {
				String ip = line.split(" ")[1].trim();
				ip = ip.substring(0, ip.lastIndexOf('.'));
				
				if (ips.containsKey(ip)) {
					ips.put(ip, ips.get(ip) + 1);
				} else {
					ips.put(ip, 1);
				}
			} catch (StringIndexOutOfBoundsException e) {
				// squash
			}
		}
		
		// explicitly clean up
		details.clear();
		details = null;
		
		// 4. sort that list numerically
		logger.info("Sorting results...");
		IpCountComparator bvc =  new IpCountComparator(ips);
        TreeMap<String,Integer> sortedIps = new TreeMap<String,Integer>(bvc);
        sortedIps.putAll(ips);
        //sortedIps.

        // explicitly clean up
        ips.clear();
        ips = null;
        
        // 5. get the top 10 items
        logger.info("Filtering list to top " + maxValues);
        List<IpCountData> topTalkers = new ArrayList<IpCountData>();

        if (sortedIps.size() > maxValues) {
			
			for (int i = 0; i < maxValues; i++) {
				Map.Entry<String, Integer> entry = sortedIps.pollFirstEntry();
				topTalkers.add(new IpCountData(entry.getKey(), entry.getValue()));
			}			
		} else {
			//topTalkers.putAll(sortedIps.descendingMap());
			int listSize = sortedIps.size();
			for (int i = 0; i < listSize; i++) {
				Map.Entry<String, Integer> entry = sortedIps.pollFirstEntry();
				topTalkers.add(new IpCountData(entry.getKey(), entry.getValue()));
			}			
		}
		
		// explicitly clean up
		sortedIps.clear();
		sortedIps = null;
		
		return topTalkers;    	
    }
		
    public Boolean ensureTargetLongerThanSource(PcapData sourceData, PcapData targetData) {
	    if (targetData.getCaptureDuration() < sourceData.getCaptureDuration()) {
	    	return true;	    	
	    } else {
	    	return false;
	    }
    }
    
    
	private static Boolean verifyTool(String filePath, String toolName) {
		if (!(new File(filePath)).exists()) {
			logger.error(String.format("Tool Missing: %s was not present at the expected location", toolName));
			return false;
		} else {
			return true;
		}
	}
	
	public Boolean verifyTools() {
		Boolean allGood = true;
		
		allGood = (verifyTool(editcapPath, "editcap")) ? allGood : false;
		allGood = (verifyTool(bittwistePath, "bittwiste")) ? allGood : false; 
		allGood = (verifyTool(mergecapPath, "mergecap")) ? allGood : false;
		allGood = (verifyTool(capinfosPath, "capinfos")) ? allGood : false;
		allGood = (verifyTool(tsharkPath, "tshark")) ? allGood : false;
		
		// if we are on windows, look for windump
		if (SystemUtils.IS_OS_WINDOWS) {
			allGood = (verifyTool(windumpPath, "windump")) ? allGood : false; 
		} else {
			allGood = (verifyTool(tcpdumpPath, "tcpdump")) ? allGood : false; 
		}
	
		return allGood;
	}
	
	/**
	 * @return the editcapPath
	 */
	public String getEditcapPath() {
		return editcapPath;
	}

	/**
	 * @param editcapPath the editcapPath to set
	 */
	public void setEditcapPath(String editcapPath) {
		this.editcapPath = editcapPath;
	}

	/**
	 * @return the bittwistePath
	 */
	public String getBittwistePath() {
		return bittwistePath;
	}

	/**
	 * @param bittwistePath the bittwistePath to set
	 */
	public void setBittwistePath(String bittwistePath) {
		this.bittwistePath = bittwistePath;
	}

	/**
	 * @return the mergecapPath
	 */
	public String getMergecapPath() {
		return mergecapPath;
	}

	/**
	 * @param mergecapPath the mergecapPath to set
	 */
	public void setMergecapPath(String mergecapPath) {
		this.mergecapPath = mergecapPath;
	}

	/**
	 * @return the capinfosPath
	 */
	public String getCapinfosPath() {
		return capinfosPath;
	}

	/**
	 * @param capinfosPath the capinfosPath to set
	 */
	public void setCapinfosPath(String capinfosPath) {
		this.capinfosPath = capinfosPath;
	}

	/**
	 * @return the tcpdumpPath
	 */
	public String getTcpdumpPath() {
		return tcpdumpPath;
	}

	/**
	 * @param tcpdumpPath the tcpdumpPath to set
	 */
	public void setTcpdumpPath(String tcpdumpPath) {
		this.tcpdumpPath = tcpdumpPath;
	}

	/**
	 * @return the tsharkPath
	 */
	public String getTsharkPath() {
		return tsharkPath;
	}

	/**
	 * @param tsharkPath the tsharkPath to set
	 */
	public void setTsharkPath(String tsharkPath) {
		this.tsharkPath = tsharkPath;
	}

	/**
	 * @return the windumpPath
	 */
	public String getWindumpPath() {
		return windumpPath;
	}

	/**
	 * @param windumpPath the windumpPath to set
	 */
	public void setWindumpPath(String windumpPath) {
		this.windumpPath = windumpPath;
	}

	/**
	 * @return the sourcePcapPath
	 */
	public String getSourcePcapPath() {
		return sourcePcapPath;
	}

	/**
	 * @param sourcePcapPath the sourcePcapPath to set
	 */
	public void setSourcePcapPath(String sourcePcapPath) {
		this.sourcePcapPath = sourcePcapPath;
	}

	/**
	 * @return the targetPcapPath
	 */
	public String getTargetPcapPath() {
		return targetPcapPath;
	}

	/**
	 * @param targetPcapPath the targetPcapPath to set
	 */
	public void setTargetPcapPath(String targetPcapPath) {
		this.targetPcapPath = targetPcapPath;
	}

	/**
	 * @return the outputPcapPath
	 */
	public String getOutputPcapPath() {
		return outputPcapPath;
	}

	/**
	 * @param outputPcapPath the outputPcapPath to set
	 */
	public void setOutputPcapPath(String outputPcapPath) {
		this.outputPcapPath = outputPcapPath;
	}
}
