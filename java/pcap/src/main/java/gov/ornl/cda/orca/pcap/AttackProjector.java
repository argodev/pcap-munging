/**
 * 
 */
package gov.ornl.cda.orca.pcap;

import java.io.File;

import org.apache.commons.lang3.SystemUtils;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.EnhancedPatternLayout;
import org.apache.log4j.Level;
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

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		initLogger();
		logger.info("CDA Attack Sample Generator");
		
		// set up a timer for the entire app
		final long startTime = System.currentTimeMillis();
		
		// TODO: Do the work
		if (verifyTools()) {
			// let's do something interesting
		} else {
			logger.error("We are missing the requried tools. Existing now.");
		}
		
		// finish our timer
		final long endTime = System.currentTimeMillis();
		
		// indicate we are finished
		logger.info("Total execution time: " + ((endTime - startTime)/1000F) + " seconds.");
		logger.info("Operation Complete");
	}
	
	private static Boolean verifyTool(String filePath, String toolName) {
		if (!(new File(filePath)).exists()) {
			logger.error(String.format("Tool Missing: %s was not present at the expected location", toolName));
			return false;
		} else {
			return true;
		}
	}
	
	private Boolean verifyTools() {
		Boolean allGood = true;
		
		allGood = (verifyTool(getEditcapPath(), "editcap")) ? allGood : false;
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
	
	private static void initLogger() {
		ConsoleAppender console = new ConsoleAppender();
		String PATTERN = "%d{ISO8601} %-5p  - %-10.26c{1}  - %m%n";
		console.setLayout(new EnhancedPatternLayout(PATTERN));
		console.setThreshold(Level.INFO);
		console.activateOptions();
		
		Logger.getRootLogger().addAppender(console);
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
}
