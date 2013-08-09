package gov.ornl.cda.orca.pcap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.EnhancedPatternLayout;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

/**
 * Hello world!
 *
 */
public class App 
{
	// set up logging
	static Logger logger = LogManager.getLogger(AttackProjector.class.getName());
	
	/**
	 * @param args
	 */
    public static void main( String[] args )
    {
		initLogger();
		logger.info("CDA Attack Sample Generator");
		
		// set up a timer for the entire app
		final long startTime = System.currentTimeMillis();
		
		// setup the projector engine
        AttackProjector projector = new AttackProjector();

        // linux settings
//        projector.setEditcapPath("/usr/sbin/editcap");
//        projector.setBittwistePath("/usr/bin/bittwiste");
//        projector.setMergecapPath("/usr/sbin/mergecap");
//        projector.setCapinfosPath("/usr/sbin/capinfos");
//        projector.setTcpdumpPath("/usr/sbin/tcpdump");
//        projector.setTsharkPath("/usr/sbin/tshark");
        
        // windows settings
        projector.setEditcapPath("C:\\Program Files\\Wireshark\\editcap.exe");
        projector.setBittwistePath("C:\\Tools\\bittwiste.exe");
        projector.setMergecapPath("C:\\Program Files\\Wireshark\\mergecap.exe");
        projector.setCapinfosPath("C:\\Program Files\\Wireshark\\capinfos.exe");
        projector.setWindumpPath("C:\\Tools\\WinDump.exe");
        projector.setTsharkPath("C:\\Program Files\\Wireshark\\tshark.exe");

        // setup some testing data
        projector.setSourcePcapPath("C:\\scratch\\pcaps\\rmi_20130416_filtered.pcap");
        projector.setTargetPcapPath("C:\\scratch\\pcaps\\ex03_rmi.pcap");
        projector.setOutputPcapPath("C:\\scratch\\pcaps\\ex03_rmi_merged.pcap");                
        
        if (projector.verifyTools()) {
			// let's do something interesting
        	
        	// get/report/store the data from the source file
    	    logger.info("Selected Source File: " + projector.getSourcePcapPath());
    	    logger.info("Querying for file details...");
        	PcapData sourceFileData = projector.getPcapDetails(projector.getSourcePcapPath());
        	
        	// get/report/store the data from the target file
            logger.info("Selected Target File: " + projector.getTargetPcapPath());
    	    logger.info("Querying for file details...");
    	    PcapData targetFileData = projector.getPcapDetails(projector.getTargetPcapPath());

            // ensure that the target data file is longer (time-wise) than the source file
    	    if (projector.ensureTargetLongerThanSource(sourceFileData, targetFileData)) {
    	    	logger.error("Source File is longer than the target file");    	    	
    	    }

    	    logger.info("Verified: target file is longer than source file.");

            // setup some temp file names
            String t1 = projector.getOutputPcapPath() + "_001";
            String t2 = projector.getOutputPcapPath() + "_002";
            String t3 = projector.getOutputPcapPath() + "_003";

            // calculate the time shift needed for source file relative to the target
//            offset = calculate_Needed_Timeshift(attackFileData, dataFileData)

            // adjust the time (editcap)
//            r = shift_pcap_time(attackFile, t1, offset)

            // prompt the user for the victim IP from the source file (show IPs?)
            // - get and store both the IP and the MAC addr for the original victim
            logger.info("Determining top talkers in source file (this may take awhile)...");
            List<IpCountData> talkers = projector.getFileTopTalkers(projector.getSourcePcapPath(), 10);
            
            logger.info("Top Talkers for source file: ");
            for (IpCountData entry : talkers) {
            	logger.info(entry.toString());
            }
            
            
//            for (String key : talkers.keySet()) {
//            	logger.info(key + "  (" + talkers.get(key) + ")");
//            }
            
            talkers.clear();
            talkers = null;
            
            // prompt the user for the victim IP from the attack file (show IPs?)
//            oldVictimIp = raw_input("Enter the IP of the victim in the attack pcap: ")
//            logging.info("Selected Victim IP: " + oldVictimIp)
//
//            logging.info("Determining MAC address for old victim...")
//            oldVictimMac = get_mac_for_ip(attackFile, oldVictimIp)
//            logging.info("Old Victim MAC: " + oldVictimMac)

            // prompt the user for the attacker (source) IP from the attack file
//            sourceIp = raw_input("Enter the IP of the attacker in the attack pcap: ")
//            logging.info("Selected Attacker IP: " + sourceIp)

            // prompt the user for the attack label
//            label = raw_input("Enter the label of the attack: ")
//            logging.info("Selected label: " + label)

            // prompt the user for the victim IP from the target data file (show IPs?)
            // - get and store both the IP and the MAC addr for the new victim
            logger.info("Determining top talkers in target file (this may take awhile)...");
            List<IpCountData> targetTalkers = projector.getFileTopTalkers(projector.getTargetPcapPath(), 10);
            
            logger.info("Top Talkers for target file: ");
            for (IpCountData entry : targetTalkers) {
            	logger.info(entry.toString());
            }
            
            
//            for (String key : targetTalkers.keySet()) {
//            	logger.info(key + "  (" + targetTalkers.get(key) + ")");
//            }

            targetTalkers.clear();
            targetTalkers = null;
//
//            for talker in talkers[:-1]:
//              logging.info(talker.strip())
//
//            newVictimIp = raw_input("Enter the IP of the victim in the target pcap: ")
//            logging.info("Selected Victim IP: " + newVictimIp)
//
//            logging.info("Determining MAC address for new victim...")
//            newVictimMac = get_mac_for_ip(dataFile, newVictimIp)
//            logging.info("New Victim MAC: " + newVictimMac)

            // ok, we now have what we need to write out the metadata file
//            logging.info("Writing metadata file...")
//            write_metadata_file(outFile, newVictimIp, sourceIp, label)

            // change the IP of the victim (bittwiste)
//            logging.info("Swapping victim IPs...")
//            swap_ips(t1, t2, oldVictimIp, newVictimIp)

            // change the MAC of the victim (bittwiste)
//            logging.info("Swapping victim MACs...")
//            swap_macs(t2, t3, oldVictimMac, newVictimMac)

            // merge the files
//            logging.info("Merging the modified attack data with the target data...")
//            merge_pcaps(dataFile, t3, outFile)

            // let's get some summary data
//            finalFileData = getPcapDetails(outFile)
//            listFileDetails(finalFileData)

            // verify changes were successful
            // - num of pkts in output should be raw + attack
//            finalPacketCount = long(get_capinfo_pkt_count(finalFileData))
//            attackPacketCount = long(get_capinfo_pkt_count(attackFileData))
//            targetPacketCount = long(get_capinfo_pkt_count(dataFileData))
//            goal = attackPacketCount + targetPacketCount
//
//            if finalPacketCount == goal:
//              logging.info("Verification: Packet Counts Match!!!")
//            else:
//              logging.error("Packet Count Verification Failed! (" + str(finalPacketCount) + " vs. " + str(goal) + ")")
//              logging.error("Final: " + str(finalPacketCount))
//              logging.error("Attack: " + str(attackPacketCount))
//              logging.error("Target: " + str(targetPacketCount))

            // - start time of output should == start time of raw
//            finalOffset = calculate_Needed_Timeshift(finalFileData, dataFileData)
//
//            if finalOffset == 0:
//              logging.info("Verification: Start Times Match!!!")
//            else:
//              logging.error("Start Time Verification Failed! (offset:" + str(finalOffset) + ")")

            // - end time of output should == end time of raw
//            finalDuration = calculateDurationInSeconds(finalFileData)
//            targetDuration = calculateDurationInSeconds(dataFileData)
//
//            if finalDuration == targetDuration:
//              logging.info("Verification: Duration Matches!!!")
//            else:
//              logging.error("Capture Duration Verification Failed! (" + str(fi            
        	
		} else {
			logger.error("We are missing the required tools. Existing now.");
		}
        
        projector.cleanUp();
        projector = null;
        
		// finish our timer
		final long endTime = System.currentTimeMillis();
		
		// indicate we are finished
		logger.info("Total execution time: " + ((endTime - startTime)/1000F) + " seconds.");
		logger.info("Operation Complete");
    }
    
	private static void initLogger() {
		ConsoleAppender console = new ConsoleAppender();
		String PATTERN = "%d{ISO8601} %-5p  - %-10.26c{1}  - %m%n";
		console.setLayout(new EnhancedPatternLayout(PATTERN));
		console.setThreshold(Level.INFO);
		console.activateOptions();
		
		Logger.getRootLogger().addAppender(console);
	}   
}