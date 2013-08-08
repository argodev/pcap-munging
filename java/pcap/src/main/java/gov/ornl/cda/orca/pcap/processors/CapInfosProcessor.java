package gov.ornl.cda.orca.pcap.processors;

import gov.ornl.cda.orca.pcap.AttackProjector;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class CapInfosProcessor implements Callable<List<String>> {

	private final String exePath;
	private final String filePath;
	private Process p;

	// set up logging
	static Logger logger = LogManager.getLogger(AttackProjector.class.getName());
	
	public CapInfosProcessor(String exePath, String filePath) {
	      this.exePath = exePath;
	      this.filePath = filePath;
	    }
	
	public List<String> call() throws Exception {
		
		List<String> rawData = new ArrayList<String>();
		ProcessBuilder pb = new ProcessBuilder(this.exePath, this.filePath); 
		p= pb.start();

		OutputStreamLineReturnProcessor pos = new OutputStreamLineReturnProcessor(p.getInputStream(), rawData);
		OutputStreamProcessor posErr = new OutputStreamProcessor(p.getErrorStream(), Level.ERROR);
		pos.start();
		posErr.start();		
		
		// wait until we are done
		p.waitFor();
		
		return rawData;
	}

	public void stop() {
		p.destroy();
	}	
}
