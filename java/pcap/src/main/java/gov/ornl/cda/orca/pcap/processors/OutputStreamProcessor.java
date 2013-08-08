/**
 * 
 */
package gov.ornl.cda.orca.pcap.processors;

import gov.ornl.cda.orca.pcap.AttackProjector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

/**
 * @author argodev
 *
 */
public class OutputStreamProcessor extends Thread {
	
	// set up logging
	static Logger logger = LogManager.getLogger(AttackProjector.class.getName());
	
	private final InputStream inputStream;
	private final Level level;
	
	public OutputStreamProcessor(InputStream inputStream, Level level) {
		this.inputStream = inputStream;
		this.level = level;
	}

	public void run() {
		InputStreamReader inputReader = null;
		BufferedReader bufferedReader = null;
		
		try {
			inputReader = new InputStreamReader(this.inputStream);
			bufferedReader = new BufferedReader(inputReader);
			String line = null;
			while ((line = bufferedReader.readLine()) != null) {
				logger.log(this.level, line);
			}
		} catch (IOException ioe) {
			
		} finally  {
			if (bufferedReader != null) {
				try {
					bufferedReader.close();
				} catch (IOException e) {
					logger.error(e.getMessage());
				}
			}
			
			if (inputReader != null) {
				try {
					inputReader.close();
				} catch (IOException e) {
					logger.error(e.getMessage());
				}
			}			
		}
	}	
}
