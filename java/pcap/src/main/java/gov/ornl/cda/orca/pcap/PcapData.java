/**
 * 
 */
package gov.ornl.cda.orca.pcap;

import java.util.List;

import org.joda.time.LocalDateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

/**
 * @author argodev
 */
public class PcapData {

	public PcapData() {
		// default constructor
	}
	
	public PcapData(List<String> rawData) {
		
		// Convert from console output
		for (String line : rawData) {
			
			// File name:           C:\scratch\pcaps\rmi_20130416_filtered.pcap
			if (line.contains("File name:")) {
				this.fileName = line.split(":")[1].trim();
				continue;
			}
			
			// File type:           Wireshark/tcpdump/... - libpcap
			if (line.contains("File type:")) {
				this.fileType = line.split(":")[1].trim();
				continue;
			}
			
			// File encapsulation:  Ethernet
			if (line.contains("File encapsulation:")) {
				this.fileEncapsulation = line.split(":")[1].trim();
				continue;
			}
				
			// Number of packets:   272
			if (line.contains("Number of packets:")) {
				this.numberPackets = Long.parseLong(line.split(":")[1].trim());
				continue;
			}

			// File size:           22864 bytes
			if (line.contains("File size:")) {
				String lineValue = line.split(":")[1].trim();
				this.fileSize = Long.parseLong(lineValue.split(" ")[0].trim());
				continue;
			}
			
			// Data size:           174734 bytes
			if (line.contains("Data size:")) {
				String lineValue = line.split(":")[1].trim();
				this.dataSize = Long.parseLong(lineValue.split(" ")[0].trim());
				continue;
			}
			
			// Capture duration:    10 seconds
			if (line.contains("Capture duration:")) {
				String lineValue = line.split(":")[1].trim();
				this.captureDuration = Long.parseLong(lineValue.split(" ")[0].trim());
				continue;
			}
			
			// Start time:          Tue Apr 16 17:06:22 2013
			if (line.contains("Start time:")) {
				String[] lineValues = line.split(":");
				String dateString = lineValues[1].trim() + ":" + lineValues[2].trim() + ":" + lineValues[3].trim();
				DateTimeFormatter fmt = DateTimeFormat.forPattern("EEE MMM dd HH:mm:ss yyyy");
				this.startTime = LocalDateTime.parse(dateString, fmt);
				continue;
			}
			
			// End time:            Tue Apr 16 17:06:33 2013
			if (line.contains("End time:")) {
				String[] lineValues = line.split(":");
				String dateString = lineValues[1].trim() + ":" + lineValues[2].trim() + ":" + lineValues[3].trim();
				DateTimeFormatter fmt = DateTimeFormat.forPattern("EEE MMM dd HH:mm:ss yyyy");
				this.endTime = LocalDateTime.parse(dateString, fmt);
				continue;
			}
			
			// Data byte rate:      17295.60 bytes/sec
			if (line.contains("Data byte rate:")) {
				String lineValue = line.split(":")[1].trim();
				this.byteRate = Float.parseFloat(lineValue.split(" ")[0].trim());
				continue;
			}
			
			// Data bit rate:       138364.78 bits/sec
			if (line.contains("Data bit rate: ")) {
				String lineValue = line.split(":")[1].trim();
				this.bitRate = Float.parseFloat(lineValue.split(" ")[0].trim());
				continue;
			}
			
			// Average packet size: 642.40 bytes
			if (line.contains("Average packet size:")) {
				String lineValue = line.split(":")[1].trim();
				this.avergePacketSize = Float.parseFloat(lineValue.split(" ")[0].trim());
				continue;
			}

			
			//			private long numberPackets = 0;
//			private long fileSize = 0;
//			private long dataSize = 0;
//			private long captureDuration = 0;
//			private LocalDateTime startTime = new LocalDateTime();
//			private LocalDateTime EndTime = new LocalDateTime();
//			private float byteRate = 0;
//			private float bitRate = 0;
//			private float avergePacketSize = 0;				
		}
	}
	
	/**
	 * @return the fileType
	 */
	public String getFileType() {
		return fileType;
	}

	/**
	 * @param fileType the fileType to set
	 */
	public void setFileType(String fileType) {
		this.fileType = fileType;
	}

	/**
	 * @return the fileEncapsulation
	 */
	public String getFileEncapsulation() {
		return fileEncapsulation;
	}

	/**
	 * @param fileEncapsulation the fileEncapsulation to set
	 */
	public void setFileEncapsulation(String fileEncapsulation) {
		this.fileEncapsulation = fileEncapsulation;
	}

	/**
	 * @return the numberPackets
	 */
	public long getNumberPackets() {
		return numberPackets;
	}

	/**
	 * @param numberPackets the numberPackets to set
	 */
	public void setNumberPackets(long numberPackets) {
		this.numberPackets = numberPackets;
	}

	/**
	 * @return the fileSize
	 */
	public long getFileSize() {
		return fileSize;
	}

	/**
	 * @param fileSize the fileSize to set
	 */
	public void setFileSize(long fileSize) {
		this.fileSize = fileSize;
	}

	/**
	 * @return the dataSize
	 */
	public long getDataSize() {
		return dataSize;
	}

	/**
	 * @param dataSize the dataSize to set
	 */
	public void setDataSize(long dataSize) {
		this.dataSize = dataSize;
	}

	/**
	 * @return the captureDuration
	 */
	public long getCaptureDuration() {
		return captureDuration;
	}

	/**
	 * @param captureDuration the captureDuration to set
	 */
	public void setCaptureDuration(long captureDuration) {
		this.captureDuration = captureDuration;
	}

	/**
	 * @return the startTime
	 */
	public LocalDateTime getStartTime() {
		return startTime;
	}

	/**
	 * @param startTime the startTime to set
	 */
	public void setStartTime(LocalDateTime startTime) {
		this.startTime = startTime;
	}

	/**
	 * @return the endTime
	 */
	public LocalDateTime getEndTime() {
		return endTime;
	}

	/**
	 * @param endTime the endTime to set
	 */
	public void setEndTime(LocalDateTime endTime) {
		this.endTime = endTime;
	}

	/**
	 * @return the byteRate
	 */
	public float getByteRate() {
		return byteRate;
	}

	/**
	 * @param byteRate the byteRate to set
	 */
	public void setByteRate(float byteRate) {
		this.byteRate = byteRate;
	}

	/**
	 * @return the bitRate
	 */
	public float getBitRate() {
		return bitRate;
	}

	/**
	 * @param bitRate the bitRate to set
	 */
	public void setBitRate(float bitRate) {
		this.bitRate = bitRate;
	}

	/**
	 * @return the avergePacketSize
	 */
	public float getAvergePacketSize() {
		return avergePacketSize;
	}

	/**
	 * @param avergePacketSize the avergePacketSize to set
	 */
	public void setAvergePacketSize(float avergePacketSize) {
		this.avergePacketSize = avergePacketSize;
	}

	/**
	 * @return the fileName
	 */
	public String getFileName() {
		return fileName;
	}

	/**
	 * @param fileName the fileName to set
	 */
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	private String fileName = "";
	private String fileType = "";
	private String fileEncapsulation = "";
	private long numberPackets = 0;
	private long fileSize = 0;
	private long dataSize = 0;
	private long captureDuration = 0;
	private LocalDateTime startTime = new LocalDateTime();
	private LocalDateTime endTime = new LocalDateTime();
	private float byteRate = 0;
	private float bitRate = 0;
	private float avergePacketSize = 0;
	
	
}
