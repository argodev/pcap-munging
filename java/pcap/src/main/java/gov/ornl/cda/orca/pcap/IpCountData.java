package gov.ornl.cda.orca.pcap;

public class IpCountData {

	private String ipAddress = "";
	private Integer count = 0;
	
	public IpCountData(String ipAddress, Integer count) {
		this.setIpAddress(ipAddress);
		this.setCount(count);
	}

	/**
	 * @return the ipAddress
	 */
	public String getIpAddress() {
		return ipAddress;
	}

	/**
	 * @param ipAddress the ipAddress to set
	 */
	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	/**
	 * @return the count
	 */
	public Integer getCount() {
		return count;
	}

	/**
	 * @param count the count to set
	 */
	public void setCount(Integer count) {
		this.count = count;
	}
	
	@Override
	public String toString() {
	    return String.format("%s (%,d)", this.getIpAddress(), this.getCount());
	  }
	
	
}
