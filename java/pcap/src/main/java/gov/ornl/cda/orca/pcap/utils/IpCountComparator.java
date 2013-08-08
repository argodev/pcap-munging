/**
 * 
 */
package gov.ornl.cda.orca.pcap.utils;

import java.util.Comparator;
import java.util.Map;

/**
 * @author argodev
 *
 */
public class IpCountComparator implements Comparator<String> {
	
	Map<String, Integer> base;
	
    public IpCountComparator(Map<String, Integer> base) {
        this.base = base;
    }

    // Note: this comparator imposes orderings that are inconsistent with equals.    
    public int compare(String a, String b) {
        if (base.get(a) >= base.get(b)) {
            return -1;
        } else {
            return 1;
        } // returning 0 would merge keys
    }
}
