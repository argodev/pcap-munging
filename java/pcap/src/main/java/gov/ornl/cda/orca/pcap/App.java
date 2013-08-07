package gov.ornl.cda.orca.pcap;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
        AttackProjector projector = new AttackProjector();

        projector.setEditcapPath("/usr/sbin/editcap");
        projector.setBittwistePath("/usr/bin/bittwiste");
        projector.setMergecapPath("/usr/sbin/mergecap");
        projector.setCapinfosPath("/usr/sbin/capinfos");
        projector.setTcpdumpPath("/usr/sbin/tcpdump");
        projector.setTsharkPath("/usr/sbin/tshark");
        
        
    }
}
