# This tool is designed to 
#
# Our design philosophy is that, wherever possible, we use standard tools and simply use
# this script to tie together the functionality we need. This allows us to avoid doing
# direct packet manipulation and questioning the fidelity with which we are doing our
# work
#
# REFERENCE:
#
# Output string from capinfos:
# File name:           /home/gillenre/Documents/VNet/attack1_pdf.pcap
# File type:           Wireshark/tcpdump/... - libpcap
# File encapsulation:  Ethernet
# Number of packets:   10
# File size:           1924 bytes
# Data size:           1740 bytes
# Capture duration:    12 seconds
# Start time:          Sat Sep 13 07:29:29 2008
# End time:            Sat Sep 13 07:29:41 2008
# Data byte rate:      145.85 bytes/sec
# Data bit rate:       1166.79 bits/sec
# Average packet size: 174.00 bytes
# Average packet rate: 0.84 packets/sec
#

import sys
import os
import optparse
import logging
import logging.config
import subprocess
import datetime
import dateutil.parser


reload(sys)
sys.setdefaultencoding("utf-8")
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# global variables
editcapPath = "/usr/sbin/editcap"
bittiwstePath = "/usr/bin/bittwiste"
mergecapPath = "/usr/sbin/mergecap"


# helper function to get the packet count from the output 
# generated from capinfos          
def get_capinfo_pkt_count(data):
  row = data[3]
  return row.split(":")[1].strip()


# helper function to get the file size from the output 
# generated from capinfos          
def get_capinfo_file_size(data):
  row = data[4]
  return row.split(":")[1].strip()  


# helper function to get the capture duration from the output 
# generated from capinfos          
def get_capinfo_capture_duration(data):
  row = data[6]
  return row.split(":")[1].strip()


# helper function to get the start time from the output 
# generated from capinfos          
def get_capinfo_start_time(data):
  row = data[7]
  return row.split(":", 1)[1].strip()  


# helper function to get the end time from the output 
# generated from capinfos          
def get_capinfo_end_time(data):
  row = data[8]
  return row.split(":", 1)[1].strip()  


# ensure we can find the tools in the environment:
# - editcap
# - bittwiste
# - mergecap
# - scapy ???
def verifyTools():
  allGood = True
  if not os.path.exists(editcapPath):
    logging.error("Tool Missing: editcap was not present at the expected location")
    allGood = False

  if not os.path.exists(bittiwstePath):
    logging.error("Tool Missing: bittwiste was not present at the expected location")
    allGood = False

  if not os.path.exists(mergecapPath):
    logging.error("Tool Missing: mergecap was not present at the expected location")
    allGood = False

  return allGood


def getPcapDetails(file):
  out = subprocess.Popen(["capinfos", file], stdout=subprocess.PIPE).communicate()[0]
  data = out.split('\n')
  return data


def listFileDetails(data):
  logging.info("")
  logging.info("Packet Count: " + get_capinfo_pkt_count(data))
  logging.info("File Size: " + get_capinfo_file_size(data))
  logging.info("Duration: " + get_capinfo_capture_duration(data))
  logging.info("Start Time: " + get_capinfo_start_time(data))
  logging.info("End Time: " + get_capinfo_end_time(data))
  logging.info("")


def calculateDurationInSeconds(fileDetails):
  start = dateutil.parser.parse(get_capinfo_start_time(fileDetails))
  end = dateutil.parser.parse(get_capinfo_end_time(fileDetails))
  rawDuration = end - start
  return long(rawDuration.seconds + rawDuration.days * 86400)


def ensure_Data_Longer_Than_Attack(attackDetails, dataDetails):
  attackSpan = calculateDurationInSeconds(attackDetails)
  dataSpan = calculateDurationInSeconds(dataDetails)
  return dataSpan > attackSpan


def calculate_Needed_Timeshift(attackDetails, dataDetails):
  attackStart = dateutil.parser.parse(get_capinfo_start_time(attackDetails))
  dataStart = dateutil.parser.parse(get_capinfo_start_time(dataDetails))
  rawOffset = dataStart - attackStart
  initialOffset = long(rawOffset.seconds + rawOffset.days * 86400)

  # now let's try to center the attack in the data
  attackLength = calculateDurationInSeconds(attackDetails)
  dataLength = calculateDurationInSeconds(dataDetails)
  additionalOffset = (dataLength - attackLength) / 2
  return initialOffset + additionalOffset
  

def shift_pcap_time(infile, outfile, seconds):
  logging.info("Shifting time in PCAP by " + str(seconds) + " seconds")
  out = subprocess.Popen(["editcap", "-t", str(seconds), infile, outfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
  data = out.split('\n')
  return data


# this method is derived from Amar Yousif
# http://www.yousicurity.com/2009/10/how-to-find-top-talkers-in-pcap-file.html
def get_top_talkers(infile, numTop):

  p1 = subprocess.Popen( ["-c", "tcpdump -tnr " + infile + " | awk -F '.' '{print $1\".\"$2\".\"$3\".\"$4}' | sort | uniq -c | sort -n | tail -n " + str(numTop) ],
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out = p1.communicate()[0]
  p1.wait()

  data = str(out).split('\n')
  return data


def get_mac_for_ip(infile, ip):
  p1 = subprocess.Popen( ["-c", "tshark -r " + infile + " -R '(ip.src==" + ip + ")' -T fields -e eth.src | sort | uniq" ],
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out = p1.communicate()[0]
  p1.wait()

  data = str(out).split('\n')
  return data[0]


def swap_ips(infile, outfile, oldip, newip):
  p1 = subprocess.Popen( ["-c", "bittwiste -I " + infile + " -O " + outfile + " -T ip -s " + oldip + "," + newip + " -d " + oldip + "," + newip ],
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out = p1.communicate()[0]
  p1.wait()

  data = str(out).split('\n')
  return data[0]


def swap_macs(infile, outfile, oldmac, newmac):
  p1 = subprocess.Popen( ["-c", "bittwiste -I " + infile + " -O " + outfile + " -T eth -s " + oldmac + "," + newmac + " -d " + oldmac + "," + newmac ],
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out = p1.communicate()[0]
  p1.wait()

  data = str(out).split('\n')
  return data[0]


def merge_pcaps(infile1, infile2, outfile):
  p1 = subprocess.Popen( ["-c", "mergecap -w " + outfile + " " + infile1 + " " + infile2 ],
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out = p1.communicate()[0]
  p1.wait()

  data = str(out).split('\n')
  return data[0]


def write_metadata_file(filePath, destIp, sourceIp, label):
  with open(filePath + "_metadata.xml", 'w') as f:
    f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n")
    f.write("  <pcapData>\n")    
    f.write("    <pcap file=\"" + os.path.basename(filePath) + "\">\n")
    f.write("    <filters>\n")
    f.write("      <filter destIP=\"" + destIp + "\" sourceIP=\"" + sourceIp + "\" />\n")
    f.write("    </filters>\n")
    f.write("    <label value=\"" + label + "\" />\n")
    f.write("  </pcap>\n")
    f.write("</pcapData>\n")


def main():
  
  # prompt for and collect needed parameters
  parser = optparse.OptionParser(usage='Usage %prog <options>')
  parser.add_option('-a', dest='attackFile', type='string', help='Enter the full path to the attack PCAP file.')
  parser.add_option('-t', dest='dataFile', type='string', help='Enter the full path to the target PCAP file')
  parser.add_option('-o', dest='outFile', type='string', help='Enter the full path to the output file')

  (options, args) = parser.parse_args()
  attackFile = options.attackFile
  dataFile = options.dataFile
  outFile = options.outFile

  if attackFile == None or dataFile == None or outFile == None:
    print parser.print_help()
    exit(0)

  #logging.info("Finshed processing file. Created {:,.0f}".format(count) + " files")
  logging.info("CDA Attack Sample Generator")
  
  # ensure we have met our prerequisites
  if not verifyTools():
    logging.error("Required tools were not present. Exiting.")
    exit(0)

  # get/report/store the data from the attack file
  logging.info("Selected Attack File: " + attackFile)
  attackFileData = getPcapDetails(attackFile)
  
  # get/report/store the data from the data file
  logging.info("Selected Data File: " + dataFile)
  dataFileData = getPcapDetails(dataFile)
  
  # ensure that the trarget data file is longer (time-wise) than the attack file
  if not ensure_Data_Longer_Than_Attack(attackFileData, dataFileData):
    logging.error("Attack File is longer than the data file")
    logging.error("Unable to proceed. Exiting")
    exit(0)

  logging.info("Verified: target file is longer than attack file.")

  # setup some temp file names
  t1 = outFile + "_001"
  t2 = outFile + "_002"
  t3 = outFile + "_003"

  # calculate the time shift needed for attack file relative to the target
  offset = calculate_Needed_Timeshift(attackFileData, dataFileData)

  # adjust the time (editcap)
  r = shift_pcap_time(attackFile, t1, offset)

  # prompt the user for the vicitim IP from the attack file (show IPs?)
  # - get and store both the IP and the MAC addr for the original victim
  logging.info("Determining top talkers in attack file (this may take awhile)...")
  talkers = get_top_talkers(attackFile, 10)
  logging.info("Attack File Top Talkers:")

  for talker in talkers[:-1]:
    logging.info(talker.strip())

  # prompt the user for the vicitim IP from the attack file (show IPs?)
  oldVictimIp = raw_input("Enter the IP of the victim in the attack pcap: ")
  logging.info("Selected Victim IP: " + oldVictimIp)

  logging.info("Determining MAC address for old victim...")
  oldVictimMac = get_mac_for_ip(attackFile, oldVictimIp)
  logging.info("Old Victim MAC: " + oldVictimMac)

  # prompt the user for the attacker (source) IP from the attack file
  sourceIp = raw_input("Enter the IP of the attacker in the attack pcap: ")
  logging.info("Selected Attacker IP: " + sourceIp)

  # prompt the user for the attack label
  label = raw_input("Enter the label of the attack: ")
  logging.info("Selected label: " + label)

  # prompt the user for the victim IP from the target data file (show IPs?)
  # - get and store both the IP and the MAC addr for the new victim
  logging.info("Determining top talkers in target file (this may take awhile)...")
  talkers = get_top_talkers(dataFile, 10)

  logging.info("Target File Top Talkers:")

  for talker in talkers[:-1]:
    logging.info(talker.strip())

  newVictimIp = raw_input("Enter the IP of the victim in the target pcap: ")
  logging.info("Selected Victim IP: " + newVictimIp)

  logging.info("Determining MAC address for new victim...")
  newVictimMac = get_mac_for_ip(dataFile, newVictimIp)
  logging.info("New Victim MAC: " + newVictimMac)

  # ok, we now have what we need to write out the metadata file
  logging.info("Writing metadata file...")
  write_metadata_file(outFile, newVictimIp, sourceIp, label)

  # change the IP of the victim (bittwiste)
  logging.info("Swapping victim IPs...")
  swap_ips(t1, t2, oldVictimIp, newVictimIp)

  # change the MAC of the victim (bittwiste)
  logging.info("Swapping victim MACs...")
  swap_macs(t2, t3, oldVictimMac, newVictimMac)

  # merge the files
  logging.info("Merging the modified attack data with the target data...")
  merge_pcaps(dataFile, t3, outFile)

  # let's get some summary data
  finalFileData = getPcapDetails(outFile)
  listFileDetails(finalFileData)

  # verify changes were successful
  # - num of pkts in output should be raw + attack
  finalPacketCount = long(get_capinfo_pkt_count(finalFileData))
  attackPacketCount = long(get_capinfo_pkt_count(attackFileData))
  targetPacketCount = long(get_capinfo_pkt_count(dataFileData))
  goal = attackPacketCount + targetPacketCount

  if finalPacketCount == goal:
    logging.info("Verification: Packet Counts Match!!!")
  else:
    logging.error("Packet Count Verification Failed! (" + str(finalPacketCount) + " vs. " + str(goal) + ")")
    logging.error("Final: " + str(finalPacketCount))
    logging.error("Attack: " + str(attackPacketCount))
    logging.error("Target: " + str(targetPacketCount))

  # - start time of output should == start time of raw
  finalOffset = calculate_Needed_Timeshift(finalFileData, dataFileData)

  if finalOffset == 0:
    logging.info("Verification: Start Times Match!!!")
  else:
    logging.error("Start Time Verification Failed! (offset:" + str(finalOffset) + ")")

  # - end time of output should == end time of raw
  finalDuration = calculateDurationInSeconds(finalFileData)
  targetDuration = calculateDurationInSeconds(dataFileData)

  if finalDuration == targetDuration:
    logging.info("Verification: Duration Matches!!!")
  else:
    logging.error("Capture Duration Verification Failed! (" + str(finalDuration) + " vs. " + str(targetDuration) + ")")


if __name__ == '__main__':
  main()
  
