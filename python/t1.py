import xml.etree.cElementTree as cElementTree
import sys
import optparse
import uuid
import logging
import logging.config
import os

reload(sys)
sys.setdefaultencoding("utf-8")

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


#
# This post contains some details about various platforms file system limits:
# http://stackoverflow.com/questions/7722130/what-is-the-max-number-of-files-that-can-be-kept-in-a-single-folder-on-win7-mac
#
# using sub-sections of 4 digits would lead to a maximimum of 65,535 files per directory.
# while this is certainly possible, limiting it to something much smaller is more likely 
# to remain more manageable.
# Three hex digits gives a maximum range of 4095.
#
# given that the hex representation of a UUID in python is 32 bytes, 
# we get a maximum depth of 10 directory levels plus files
# 
# we assume that uid is 32 chars long
# given a base value of "C:\scratch"
# and a uid of fb0ac9ca66a848b696676ce84cf1d252
# the resultant value is something like:
# C:\scratch\fb0\ac9\ca6\6a8\48b\696\676\ce8\4cf\1d2
def buildPath(base, uid):
	dirLength = 3
	numDirs = 2
	path = base

	for i in range(numDirs):
		idxr = i * dirLength
		path = os.path.join(path, uid[idxr:idxr + dirLength])

	return path


def ensureDir(f):
    d = os.path.dirname(f)
    if not os.path.exists(d):
        os.makedirs(d)


def buildUniqueFilePath(outputDirectory):
	uid = uuid.uuid4()
	dirPath = buildPath(outputDirectory, uid.hex)
	return os.path.join(dirPath, uid.hex)

  
def parseRevisionFile(inputFile, outputDirectory):
	count = 0
	context = cElementTree.iterparse(inputFile, events=("start", "end", "start-ns"))
	root = None
	namespace = '{http://www.mediawiki.org/xml/export-0.8/}'
	count = 0

	for event, elem in context:

		if event == "start" and root is None:
			root = elem
			continue
		# Find each revision
		if event == "end" and elem.tag == namespace +"revision":
			for i in range(len(elem)):
				# Text element of each revision
				if elem[i].tag == namespace + "text" and elem[i].text is not None:
					# Ignore redirects
					if elem[i].text.startswith('#REDIRECT',0,9):
						print "Redirect"
					else:
						# grab the text and write it out
						text = elem[i].text
						filePath = buildUniqueFilePath(outputDirectory)
						ensureDir(filePath)
						f = open(filePath, 'w+')
						f.write(text)
						f.close()
						#logging.info("Wrote File: " + filePath)
						count = count + 1
					
						if ((count % 100) == 0):
							logging.info("Created: {:,.0f}".format(count) + " files")


			root.clear()

	logging.info("Finshed processing file. Created {:,.0f}".format(count) + " files")


def main():
	parser = optparse.OptionParser('usage %prog -i <input file> -o <output directory>')
  	parser.add_option('-i', dest='inputFile', type='string', help='specify the input file')
  	parser.add_option('-o', dest='outputDirectory', type='string', help='specify the output directory')

  	(options, args) = parser.parse_args()
  	inputFile = options.inputFile
  	outputDirectory = options.outputDirectory

  	if inputFile == None or outputDirectory == None:
  		print parser.usage
  		exit(0)

  	# if we are still here, let's parse this sucker
  	parseRevisionFile(inputFile, outputDirectory)


if __name__ == "__main__":
	main()