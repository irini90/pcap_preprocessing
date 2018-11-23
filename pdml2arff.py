#!/usr/bin/python
# change the path (above) to reflect where you have python installed
#
# this script will take a tshark generated pdml file and turn it
# into an arff formatted file, suitable for ingestment by weka
# here's how to create the pdml file from pcap:
# tshark -T pdml -r <infile> > <outfile>
# (adding -V gets you no more data)
# usage of this script: pdml2arff.py <outfile> (outfile is pdml from above)
# ./pdml2arff.py <input_file> -o <output_file(optional)> -n (convert all strings to numerics

import csv
import time
import progressbar
import fileinput
from datetime import datetime

bar = progressbar.ProgressBar(widgets=[
    ' [', progressbar.Timer(), '] ',
    progressbar.Bar(),
    ' (', progressbar.ETA(), ') ',
])

class myDialect(csv.Dialect):
    delimiter = ','
    quotechar = '"'
    quoting = csv.QUOTE_NONNUMERIC
    lineterminator = "\n"
    doublequote = False
    skipinitialspace = False

#
# Define a simple class to wrap functions
#
class PdmlConvert:
    def __init__( self, templateString , numbers_only=False ):
        self.template = templateString
        self.numbers_only = numbers_only
        self.headers = [
            "packet_id",
            "num",
            "len",
            "caplen",
            "timestamp",
            "frame.offset_shift",
            "frame.time_epoch",
            "frame.time_delta",
            "frame.time_delta_displayed",
            "frame.time_relative",
            "frame.number",
            "frame.len",
            "frame.cap_len",
            "frame.marked",
            "frame.ignored",
            "ip.version",
            "ip.hdr_len",
            "ip.dsfield.dscp",
            "ip.dsfield.ecn",
            "ip.src",
            "ip.dst",
            "ip.len",
            "ip.flags",
            "ip.flags.rb",
            "ip.flags.df",
            "ip.flags.mf",
            "ip.frag_offset",
            "ip.ttl",
            "ip.proto",
            "ip.checksum.status",
            "tcp.stream",
            "tcp.len",
            "tcp.seq",
            "tcp.nxtseq",
            "tcp.ack",
            "tcp.hdr_len",
            "tcp.flags",
            "tcp.flags.res",
            "tcp.flags.ns",
            "tcp.flags.cwr",
            "tcp.flags.ecn",
            "tcp.flags.urg",
            "tcp.flags.ack",
            "tcp.flags.push",
            "tcp.flags.reset",
            "tcp.flags.syn",
            "tcp.flags.fin",
            "tcp.window_size_value",
            "tcp.window_size",
            "tcp.window_size_scalefactor",
            "tcp.checksum.status",
            "tcp.urgent_pointer",
            "tcp.options.timestamp.tsval",
            "tcp.options.timestamp.tsecr",
            "tcp.analysis.bytes_in_flight",
            "tcp.analysis.push_bytes_sent",
            "tcp.time_relative",
            "tcp.time_delta",
            "tcp.payload",
            "icmp.type",
            "icmp.code",
            "icmp.ident",
            "icmp.seq",
            "icmp.seq_le",
            "icmp.resp_in",
            "data.len",
            "udp.srcport",
            "udp.dstport",
            "udp.length",
            "udp.checksum.status",
            "udp.stream",
            "dns.flags.response",
            "dns.flags.opcode",
            "dns.flags.truncated",
            "dns.flags.recdesired",
            "dns.flags.z",
            "dns.flags.checkdisable",
            "dns.count.queries",
            "dns.count.answers",
            "dns.count.auth_rr",
            "igmp.type",
            "igmp.max_resp",
            "ntp.flags.li",
            "ntp.flags.vn",
            "ntp.flags.mode",
            "ntp.stratum",
            "ntp.ppoll",
            "ntp.rootdelay",
            "ntp.rootdispersion",
            "ntp.precision"
        ]
        self.results = []
        self.packet_count = 1

    #
    # convert the given input to ARFF format
    #
    def convert_file( self, input_file , **kwargs ):
        fname,ext = self.parse_filename( input_file )
        output_file = kwargs.get( 'output_file', fname+'.arff' )
        startTime = datetime.now()
        print(output_file + ' is about to be generated...')
        self.parse_file( input_file )
        header = self.build_header( input_file )    # build the top section of output file
        self.write_to_file( header , output_file )    # write top section to output file
        self.append_array_of_dict_to_csv( output_file )    # write data to output file
        self.remove_quotation_marks_from_question_marks( output_file ) # remove all quotation marks around question marks
        print(output_file + ' has been generated successfully in ' + str(datetime.now() - startTime) + '...')

    #
    # Replaces all instances of '"?"' with '?' in the file output_file
    # Saves back to output_file
    #
    def remove_quotation_marks_from_question_marks ( self, output_file ):
        # Read in the file
        with open(output_file, 'r') as file :
          filedata = file.read()

        # Replace the target string
        filedata = filedata.replace('"?"', '?')

        # Write the file out again
        with open(output_file, 'w') as file:
          file.write(filedata)

    #
    #  uses xml.dom.minidom to parse input xml file
    #  - reads each packet -> proto -> field
    #  - creates a key/value results dict {} for each field
    #  - new fields are added to headers array
    #
    def parse_file( self , file ):
        counter = 0
        from xml.dom import minidom    # load minidom
        self.clean_file( file )        # found a parsing error in input data, see clean_file for info
        xmldoc = minidom.parse( file )    # use minidom to parse xml
        packetCount = len(xmldoc.getElementsByTagName('packet'))
        for packet in xmldoc.getElementsByTagName('packet'):# for every packet -> proto -> field...
            counter +=1
            bar.update((counter/packetCount)*100)
            self.parse_packet(packet)

    #
    #
    def parse_packet( self , packet ):
        id = self.packet_count
        self.packet_count += 1
        arf = self.create_arf( id )
        for field in packet.getElementsByTagName('field'):
            if field.getAttribute('name') in self.headers:
                arf = self.parse_field_into_arf( arf , field )
            for subfield in field.getElementsByTagName('field'):
                arf = self.parse_field_into_arf( arf , subfield )
        self.results.append( arf )


    #
    # parse_field_into_arf ( arf , field )
    #                      Adds any field or subfields to arf {} if it has a value
    #
    def parse_field_into_arf( self , arf , field ):
        field_name = field.getAttribute('name')    # get name attribute of field
        arf = self.append_key_value( field_name , self.get_value_from_field( field ) , arf )    # append key/val to arf dict {}

        # Some fields have children subfields with values
        for subfield in field.getElementsByTagName('field'):
            sf_name = subfield.getAttribute('name')
            arf = self.append_key_value( sf_name , self.get_value_from_field( subfield ) , arf )
        return arf

    #
    #
    #
    def append_key_value( self , key , value , map ):
        if value == '':
            return map
        if not key in self.headers and key != 'ip.src' and key != 'ip.dst':
            self.headers.append(key)
        map[key] = value
        return map

    #
    # Returns an unmaskedvalue or a vlue or '' from field attributes
    #
    def get_value_from_field( self , field ):
            # Gen Info
        if field.getAttribute('name') == "num":
            return int(field.getAttribute('size'))
        elif field.getAttribute('name') == "len":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "caplen":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "timestamp":
            return float(field.getAttribute('value'))
            # -------------------------------------
            # Frame
        elif field.getAttribute('name') == "frame.offset_shift":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.time_epoch":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.time_delta":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.time_delta_displayed":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.time_relative":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.number":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.len":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.cap_len":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.marked":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "frame.ignored":
            return int(field.getAttribute('show'))
            # this attribute is a string
        # elif field.getAttribute('name') == "frame.protocols":
        #     return str(field.getAttribute('show'))
            # --------------------------------------
            # Ethernet layer we excluded as it contains identifiable information
            # IP
        elif field.getAttribute('name') == "ip.version":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ip.hdr_len":
            return int(field.getAttribute('show'))
        # elif field.getAttribute('name') == "ip.dsfield":
        #     return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ip.dsfield.dscp":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ip.hdr_len":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ip.dsfield.ecn":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ip.src":
            return field.getAttribute('show')
        elif field.getAttribute('name') == "ip.dst":
            return field.getAttribute('show')
        elif field.getAttribute('name') == "ip.len":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ip.flags":
            return int(field.getAttribute('pos'))
        elif field.getAttribute('name') == "ip.flags.rb":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ip.flags.df":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ip.flags.mf":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ip.frag_offset":
            return int(field.getAttribute('show'))

        elif field.getAttribute('name') == "ip.ttl":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ip.proto":
            return int(field.getAttribute('show'))
            # checksum is a hex value
        # elif field.getAttribute('name') == "ip.checksum":
        #     return int(field.getAttribute('value'))
            # ------------------------
        elif field.getAttribute('name') == "ip.checksum.status":
            return int(field.getAttribute('show'))
            # end of IP none of address info included
            # tcp

        elif field.getAttribute('name') == "tcp.stream":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.len":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.seq":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.nxtseq":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.ack":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.hdr_len":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.flags":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.res":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.ns":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.cwr":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.ecn":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.urg":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.ack":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.push":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.reset":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.syn":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.flags.fin":
            return int(field.getAttribute('value'))
            # tcp.flags.str is a string attribute
        # elif field.getAttribute('name') == "tcp.flags.str":
        #     return int(field.getAttribute('show'))
            # ----------------------------------
        elif field.getAttribute('name') == "tcp.window_size_value":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.window_size":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.window_size_scalefactor":
            return int(field.getAttribute('show'))
            # tcp.checksum is supposed to be a string
        # elif field.getAttribute('name') == "tcp.checksum":
        #     return int(field.getAttribute('value'))
            # ------------------------------------
        elif field.getAttribute('name') == "tcp.checksum.status":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.urgent_pointer":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "tcp.options.timestamp.tsval":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.options.timestamp.tsecr":
            return int(field.getAttribute('show'))

        elif field.getAttribute('name') == "tcp.analysis.bytes_in_flight":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.analysis.push_bytes_sent":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.time_relative":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.time_delta":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "tcp.payload":
            return float(field.getAttribute('size'))
            # icmp layer
        elif field.getAttribute('name') == "icmp.type":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "icmp.code":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "icmp.ident":
            return int(field.getAttribute('show'))
            # icmp checksum is a hex value
        # elif field.getAttribute('name') == "icmp.checksum":
        #     return float(field.getAttribute('show'))
            # ---------------------------------
        elif field.getAttribute('name') == "icmp.seq":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "icmp.seq_le":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "icmp.resp_in":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "data.len":
            return int(field.getAttribute('show'))
            # udp layer
        elif field.getAttribute('name') == "udp.srcport":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "udp.dstport":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "udp.length":
            return int(field.getAttribute('show'))
        # elif field.getAttribute('name') == "udp.checksum":
        #     return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "udp.checksum.status":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "udp.stream":
            return int(field.getAttribute('show'))
            # dns layer
        # elif field.getAttribute('name') == "dns.id":
        #     return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "dns.flags.response":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "dns.flags.opcode":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "dns.flags.truncated":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "dns.flags.recdesired":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "dns.flags.z":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "dns.flags.checkdisable":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "dns.count.queries":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "dns.count.answers":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "dns.count.auth_rr":
            return int(field.getAttribute('value'))

            # igmp layer
        elif field.getAttribute('name') == "igmp.type":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "igmp.max_resp":
            return int(field.getAttribute('value'))
            # ntp layer
        elif field.getAttribute('name') == "ntp.flags.li":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ntp.flags.vn":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ntp.flags.mode":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ntp.stratum":
            return int(field.getAttribute('value'))
        elif field.getAttribute('name') == "ntp.ppoll":
            return int(field.getAttribute('show'))
        elif field.getAttribute('name') == "ntp.rootdelay":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "ntp.rootdispersion":
            return float(field.getAttribute('show'))
        elif field.getAttribute('name') == "ntp.precision":
            return int(field.getAttribute('show'))
        else:
            return ''

    #
    #
    #
    def create_arf( self , id ):
        return { 'packet_id': id }

    #
    # This clean file is a simple xml cleaner of the <proto> </proto> element
    # In the input files I've seen, there is an extra </proto> which shows up
    # just before a '</packet>' in the data (often but not always).  So this function
    # counts each opening '<proto' and closing '</proto>' and whenever we see an extra
    # (count < 0) we do not output that extra one.  This seems to clean the file properly.
    #
    def clean_file( self , file ):
        import re
        stack = 0
        output = []
        for line in open( file , 'r'):
            if re.search('<proto',line):
                stack += 1
            elif re.search('</proto>',line):
                stack -= 1

            if stack >= 0:
                output.append(line)
            else:
                stack += 1

        o = open(file,'wb')
        for line in output:
            o.write( line )

    #
    # Appends and Array of Dictionaries to given filename
    # - inserts headers at beginning (of where appending happens)
    #
    def append_array_of_dict_to_csv( self , filename ):
        csvfile = open(filename, 'ab')    # open file for appending
        dialect = myDialect()
        # self.headers.append('packet_type')
        self.headers.append('class')
        csvw = csv.DictWriter( csvfile , self.headers, '?' , dialect=dialect )    # instantiate DictWriter
        for kvs in self.results:    # for every dict result, append dict to csv
            if self.numbers_only:
                kvs = self.map2num( kvs )
            if 'ip.src' in kvs and kvs['ip.src'] == '172.16.5.56':
                kvs['class'] = 'malicious'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.114':
            #     kvs['class'] = 'BelkinCam'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.121':
            #     kvs['class'] = 'Hive'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.122':
            #     kvs['class'] = 'SmartThings'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.125':
            #     kvs['class'] = 'Lifx'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.127':
            #     kvs['class'] = 'TPLinkCam'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.123':
            #     kvs['class'] = 'TPLinkPlug'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.109':
            #     kvs['class'] = 'AmazonEcho'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.114':
            #     kvs['class'] = 'BelkinCam'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.121':
            #     kvs['class'] = 'Hive'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.122':
            #     kvs['class'] = 'SmartThings'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.125':
            #     kvs['class'] = 'Lifx'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.127':
            #     kvs['class'] = 'TPLinkCam'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.123':
            #     kvs['class'] = 'TPLinkPlug'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.2':
            #     kvs['class'] = 'AP'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.src' in kvs and kvs['ip.src'] == '192.168.200.3':
            #     kvs['class'] = 'Firewall'
            #     kvs['packet_type'] = 'out'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.2':
            #     kvs['class'] = 'AP'
            #     kvs['packet_type'] = 'in'
            # elif 'ip.dst' in kvs and kvs['ip.dst'] == '192.168.200.3':
            #     kvs['class'] = 'Firewall'
            #     kvs['packet_type'] = 'in'
            else:
                kvs['class'] = 'benign'
                # kvs['packet_type'] = '?'

            # remove these as we do not want them to appear in our results
            if 'ip.src' in kvs:
                kvs.pop('ip.src', None)
            if 'ip.dst' in kvs:
                kvs.pop('ip.dst', None)

            csvw.writerow( kvs )

    #
    # Writes text to filename
    #
    def write_to_file( self , text , filename ):
        f = open( filename , 'wb')
        f.write( text )

    #
    # Build header/top section of output file
    #
    def build_header( self , filename ):
        from string import Template
        text = Template( self.template ) # Template example:
        attr_str = "" # temp = Template('this is a $INSERT')
        for attr in self.headers:     # print temp.substitute(INSERT='test')
            attr_str += "@attribute " + attr + " numeric" + "\n" # use this if outputting "numeric" data type
        # attr_str += "@attribute packet_type {in, out}\n"
        attr_str += "@attribute class {malicious,benign}"
        return text.substitute(RELATION=filename,ATTRIBUTES=attr_str)

    #
    # Parse a filename into its base name and extension
    # returns [basename,ext] or 'Invalid Filename'
    #
    def parse_filename( self , name ):
        import re
        r = re.search( r"(\S+)(\.\S{1,4})$", name )
        if r:
            return [ r.group(1) , r.group(2) ]
        else:
            raise 'Invalid Filename'

    #
    #  converts each value of the given map/dict to an integer using str2num
    #
    def map2num( self , m ):
        result = {}
        for k,v in m.iteritems():
            result[k] = self.str2num(v)
        return result

    #
    # Convert a string to a number (takes the ord value of each letter and
    # combines it then converts it to int)
    # i.e. str2num( 'abc' ); ord('a') = 97; "979899" => returns 979899 as int
    #
    def str2num( self , s ):
        if type(s) is int:
            return s
        num = ''
        for letter in s:
            o = ord(letter)
            num += str(o)
        return int(num)

    #
    #  Write errors to log
    #
    def error_log( self , message ):
        f = open('pdml.errors.log','wb')
        f.write( message )

# Template ARFF File
arff = '''
%
% This arff created by pdml2arff.py
% Written by Tim Stello with input from Charlie Fowler, spring 2013
% This script takes a pdml file created by tshark and converts it to arff
%
@relation $RELATION
%
%attributes
%
$ATTRIBUTES
%
@data
%
'''

#
# Main: this portion executes only when this file is executed
# from the command line.  If you 'import' this file, this section
# will not execute
#
if __name__ == '__main__':
    import sys
    usage = "./pdml2arffpy <input_file> -o <output_file (optional)> -n (convert all strings to numerics)\n"
    numbers_only = False
    if '-n' in sys.argv:
        numbers_only = True
        sys.argv.remove('-n')
    pdmlc = PdmlConvert(arff , numbers_only )
    l = len(sys.argv)
    if l == 2:
        pdmlc.convert_file( sys.argv[1] )
    elif l == 4:
        pdmlc.convert_file( sys.argv[1] , { 'output_file':sys.argv[3] })
    else:
        print usage
        sys.exit
