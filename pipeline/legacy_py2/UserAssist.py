# UserAssist.py
# coding: utf-8

# Author : S.Nagahori
# Creation Date:2017/04/25
# Last Updated Date:2017/11/02


import sys
import struct
import zipfile
import argparse
import binascii
import datetime
import codecs
import cStringIO as sio
import xml.etree.cElementTree as et
import re
from os import path
from csv import writer

# Values used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
CACHE_MAGIC_NT5_2 = 0xbadc0ffe
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

# Values used by Windows 6.1 (Win7 and Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xbadc0fee
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

# Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xdeadbeef
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

# Values used by Windows 8
WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = '00ts'

# Magic value used by Windows 8.1
WIN81_MAGIC = '10ts'

# Values used by Windows 10
WIN10_STATS_SIZE = 0x30
WIN10_MAGIC = '10ts'
CACHE_HEADER_SIZE_NT6_4 = 0x30
CACHE_MAGIC_NT6_4 = 0x30

bad_entry_data = 'N/A'
g_verbose = False
g_usebom = False
output_header  = ["Last Modified", "Last Update", "Path", "File Size", "Exec Flag"]

# Date Formats
DATE_MDY = "%m/%d/%y %H:%M:%S"
DATE_ISO = "%Y-%m-%d %H:%M:%S"
g_timeformat = DATE_ISO

# Convert FILETIME to datetime.
# Based on http://code.activestate.com/recipes/511425-filetime-to-datetime/
def convert_filetime(dwLowDateTime, dwHighDateTime):

    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return date + datetime.timedelta(microseconds=temp_time/10,hours=9) ####Update20170221byJCRAT
    except OverflowError, err:
        return None

# Return a unique list while preserving ordering.
def unique_list(li):

    ret_list = []
    for entry in li:
        if entry not in ret_list:
            ret_list.append(entry)
    return ret_list

# Write the Log.
def write_it(rows, outfile=None):

    try:

        if not rows:
            print "[-] No data to write..."
            return

        if not outfile:
            for row in rows:
                print " ".join(["%s"%x for x in row])
        else:
            print "[+] Writing output to %s..."%outfile
            try:
                f = open(outfile, 'wb')
                if g_usebom:
                    f.write(codecs.BOM_UTF8)
                csv_writer = writer(f, delimiter=',')
                csv_writer.writerows(rows)
                f.close()
            except IOError, err:
                print "[-] Error writing output file: %s" % str(err)
                return

    except UnicodeEncodeError, err:
        print "[-] Error writing output file: %s" % str(err)
        return


# Read value of [*\Count] registry 
def read_count(countbin, quiet=False):
   binlen = len(countbin)
   if binlen < 20:
        # Data size less than minimum header size.
        return None

   out_list = []

   num_counts = struct.unpack('<L', countbin[4:8])[0]
   #print num_counts
   
   file_time = struct.unpack('<2L', countbin[binlen-12:binlen-4])
   try:
       file_time = convert_filetime(file_time[0], file_time[1]).strftime(g_timeformat)
   except:
       file_time = 'N/A'

   row = [num_counts, file_time]
   out_list.append(row)
   if len(out_list) == 0:
        return None
   return out_list 
   
def _rot13(c):
    if 'A' <= c and c <= 'Z':
        return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))

    if 'a' <= c and c <= 'z':
        return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))

    return c
   
def rot13(s):
    g = (_rot13(c) for c in s)
    return ''.join(g)

# Get UserAssist data from .reg file.
# Finds the first key named "Count" and parses the
# Hex data that immediately follows. It's a brittle parser,
# but the .reg format doesn't change too often.
def read_from_reg(reg_file, quiet=False):
    out_list = []

    if not path.exists(reg_file):
        return None

    f = open(reg_file, 'rb')
    file_contents = f.read()
    f.close()
#    try:
#        file_contents = file_contents.decode('utf-16')
#    except:
#        pass #.reg file should be UTF-16, if it's not, it might be ANSI, which is not fully supported here.

    if not file_contents.startswith('Windows Registry Editor'):
        print "[-] Unable to properly decode .reg file: %s" % reg_file
        return None

    path_name = None
    relevant_lines = []
    found_count = False
    count_keys = 0
    for line in file_contents.split("\r\n"):
        if re.match('\".+\"=hex:', line.lower()):
            r = re.compile("\"(.+)\"=hex:(.+)")
            m = r.search(line)
            key_name = rot13(m.group(1))
            relevant_lines.append(m.group(2))
            found_count = True
        elif '\\count]' in line.lower():
            # The Registry path is not case sensitive. Case will depend on export parameter.
            path_name = line.partition('[')[2].partition(']')[0]
            count_keys += 1
        elif found_count and '\\' not in line:
            relevant_lines.append(line)
            hex_str = "".join(relevant_lines).replace('\\', '').replace(' ', '').replace(',', '')
            bin_data = binascii.unhexlify(hex_str)
            tmp_list = read_count(bin_data, quiet)
            if tmp_list:
                for row in tmp_list:
                    row.append(key_name)
                    if row not in out_list:
                        out_list.append(row)
            found_count = False
            path_name = None
            relevant_lines = []
        elif found_count and "," in line and '\"' not in line:
            relevant_lines.append(line)

        elif found_count and (len(line) == 0 or '\"' in line):
            # begin processing a block
            hex_str = "".join(relevant_lines).replace('\\', '').replace(' ', '').replace(',', '')
            bin_data = binascii.unhexlify(hex_str)
            tmp_list = read_count(bin_data, quiet)

            if tmp_list:
                for row in tmp_list:
                    row.append(key_name)
                    if row not in out_list:
                        out_list.append(row)

            # reset variables for next block
            found_count = False
            path_name = None
            relevant_lines = []
            break

    if count_keys <= 0:
        print "[-] Unable to find value in .reg file: %s" % reg_file
        return None

    if len(out_list) == 0:
        return None
    else:
        # Add the header and return the list.
        if g_verbose:
            out_list.insert(0, output_header + ['Key Path'])
            return out_list
        else:
        # Only return unique entries.
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

# Do the work.
def main(argv=[]):

    global g_verbose
    global g_timeformat
    global g_usebom

    parser = argparse.ArgumentParser(description="Parses UserAssist data")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Toggles verbose output")
    parser.add_argument("-t","--isotime", action="store_const", dest="timeformat", const=DATE_ISO, default=DATE_MDY,
        help="Use YYYY-MM-DD ISO format instead of MM/DD/YY default")
    parser.add_argument("-B", "--bom", action="store_true", help="Write UTF8 BOM to CSV for easier Excel 2007+ import")

    group = parser.add_argument_group()
    group.add_argument("-o", "--out", metavar="FILE", help="Writes to CSV data to FILE (default is STDOUT)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--local", action="store_true", help="Reads data from local system")
    group.add_argument("-b", "--bin", metavar="BIN", help="Reads data from a binary BIN file")
    group.add_argument("-m", "--mir", metavar="XML", help="Reads data from a MIR XML file")
    group.add_argument("-z", "--zip", metavar="ZIP", help="Reads ZIP file containing MIR registry acquisitions")
    group.add_argument("-i", "--hive", metavar="HIVE", help="Reads data from a registry reg HIVE")
    group.add_argument("-r", "--reg", metavar="REG", help="Reads data from a .reg registry export file")

    args = parser.parse_args(argv[1:])

    if args.verbose:
        g_verbose = True

    # Set date/time format
    g_timeformat = args.timeformat

    # Enable UTF8 Byte Order Mark (BOM) so Excel imports correctly
    if args.bom:
        g_usebom = True

    # Read the key data from a registry hive.
    elif args.reg:
        print "[+] Reading .reg file: %s..." % args.reg
        entries = read_from_reg(args.reg)
        if not entries:
            print "[-] No UserAssist entries found..."
        else:
            write_it(entries, args.out)

if __name__ == '__main__':
    main(sys.argv)
