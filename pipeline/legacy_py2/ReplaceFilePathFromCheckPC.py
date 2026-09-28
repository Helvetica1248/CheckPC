#!/usr/bin/python
# coding: utf-8

import sys
import os.path
import re
import traceback


def main(args=[]):
    argc = len(args)

    if argc < 2:
        print "usage: " + args[0] + " [FILE]"
        sys.exit(1)

    if os.path.exists(args[1]):
        try:
            input = open(args[1], "r")
        except:
            sys.exit(1)
        checkPC_dirname=os.path.dirname(args[1])
        if checkPC_dirname != "" and checkPC_dirname[len(checkPC_dirname)-1] != "/":
            checkPC_dirname += "/"
        checkPC_filename=os.path.basename(args[1]).replace("Temp_","")
        output = open(checkPC_dirname+"Parsed_"+checkPC_filename, "w")
        flag_dircmd=False
        dircmd_path=""
        count=0
        try:
            line = input.readline().replace("\r\n","\n")
            output.write(line)
 
            while line:
                try:
                    line = input.readline().replace("\r\n","\n")
                    if flag_dircmd:
                        if line == "\n":
                            count+=1
                        else:
                            if re.match(r"[0-9]{2}/[0-9]{2}/[0-9]{4}  [0-9]{2}:[0-9]{2} (AM|PM).*", line):
                                year=line[6:10]
                                day=line[3:5]
                                month=line[0:2]
                                if line[18:20] == "PM":
                                    hour=str(int(line[12:14],10)+12)
                                else:
                                    hour=line[12:14]
                                minute=line[15:17]
                                date="%s/%s/%s  %s:%s" %(year,month,day,hour,minute)
                                line=date+line[20:]
                                dir_filepath=dircmd_path.rstrip("\\")+"\\"+line[36:]
                                line=line[:36]+dir_filepath

                            elif re.match(r"[0-9]{4}/[0-9]{2}/[0-9]{2}  (午前|午後) [0-9]{2}:[0-9]{2} .*", line):
                                if line[12:18] == "午後" and line[19:21] != "12":
                                    hour=str(int(line[19:21],10)+12)
                                elif line[12:18] == "午前" and line[19:21] == "12":
                                    hour="00"
                                else:
                                    hour=line[19:21]
                                minute=line[22:24]
                                date="%s  %s:%s" %(line[0:10],hour,minute)
                                line=date+line[24:]
                                dir_filepath=dircmd_path.rstrip("\\")+"\\"+line[36:]
                                line=line[:36]+dir_filepath

                            elif re.match(r'[0-9]{2}/[0-9]{2}/[0-9]{4}  [0-9]{2}:[0-9]{2}.*', line):
                                year=line[6:10]
                                day=line[3:5]
                                month=line[0:2]
                                hour=line[12:14]
                                minute=line[15:17]
                                date="%s/%s/%s  %s:%s" %(year,month,day,hour,minute)
                                line=date+line[17:]
                                dir_filepath=dircmd_path.rstrip("\\")+"\\"+line[36:]
                                line=line[:36]+dir_filepath

                            elif re.match(r'[0-9]{4}/[0-9]{2}/[0-9]{2}  [0-9]{2}:[0-9]{2}.*', line):
                                dir_filepath=dircmd_path.rstrip("\\")+"\\"+line[36:]
                                line=line[:36]+dir_filepath
                                
                            elif re.match(r'[0-9]{2}/[0-9]{2}/[0-9]{2}  [0-9]{2}:[0-9]{2}.*', line):
                                dir_filepath=dircmd_path.rstrip("\\")+"\\"+line[34:]
                                line=line[:34]+dir_filepath

                        if count == 2:
                            count = 0
                            flag_dircmd=False
                            dircmd_path = ""

                    else:
                        if line.find("のディレクトリ") > 0:
                             dircmd_path=line.replace("のディレクトリ","").strip()
                             flag_dircmd=True
                        elif line.find("議朕村") > 0:
                             dircmd_path=line.replace("議朕村","").strip()
                             flag_dircmd=True
                        elif line.find("Directory of") > 0:
                             dircmd_path=line.replace("Directory of","").strip()
                             flag_dircmd=True

                    output.write(line)
                except:
                    traceback.print_exc()
            input.close()

        except:
            traceback.print_exc()
        output.close()

if __name__ == '__main__':
    main(sys.argv)