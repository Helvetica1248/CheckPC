#!c:\python27
# -*- coding: utf-8 -*-
# Decoder Type 01a

# ================================================================================
# exsummary.py
# Copyright(C) 2015-2016 J-CRAT IPA, Japan. All Rights Reserved.
# ================================================================================
# --------------------------------------------------------------------------------
# FileName:    exsummary.py
# Description: サマリーの出力結果を項目ごとにセパレートするためのスクリプト
# Author:      Mitsuaki Uchino
# Date:        2020/4/1
# Update:      2020/8/24
# Modify:      2020/8/24
# --------------------------------------------------------------------------------

import commands
import sys
import argparse
import os

file_linelist = []

# ================================================================================
# ファイル読み込み
# ================================================================================
def ReadFile(filename, startline, endline):
    # 1行毎にファイル終端まで全て読む(改行文字も含まれる)
    f = open(filename)
    lines2 = f.readlines()
    f.close()

    # 読み込み開始フラグ
    flag = 0
    # ループで1行毎に処理を行う
    for line in lines2:
        # 開始文字列が前方一致した場合、フラグを立てる
        if line.find(startline) != -1:
            flag = 1
        # 終了文字列が前方一致した場合、ループを抜ける
        elif line.find(endline) != -1:
            break

        # フラグが立っている場合、文字を表示する
        if flag == 1:
            print os.path.basename(filename) + ":" + line,

def OutPutListReadFile(filename, startline, endline):
    # 1行毎にファイル終端まで全て読む(改行文字も含まれる)
    f = open(filename)
    lines2 = f.readlines()
    f.close()

    # 読み込み開始フラグ
    flag = 0
    # ループで1行毎に処理を行う
    for line in lines2:
        # 開始文字列が前方一致した場合、フラグを立てる
        if line.find(startline) != -1:
            flag = 1
        # 終了文字列が前方一致した場合、ループを抜ける
        elif line.find(endline) != -1:
            break

        # フラグが立っている場合、文字をlist
        if flag == 1:
            file_linelist.append(line)

# ================================================================================
# メイン
# ================================================================================
def main():
    # オプションの設定
    parser = argparse.ArgumentParser(description="Extract the results of CheckPC.bat(0.9.8-f)", add_help=False)

    parser.add_argument("FILENAME", nargs="*", help="Enter the FILENAME")

    #010_PersistenceRegistry
    parser.add_argument("-pr", "--preg", action="store_true", help="Show Summary from PersistenceRegistry")
    #020_Startup
    parser.add_argument("-su", "--strtup", action="store_true", help="Show Summary from Startup")
    #030_ActiveSetup
    parser.add_argument("-as", "--asetup", action="store_true", help="Show Summary from ActiveSetup")
    #040_TaskScheduler
    parser.add_argument("-ts", "--tsksch", action="store_true", help="Show Summary from TaskScheduler")
    #050_DNS-Cache
    parser.add_argument("-dc", "--dnscch", action="store_true", help="Show Summary from DNS Cache")
    #060_TaskList
    parser.add_argument("-tl", "--tsklst", action="store_true", help="Show Summary from TaskList")
    #070_ConnectionInfo
    parser.add_argument("-ci", "--cctinf", action="store_true", help="Show Summary from ConnectionInfo")
    #080_Service
    parser.add_argument("-sv", "--svc", action="store_true", help="Show Summary from Service")
    #090_Firewall-Rules
    parser.add_argument("-fr", "--frwrl", action="store_true", help="Show Summary from Firewall Rules")
    #100_WMI
    parser.add_argument("-wm", "--wmi", action="store_true", help="Show Summary from WMI")
    #110_COM-Component
    parser.add_argument("-co", "--comcmop", action="store_true", help="Show Summary from COM Component")
    #121_DI-Double-Extension
    parser.add_argument("-dd", "--doubleex", action="store_true", help="Show Summary from Directory Info Double Extension")
    #122_DI-Office-Startup-Folder
    parser.add_argument("-do", "--officestart", action="store_true", help="Show Summary from Directory Info Office Startup Folder")
    #123_DI-Quarantine-File
    parser.add_argument("-dq", "--quarantine", action="store_true", help="Show Summary from Directory Info Quarantine File")
    #124_DI-Suspicious-File
    parser.add_argument("-df", "--suspfile", action="store_true", help="Show Summary from Directory Info Suspicious File")
    #125_DI-Blacklist-File
    parser.add_argument("-db", "--blacklistfile", action="store_true", help="Show Summary from Directory Info Blacklist File")
    #126_DI-Suspicious-Path
    parser.add_argument("-dp", "--susppath", action="store_true", help="Show Summary from Directory Info Suspicious Path")
    #130_Prefetch
    parser.add_argument("-pf", "--prftch", action="store_true", help="Show Parsed_CheckPC from Prefetch")
    #140_AppCompatFlags
    parser.add_argument("-af", "--apcf", action="store_true", help="Show Summary from AppCompatFlags")
    #141_AppCompatCache
    parser.add_argument("-ac", "--apcchk", action="store_true", help="Show Summary from AppCompatCache")
    #150_UserAssist
    parser.add_argument("-ua", "--usrast", action="store_true", help="Show Summary from UserAssist")
    #160_PowerShell-History
    parser.add_argument("-ph", "--powershellhis", action="store_true", help="Show Summary from PowerShell History")
    #170_Others
    parser.add_argument("-ot", "--others", action="store_true", help="Show Summary from Others")


    # 引数の設定
    argvs = sys.argv
    argc = len(argvs)

    # 引数チェック
    if (argc <= 2):
        parser.print_help()
        sys.exit(1)

    # オプションの呼び出し
    options = parser.parse_args()

    # FILENAME(可変長変数)を取り出し、ファイル読み込み関数を実行
    for filename in options.FILENAME:
        #010_PersistenceRegistry
        if options.preg:
            #開始位置
            startline = "[PersistenceRegistry"
            #終了位置
            endline = "[Startup"
            OutPutListReadFile(filename, startline, endline)
            tsline = []

            #ファイルパスなど文字数が多く、分割された項目を結合
            for item in file_linelist:
                pipe = item.split('|')
                if len(pipe) >= 3:
                    if pipe[0].strip() == '':
                        tsline[len(tsline)-1][1] = tsline[len(tsline)-1][1] + pipe[1]
                        continue
                tsline.append(pipe)
                        
            for item1 in range(len(tsline)):
                string = "|".join(tsline[item1])
                print(os.path.basename(filename) + ":" + string.strip("\n"))

        #020_Startup
        if options.strtup:
            #開始位置
            startline = "[Startup"
            #終了位置
            endline = "[ActiveSetup"
            ReadFile(filename, startline, endline)

        #030_ActiveSetup
        if options.asetup:
            #開始位置
            startline = "[ActiveSetup"
            #終了位置
            endline = "[TaskScheduler"
            ReadFile(filename, startline, endline)

        #040_TaskScheduler
        if options.tsksch:
            #開始位置
            startline = "[TaskScheduler"
            #終了位置
            endline = "[DNS Cache"
            OutPutListReadFile(filename, startline, endline)
            tsline = []

            #ファイルパスなど文字数が多く、分割された項目を結合
            for item in file_linelist:
                pipe = item.split('|')
                if len(pipe) >= 5:
                    if pipe[0].strip() == '':
                        tsline[len(tsline)-1][1] = tsline[len(tsline)-1][1] + pipe[1]
                        continue
                tsline.append(pipe)
                        
            for item1 in range(len(tsline)):
                string = "|".join(tsline[item1])
                print(os.path.basename(filename) + ":" + string.strip("\n"))
                
        #050_DNS-Cache
        if options.dnscch:
            #開始位置
            startline = "[DNS Cache"
            #終了位置
            endline = "[TaskList"
            ReadFile(filename, startline, endline)

        #060_TaskList
        if options.tsklst:
            #開始位置
            startline = "[TaskList"
            #終了位置
            endline = "[ConnectionInfo"
            ReadFile(filename, startline, endline)

        #070_ConnectionInfo
        if options.cctinf:
            #開始位置
            startline = "[ConnectionInfo"
            #終了位置
            endline = "[Service"
            ReadFile(filename, startline, endline)

        #080_Service
        if options.svc:
            #開始位置
            startline = "[Service"
            #終了位置
            endline = "[Firewall Rules"
            OutPutListReadFile(filename, startline, endline)
            tsline = []

            #ファイルパスなど文字数が多く、分割された項目を結合
            for item in file_linelist:
                pipe = item.split('|')
                if len(pipe) >= 5:
                    if pipe[0].strip() == '':
                        tsline[len(tsline)-1][3] = tsline[len(tsline)-1][3] + pipe[3]
                        continue
                tsline.append(pipe)
                        
            #結合後の項目を出力
            for item1 in range(len(tsline)):
                string = "|".join(tsline[item1])
                print(os.path.basename(filename) + ":" + string.strip("\n"))

        #090_Firewall-Rules
        if options.frwrl:
            #開始位置
            startline = "[Firewall Rules"
            #終了位置
            endline = "[WMI"
            ReadFile(filename, startline, endline)

        #100_WMI
        if options.wmi:
            #開始位置
            startline = "[WMI"
            #終了位置
            endline = "[COM Component"
            ReadFile(filename, startline, endline)

        #110_COM-Component
        if options.comcmop:
            #開始位置
            startline = "[COM Component"
            #終了位置
            endline = "[Directory Info"
            ReadFile(filename, startline, endline)

        #121_DI-Double-Extension
        if options.doubleex:
            #開始位置
            startline = "+ Double Extension"
            #終了位置
            endline = "+ Office Startup Folder"
            ReadFile(filename, startline, endline)

        #122_DI-Office-Startup-Folder
        if options.officestart:
            #開始位置
            startline = "+ Office Startup Folder"
            #終了位置
            endline = "+ Quarantine File"
            ReadFile(filename, startline, endline)

        #123_DI-Quarantine-File
        if options.quarantine:
            #開始位置
            startline = "+ Quarantine File"
            #終了位置
            endline = "+ Suspicious File"
            ReadFile(filename, startline, endline)

        #124_DI-Suspicious-File
        if options.suspfile:
            #開始位置
            startline = "+ Suspicious File"
            #終了位置
            endline = "+ Blacklist File"
            ReadFile(filename, startline, endline)

        #125_DI-Blacklist-File
        if options.blacklistfile:
            #開始位置
            startline = "+ Blacklist File"
            #終了位置
            endline = "+ Suspicious Path"
            ReadFile(filename, startline, endline)


        #126_DI-Suspicious-Path
        if options.susppath:
            #開始位置
            startline = "+ Suspicious Path"
            #終了位置
            endline = "[Prefetch"
            ReadFile(filename, startline, endline)

        #130_Prefetch
        if options.prftch:
            #開始位置
            startline = "23. Check Prefetch"
            endline = "24. Check Recent Behavior"
            ReadFile(filename, startline, endline)

        #140_AppCompatFlags
        if options.apcf:
            #開始位置
            startline = "[AppCompatFlags"
            #終了位置
            endline = "[AppCompatCache"
            ReadFile(filename, startline, endline)
            
        #141_AppCompatCache
        if options.apcchk:
            startline = "[AppCompatCache"
            #終了位置
            endline = "[UserAssist"
            ReadFile(filename, startline, endline)

        #150_UserAssist
        if options.usrast:
            #開始位置
            startline = "[UserAssist"
            #終了位置
            endline = "[PowerShell History"
            ReadFile(filename, startline, endline)

        #160_PowerShell-History
        if options.powershellhis:
            #開始位置
            startline = "[PowerShell History"
            #終了位置
            endline = "[Others"
            ReadFile(filename, startline, endline)

        #17Other
        if options.others:
            #開始位置
            startline = "[Others"
            #終了位置
            endline = "EOF EOF EOF"
            ReadFile(filename, startline, endline)




if __name__ == '__main__':
    sys.exit(main())
