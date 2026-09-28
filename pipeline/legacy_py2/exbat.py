#!c:\python27
# -*- coding: utf-8 -*-
# Decoder Type 01a

# ================================================================================
# extract.py
# Copyright(C) 2015-2016 J-CRAT IPA, Japan. All Rights Reserved.
# ================================================================================
# --------------------------------------------------------------------------------
# FileName:    exbat.py
# Description: CheckPC.bat(0.9.8-f)の出力結果を確認するためのスクリプト
# Author:      Masayuki Ohrui
# Date:        2016/03/02
# Update:      -
# Modify:      -
# --------------------------------------------------------------------------------

import commands
import sys
import argparse
import os
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

# ================================================================================
# メイン
# ================================================================================
def main():
    # オプションの設定
    parser = argparse.ArgumentParser(description="Extract the results of CheckPC.bat(0.9.8-f)", add_help=False)

    parser.add_argument("FILENAME", nargs="*", help="Enter the FILENAME")
    parser.add_argument("-d", "--dns", action="store_true", help="Show DNS History")
    parser.add_argument("-r", "--reg", action="store_true", help="Show System Startup Settings from Registry")
    parser.add_argument("-l", "--link", action="store_true", help="Show Startup Folder .lnk File")
    parser.add_argument("-as", "--activexstartup", action="store_true", help="Show ActiveX Startup")
    parser.add_argument("-s", "--startup", action="store_true", help="Show Startup Files")
    parser.add_argument("-st", "--schtasks", action="store_true", help="Show Task Scheduler")
    parser.add_argument("-sr", "--servicereg", action="store_true", help="Show Service Registry")
    parser.add_argument("-sc", "--service", action="store_true", help="Show Service")
    parser.add_argument("-f", "--file", action="store_true", help="Show Well-known Files")
    parser.add_argument("-a", "--appdata", action="store_true", help="Show AppData Subdirectories")
    parser.add_argument("-t", "--temp", action="store_true", help="Show %%TEMP%% Files")
    parser.add_argument("-o", "--other", action="store_true", help="Show Other Files")
    parser.add_argument("-n", "--netstat", action="store_true", help="Show netstat /ao")
    parser.add_argument("-tl", "--tasklist", action="store_true", help="Show tasklist /svc")
    parser.add_argument("-p", "--process", action="store_true", help="Show wmic process")
    parser.add_argument("-cf", "--compatflags", action="store_true", help="Show AppCompatFlags")
    parser.add_argument("-av", "--antivirus", action="store_true", help="Show AntiVirusProduct/FireWallProduct")
    parser.add_argument("-pf", "--prefetch", action="store_true", help="Show Prefetch")
    parser.add_argument("-rb", "--recentbehavior", action="store_true", help="Show Recent Behavior")
    parser.add_argument("-sfr", "--shellfolderreg", action="store_true", help="Show Shell Folders Registry")
    parser.add_argument("-w", "--wmi", action="store_true", help="Show WMI Setting")
    parser.add_argument("-h", "--hosts", action="store_true", help="Show hosts file")
    parser.add_argument("-sl", "--shortcutlink", action="store_true", help="Show Startup Shortcut Link")

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
        if options.reg:
            startline = "2. Check System Startup Settings from Registry"
            endline = "3. Check Startup Folder"
            ReadFile(filename, startline, endline)

        if options.link:
            startline = "3. Check Startup Folder"
            endline = "4. Check Association of EXE"
            ReadFile(filename, startline, endline)

        if options.activexstartup:
            startline = "6. Check Active Startup"
            endline = "7. Check Task Scheduler"
            ReadFile(filename, startline, endline)

        if options.schtasks:
            startline = "7. Check Task Scheduler"
            endline = "8. Check IP Address"
            ReadFile(filename, startline, endline)

        if options.dns:
            startline = "11. Check DNS"
            endline = "13. Check Net Share and Net Use"
            ReadFile(filename, startline, endline)

        if options.file:
            startline = "15-1. Well-known Files Summary"
            endline = "15-2. AppData Subdirectories"
            ReadFile(filename, startline, endline)

        if options.appdata:
            startline = "15-2. AppData Subdirectories"
            endline = "15-3. %TEMP% Files"
            ReadFile(filename, startline, endline)

        if options.temp:
            startline = "15-3. %TEMP% Files"
            endline = "15-4. Others"
            ReadFile(filename, startline, endline)

        if options.other:
            startline = "15-4. Others"
            endline = "16. Check Netstat"
            ReadFile(filename, startline, endline)

        if options.netstat:
            startline = "16. Check Netstat"
            endline = "17. Check Tasklist"
            ReadFile(filename, startline, endline)

#        if options.netstat:
#            startline = "NETSTAT/ao"
#            endline = "NETSTAT/naob"
#            ReadFile(filename, startline, endline)

        if options.tasklist:
            startline = "17. Check Tasklist"
            endline = "18-1. Check Service"
            ReadFile(filename, startline, endline)

#        if options.process:
#           startline = "wmic process"
#           endline = "18-1. Check Service"
#           ReadFile(filename, startline, endline)

        if options.service:
            startline = "18-1. Check Service"
            endline = "18-2. Check Service Registry"
            ReadFile(filename, startline, endline)

        if options.servicereg:
            startline = "18-2. Check Service Registry"
            endline = "19. Check Shadow Copy"
            ReadFile(filename, startline, endline)

        if options.compatflags:
           startline = "21. Check AppCompatFlags"
           endline = "22. Check AntiVirusProduct/FireWallProduct"
           ReadFile(filename, startline, endline)

        if options.antivirus:
           startline = "22. Check AntiVirusProduct/FireWallProduct"
           endline = "23. Check Prefetch"
           ReadFile(filename, startline, endline)

        if options.prefetch:
           startline = "23. Check Prefetch"
           endline = "24. Check Recent Behavior"
           ReadFile(filename, startline, endline)

        if options.recentbehavior:
           startline = "24. Check Recent Behavior"
           endline = "XX. Check Others"
           ReadFile(filename, startline, endline)

        if options.shellfolderreg:
           startline = "--Check Shell Folders reg--"
           endline = "--Check hosts File--"
           ReadFile(filename, startline, endline)

        if options.hosts:
           startline = "--Check hosts File--"
           endline = "--Check Folder Option reg--"
           ReadFile(filename, startline, endline)

        if options.wmi:
           startline = "--Check WMI Setting--"
           endline = "--Check Empire Script Code reg--"
           ReadFile(filename, startline, endline)

        if options.shortcutlink:
           startline = "--Check Shortcut Link Startup--"
           endline = "\\x1a"
           ReadFile(filename, startline, endline)


if __name__ == '__main__':
    sys.exit(main())
