import helper
import sys_info
import analyze_file
import log_analyze

choice = int(input(helper.Interface()))

match choice:
    case 1:
        sys_info.sys_info()
    case 2:
        pathFile = input("Write the file name or path: ")
        analyze_file.analyze_file(pathFile)
    case 3:
        #pathFile = input("Write the file name or path: ")
        log_analyze.analyze_logs("auth.log.txt")