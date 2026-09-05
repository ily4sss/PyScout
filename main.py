import helper
import sys_info
import analyze_file

choice = int(input(helper.Interface()))

match choice:
    case 1:
        sys_info.sys_info()
    case 2:
        #pathFile = input("Write the file name or path: ")
        analyze_file.analyze_file("test.txt")