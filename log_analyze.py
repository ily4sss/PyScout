<<<<<<< HEAD
import helper
from datetime import datetime
def analyze_logs(pathFile):
    with open(pathFile) as file:
        print("------ Log Analysis ------")
        print(helper.search_log(file, "sshd", "SSH events:"))
        print(helper.search_log(file, "Accepted publickey", "Successful SSH logins:"))
        print(helper.search_log(file, "Failed password", "Failed SSH logins:"))
        print(helper.search_log(file, "Invalid user", "Invalid user attempts:"))
        print(helper.search_log(file, "session opened", "Sessions opened:"))
        print(helper.search_log(file, "session closed", "Sessions closed:"))
        print(helper.search_log(file, "Connection closed", "Disconnects:"))
        print("--------------------------")
        
        file.seek(0)
        date = {}
        sep = "from "
        ip_duplc = set()
        prompt = "Source IP addresses: "
        
        for i in file:
            
            if sep in i and "sshd" in i:
                start_i = i.find(sep) + len(sep)
                end_i = i.find(" ", start_i)
                ip = i[start_i:end_i]

                if ip in ip_duplc:
                    continue
                ip_duplc.add(ip)
                prompt += ", "
        print(prompt.rstrip(", "))
        
        file.seek(0)
        data = file.readlines()
        status_ip = {}
        ip_dict = {}
        print("--------------------- IP attempts -------------------------")
        for ips in ip_duplc:
            count = 0
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.attempts_set):
                    count += 1
            ip_dict[ips] = count
            print(f"IP [{ips}] : {count} attempts")
        sus_ip = set()
        print("--------- failed -----------")
        for ips in ip_duplc:
            count = 0
            status_ip.setdefault(ips, {"failed" : 0 , "accept": 0})
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.failed_attempts):
                    count += 1
                    
                    date_end = line.find(" ip-")
                    date_str = datetime.now().strftime("%Y") + " " + line[:date_end] if date_end != -1 else ""
                    date_obj = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
                    date.setdefault(ips, []).append(date_obj)
                    
                    status_ip[ips]["failed"] = count
                if count > 10:
                    sus_ip.add(ips)
            print(f"Failed attempts per IP [{ips}] : {count}")
        print("--------- Successful -----------")
        file.seek(0)
        for ips in ip_duplc:
            count = 0
            status_ip.setdefault(ips, {"failed" : 0 , "accept": 0})
            
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.accept_attempts):
                    count += 1
                    status_ip[ips]["accept"] = count
                    
                    date_end = line.find(" ip-")
                    date_str = datetime.now().strftime("%Y") + " " + line[:date_end] if date_end != -1 else ""
                    date_obj = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
                    date.setdefault(ips, []).append(date_obj)
                    
            print(f"Successful attempts per IP [{ips}] : {count}")
        print("----------Date", date)
        print("--------- Suspicious -----------")
        
        prompt = "Suspicious IPs :"
        for ip in sus_ip:
            prompt += ip + ", "
        print (prompt.rstrip(", "))
        
        print("--------- Active -----------")
        
        print(f"Most active IP: {max(ip_dict, key=ip_dict.get)}")
        
        print("--------- Unique -----------")
        
        print(f"Unique IP count : {len(ip_dict)}")
        
        print("--------------------- SSH Users -------------------------")
        
        file.seek(0)
        sep = "session opened for user "
        usr_duplc = set()
        usr_dict = {}
        prompt_usr = "SSH connected users: "
        for i in file:
            if sep in i and "sshd" in i:
                start_i = i.find(sep) + len(sep)
                end_i = i.find(" ", start_i)
                ip = i[start_i:end_i]
                if ip in usr_duplc:
                    continue
                usr_duplc.add(ip)
                prompt_usr += ip + ", "
                
        print(prompt_usr.rstrip(", "))
        print("--------- User attempts -----------")
        for usrs in usr_duplc:
            count = 0
            for line in data:
                if usrs in line and any(attempt in line for attempt in helper.attempts_set):
                    count += 1
            usr_dict[usrs] = count
            print(f"User [{usrs}]: {count} attempts")
        
        print("--------- Most attempted Users  -----------")
        
        print(f"Most attempted username : {max(usr_dict, key=usr_dict.get)}")
        
        print("--------- Unique -----------")
        
        print(f"Unique connected users : {len(usr_dict)}")
        
        choice = int(input(helper.investigate_interface()))
        match choice:
            case 1:
                print("--------------------- Ip Investigation  -------------------------")
                ip = input("Enter an IP to search for its logs (format example: 8.8.8.8):")
                if ip in ip_duplc:
                    print(f"\nIP :{ip}\n")
                    for ips in ip_dict:
                        if ips == ip:
                            print(f"Total attempts: {ip_dict.get(ips, 0)}")
                    if ip in status_ip:
                        print(f"Successful: {status_ip[ip]["accept"]}")
                        print(f"Failed: {status_ip[ip]["failed"]}")
                    if ip in sus_ip:
                        print("Status:  Suspicious")
                    else:
                        print("Status:  Not Suspicious")
                    print("------- Dates -------")
                    if ip in date:
                        if date[ip][0] == date[ip][-1]:
                            print(f"First date of IP [{ip}]: {date[ip][0]}")
                            print("No other dates for this IP")
                        else:
                            print(f"First date of IP [{ip}]: {date[ip][0]}")
                            print(f"Last date of IP [{ip}]: {date[ip][-1]}")
                print("----------------------------------------------")
            case 2:
                print("--------------------- User Investigation -------------------------")
                user = input("Enter a user to search for its logs :")
                if user in usr_dict:
                    print(f"\nUser :{user}\n")
                    for usrs in usr_dict:
                        if user == usrs:
                            print(f"Total attempts: {usr_dict.get(usrs, 0)}")
                            prompt = "Status: "
                            if max(usr_dict, key=usr_dict.get) == user:
                                prompt += "Most attempted user "
                            else:
                                prompt += "None"
                            print(prompt)
                            
                        
=======
import helper

def analyze_logs(pathFile):
    with open(pathFile) as file:
        print("------ Log Analysis ------")
        print(helper.search_log(file, "sshd", "SSH events:"))
        print(helper.search_log(file, "Accepted publickey", "Successful SSH logins:"))
        print(helper.search_log(file, "Failed password", "Failed SSH logins:"))
        print(helper.search_log(file, "Invalid user", "Invalid user attempts:"))
        print(helper.search_log(file, "session opened", "Sessions opened:"))
        print(helper.search_log(file, "session closed", "Sessions closed:"))
        print(helper.search_log(file, "Connection closed", "Disconnects:"))
        print("--------------------------")
        
        file.seek(0)
        sep = "ip-"
        ip_duplc = set()
        prompt = "Source IP addresses: "
        for i in file:
            if sep in i and "sshd" in i:
                start_i = i.find(sep) + len(sep)
                end_i = i.find(" ", start_i)
                ip = i[start_i:end_i]
                if ip in ip_duplc:
                    continue
                ip_duplc.add(ip)
                prompt += ip.replace("-", ".") + ", "
        print(prompt.rstrip(", "))
        file.seek(0)
        data = file.readlines()
        status_ip = {}
        ip_dict = {}
        print("--------------------- IP attempts -------------------------")
        for ips in ip_duplc:
            count = 0
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.attempts_set):
                    count += 1
            ip_dict[ips] = count
            print(f"IP [{ips}] : {count} attempts")
        sus_ip = set()
        print("--------- failed -----------")
        for ips in ip_duplc:
            count = 0
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.failed_attempts):
                    count += 1
                    status_ip.setdefault(ips, {"failed" : 0 , "accept": 0})
                    status_ip[ips]["failed"] = count
                if count > 10:
                    sus_ip.add(ips)
            print(f"Failed attempts per IP [{ips}] : {count}")
        print("--------- Successful -----------")
        for ips in ip_duplc:
            count = 0
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.accept_attempts):
                    count += 1
                    status_ip[ips]["accept"] = count
            print(f"Successful attempts per IP [{ips}] : {count}")
        
        print("--------- Suspicious -----------")
        
        prompt = "Suspicious IPs :"
        for ip in sus_ip:
            prompt += ip + ", "
        print (prompt.rstrip(", "))
        
        print("--------- Active -----------")
        
        print(f"Most active IP: {max(ip_dict, key=ip_dict.get)}")
        count = 0
        for ip in ip_dict:
             count += 1
        
        print("--------- Unique -----------")
        
        print(f"Unique IP count : {count}")
        
        print("--------------------- SSH Users -------------------------")
        
        file.seek(0)
        sep = "session opened for user "
        usr_duplc = set()
        usr_dict = {}
        prompt_usr = "SSH connected users: "
        for i in file:
            if sep in i and "sshd" in i:
                start_i = i.find(sep) + len(sep)
                end_i = i.find(" ", start_i)
                ip = i[start_i:end_i]
                if ip in usr_duplc:
                    continue
                usr_duplc.add(ip)
                prompt_usr += ip + ", "
                
        print(prompt_usr.rstrip(", "))
        print("--------- User attempts -----------")
        for usrs in usr_duplc:
            count = 0
            for line in data:
                if usrs in line and any(attempt in line for attempt in helper.attempts_set):
                    count += 1
            usr_dict[usrs] = count
            print(f"User [{usrs}]: {count} attempts")
        
        print("--------- Most Targeted Users  -----------")
        
        print(f"Most targeted username : {max(usr_dict, key=usr_dict.get)}")
        count = 0
        
        print("--------- Unique -----------")
        
        for usr in usr_dict.keys():
            count += 1
        
        print(f"Unique connected users : {count}")
        
        print("--------------------- Ip investigating -------------------------")
        ip = input("Enter an IP  search for its logs (format example: 8-8-8-8):")
        
        if ip in ip_duplc:
            for ips in ip_dict:
                if ips == ip:
                    print(f"Attempts :{ip_dict.get(ips, 0)}")
            if ip in sus_ip:
                print("Suspicious IP")
            if ip in status_ip:
                print(f"Failed attempts [{ip}] : {status_ip[ip]["failed"]}")
                print(f"Successful attempts [{ip}] : {status_ip[ip]["accept"]}")
        print("----------------------------------------------")
                
>>>>>>> 649c610 (Working on Date timestamps feature)
