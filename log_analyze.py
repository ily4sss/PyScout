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
        for ips in ip_duplc:
            count = 0
            for line in data:
                if ips in line and any(attempt in line for attempt in helper.attempts_set):
                    count += 1
            print(f"IP [{ips}] : {count} attempts")
        file.seek(0)
        sep = "session opened for user "
        usr_duplc = set()
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
        print("----------user :", usr_duplc)
        for usrs in usr_duplc:
            count = 0
            for line in data:
                if usrs in line and any(attempt in line for attempt in helper.attempts_set):
                    count += 1
            print(f"User [{usrs}]: {count} attempts")
                    
        print(prompt_usr.rstrip(", "))
        