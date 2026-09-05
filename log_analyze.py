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
        sep = "session opened for user "
        usr_duplc = set()
        prompt = "SSH connected users: "
        for i in file:
            if sep in i and "sshd" in i:
                start_i = i.find(sep) + len(sep)
                end_i = i.find(" ", start_i)
                ip = i[start_i:end_i]
                if ip in usr_duplc:
                    continue
                usr_duplc.add(ip)
                prompt += ip + ", "
        print(prompt.rstrip(", "))
        