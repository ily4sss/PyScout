def interface():
    return """========================
PyScout
========================
1. System informations
2. Analyze a text file
3. Analyze an SSH log file
choose: """

def investigate_interface():
    return """============ Data investigating ============
1. IPs search 
2. Users search
choose: """

def search_log(file, word, prints):
    count = 0
    file.seek(0)
    for i in file:
        if word in i and "sshd" in i:
            count += 1
    return f"{prints} {count}"

attempts_set = {
    "Accepted publickey",
    "Accepted password",
    "Failed password",
    "Failed publickey",
    "authentication failure"
}
failed_attempts = {
    "Accepted publickey",
    "Accepted password"
}
accept_attempts = {
    "Failed password",
    "Failed publickey",
    "authentication failure"
}