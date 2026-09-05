def Interface():
    return """========================
PyScout
========================
1. System informations
2. Analyze a text file
3. Analyze a log file
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