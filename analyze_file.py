
def analyze_file(pathFile):
    with open(pathFile) as file:
        data = file.read()
        file.seek(0)
        list_words = data.split()
        print(f"Words: {len(list_words)}")
        total_lines = 0
        for i in file:
            total_lines += 1
        print(f"lines: {total_lines}")
        print(f"total characters: {len(data)}")
        print("------Word dictionary-------")
        history_duplc = set()
        for i in list_words:
            dict_total = 0
            if i in history_duplc:
                continue
            for j in list_words:
                if j == i:
                    dict_total += 1
                    history_duplc.add(i) 
            print(f"{i}: {dict_total}")
        uni_words = set(list_words)
        num_uni_words = 0
        for i in uni_words:
            num_uni_words += 1
        print(f"unique words: {num_uni_words}")