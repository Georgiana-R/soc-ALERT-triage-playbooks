# Simple log parser for suspicious keywords

keywords = ["powershell", "encoded", "cmd.exe"]

with open("sample_logs.txt", "r") as file:
    for line_number, line in enumerate(file, start=1):
        lower_line = line.lower()

        for word in keywords:
            if word in lower_line:
                print(f"[!] Suspicious (line {line_number}, keyword: {word}): {line.strip()}")
                break
