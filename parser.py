from collections import Counter

LOG_FILE = 'log_file.txt'

auth_events = []
process_events = []
alerts = []

def extract_value(line, key):
    if f"{key}" in line:
        return line.split(f"{key}=")[1].split()[0]
    return "N/A"
    

def parse_logs(log_file):
    try:
        with open(log_file, 'r') as file:

            for line in file:
                line = line.strip()


                if 'EventID=4625' in line :
                    event ={
                        'EventID': extract_value(line, 'EventID'),
                        'USER': extract_value(line, 'AccountName'),
                        'SourceIP': extract_value(line, 'SourceIP'),
                        'Status': "FAIL !!" }
                    auth_events.append(event)
                elif 'EventID=4624' in line :
                    event ={
                        'EventID': extract_value(line, 'EventID'),
                        'USER': extract_value(line, 'AccountName'),
                        'SourceIP': extract_value(line, 'SourceIP'),
                        'Status': "SUCCESS"}    
                    auth_events.append(event)

                elif 'EventID=4688' in line:
                    event = {
                        'EventID': extract_value(line, 'EventID'),
                        'USER': extract_value(line, 'AccountName'),
                        'ProcessName': extract_value(line, 'ProcessName')
                        }
                    process_events.append(event)
    except FileNotFoundError:
        print(f"Log file not found.")


def detect_brute_force(threshold=3):

    IP_COUNT = Counter()
    for event in auth_events:
        if event['Status'] == "FAIL !!":
            IP_COUNT[event['SourceIP']] += 1

    for ip, count in IP_COUNT.items():
        if count >= threshold:
            alerts.append({
                "AlertName":"Possible Brute Force !",
                "Severity":"Medium",
                "SourceIP":ip,
                "FailedAttempts":count,
                "Description":f"Detected {count} failed login attempts from IP {ip} indicating a possible brute force attack."
            })
def generate_report():
    print("Authentication Events:")
    for event in auth_events:
        print(event)
    print("\nProcess Creation Events:")
    for event in process_events:
        print(event)
    print("\nAlerts:")
    for alert in alerts:
        print(alert)
def main():
    parse_logs(LOG_FILE)
    detect_brute_force()
    generate_report()
if __name__ == "__main__":
    main()