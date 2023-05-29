import virustotal3.core as core
from dotenv import load_dotenv
import os
import json

def read_log():
    #odczytanie adresów z logu
    #jak coś to te logi są tak zrobione że każda linia jest osobnym jsonem
    #zwraca listę ze wszystkimi adresami
    cowriepath = input("Input log file path/name [output/cowrie.json]: ") or "output/cowrie.json"
    
    with open(cowriepath, "r") as log:
        all_addreses = set()
        for i in log.readlines():
            event_data = json.loads(i)
            if event_data["eventid"]=="cowrie.session.connect":
                ip_addr = event_data["src_ip"]
                all_addreses.add(ip_addr)
        print(f"Log file {cowriepath} analysed")
        return all_addreses

if __name__=="__main__":
    load_dotenv()
    key = os.getenv("API_KEY")
    ip_analyser = core.IP(api_key = key)
    #addreses = read_log()
    addressespath = input("Input address file path/name [source/addresses.txt]: ") or "source/addresses.txt"
    
    addresses = [line.strip() for line in open(addressespath, 'r')]
    print(f"Found {len(addresses)} unique IP addresses")
    
    result = []
    
    filepath = input("Input result file path/name [output/results.json]: ") or "output/results.json"
    
    
    print("Starting analysis...")
    for ip in addresses:
        print(f"Analysing IP: {ip}")
        analysis_result = ip_analyser.info_ip(ip)
        result.append(analysis_result)
    print("Analysis finished.")
    
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
        print(f"Results saved to {filepath}")