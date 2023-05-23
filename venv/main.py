import virustotal3.core as core
from dotenv import load_dotenv
import os
import json
import sqlite3
def create_database():
    #stworzenie bazy danych jeśli jej jeszcze nie ma
    #zwraca połączenie do bazy
    if not os.path.isfile("venv/database.db"):
        conn = sqlite3.connect("venv/database.db")
        cursor = conn.cursor()
        #tutaj trzeba ogarnąć jakie konkretnie dane chcemy zapisać
        cursor.execute(
            """CREATE TABLE reputation(
            ip_addr TEXT,
            reputation TEXT
            )
            """
        )
        conn.commit()
        return conn
    else:
        return sqlite3.connect("database.db")



def read_log():
    #odczytanie adresów z logu
    #jak coś to te logi są tak zrobione że każda linia jest osobnym jsonem
    #zwraca listę ze wszystkimi adresami
    with open("venv/cowrie.json", "r") as log:
        all_addreses = set()
        for i in log.readlines():
            event_data = json.loads(i)
            if event_data["eventid"]=="cowrie.session.connect":
                ip_addr = event_data["src_ip"]
                all_addreses.add(ip_addr)
            
        return all_addreses
    
 
def save_ip(ip_data, conn):
    #zapis ip do bazy, tutaj też zależy co jakie pola będziemy mieć w bazie 
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reputation(ip_addr, reputation) VALUES(?,?)", (ip_data["src_ip"], ip_data["reputation"]))
    conn.commit()

#def check_ip(analyser, ip, conn):
#    #sprawdzenie reputacji ip
#    cursor = conn.cursor()
#    cursor.execute("SELECT reputation FROM reputation WHERE ip_addr==?", (ip,))
#    ip_data = cursor.fetchone()
#    if len(ip_data)==0:
#        #jeśli nie ma w bazie to sprawdza virustotal i dodaje do bazy
#        ip_reputation = analyser.info_ip(ip)
#        save_ip(ip_reputation, conn)
#        return ip_reputation
#    else:
#        #jeśli jest w bazie to zwraca to co zapiszemy
#        return ip_data


if __name__=="__main__":
    load_dotenv()
    key = os.getenv("API_KEY")
    ip_analyser = core.IP(api_key = key)
    addresses = read_log()
    with open("results.json", "a") as res:
        for ip in addresses:
            result = ip_analyser.info_ip(ip)
            res.write(result + "\n")
