#!/usr/bin/python3

# Import necessary modules
import json
import ipaddress
import nmap


# Function to validate an IP address
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# Function to validate scan type (1, 2, or 3)
def validate_scan_type(scan_type):
    return scan_type in ['1', '2', '3']


# Function to perform NMAP scan based on user input
def perform_scan(ip_address, scan_type):
    scanner = nmap.PortScanner()
    try:
        # Perform different types of scans based on user choice
        if scan_type == '1':
            result = scanner.scan(ip_address, arguments='-v -sS')  # SYN ACK scan
        elif scan_type == '2':
            result = scanner.scan(ip_address, arguments='-v -sU')  # UDP scan
        elif scan_type == '3':
            result = scanner.scan(ip_address, arguments='-v -sS -sV -sC -A -O')  # Comprehensive scan
        else:
            return "Invalid scan type. Please select a valid option."

        return result

    except Exception as e:
        return f"An error occurred: {e}"


# Function to save scan results to a JSON file
def save_to_json(scan_result):
    try:
        with open('scan_results.json', 'w') as json_file:
            json.dump(scan_result, json_file, indent=4)
        print("Scan results saved to 'scan_results.json'.")
    except Exception as e:
        print(f"Failed to save scan results: {e}")


# Main function to handle user input and execute the scan
def main():
    # ASCII art of Spider-Man
    print(r'''
                                 .-"""-.    __                         
                            /       \.-"  "-.                      
                         __:  :\     ;       `.                    
                  _._.-""  :  ; `.   :   _     \                   
                .'   "-.  "   :   \ /;    \    .^.              .-,
    .-".       :        `.     \_.' \'   .'; .'   `.            `dP
 ,-"    \      ;\         \  '.     /". /  :/       `.      __ dP_,
 :    '. \_    ; `.  __.   ;_  `-._/   Y    \         `.   ( dP".';
 ;      \  `.  :   "-._    ; ""-./      ;    "-._       `--dP .'  ;
:    .--.;   \  ;      l   '.    `.     ;        ""--.   dP  /   / 
;   /    :    \/       ;\  . "-.   \___/            __\dP .-"_.-"  
:  /     L_    \`.    :  "-.J   "-._/  ""-._       ( dP\ /   /     
; :      ; \    `.`.  ;     /"+.     ""-.   ""--.._dP-, `._."      
 \;     :   \     `.`-'   _/ /  "-.___   "         \`-'            
  `.    ;    \      `._.-"  (     ("--..__..---g,   \              
    `. :      ;             /\  .-"\       ,-dP ;    ;             
      \;   .-';    _   _.--"  \/    `._,-.-dP-' |    ;             
       :     :---"" """        `.     _:'.`.\   :    ;\            
        \  , :              bug  "-. (,j\ ` /   ;\(// \\           
         `:   \                     "dP__.-"    '-\\   \;          
           \   :                .--dP,             \;              
            `--'                `dP`-'                             
                              .-j                                  
                              `-:_                                 
                                 \)                                
                                  `--'
        ''')

    print("Welcome, this is an NMAP automation tool")
    print("---------------------------------------")

    # Get user input for IP address
    ip_address = input("Enter the IP address you want to scan: ")
    if not validate_ip(ip_address):
        print("Invalid IP address. Please enter a valid IP.")
        return

    # Get user input for scan type
    scan_type = input("""\nPlease enter the type of scan you want to run
                    1) SYN ACK scan
                    2) UDP Scan
                    3) Comprehensive Scan\n""")
    if not validate_scan_type(scan_type):
        print("Invalid scan type. Please enter a valid option.")
        return

    print(f"Scanning {ip_address}...")
    scan_result = perform_scan(ip_address, scan_type)
    print("Scan completed.")
    print(scan_result)

    # Save the scan results to a JSON file

