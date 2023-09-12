#!/usr/bin/env python3
import zipfile
import argparse



def main():
    parser = argparse.ArgumentParser(description="Zipfile password cracker using a brute-force dictionary attack.")
    parser.add_argument("zipfile", help="The zip file to be cracked")
    parser.add_argument("wordlist", help="The wordlist file")
    args = parser.parse_args()
    zipfilename = args.zipfile
    dictionary = args.wordlist
    
    password = None
    zip_file = zipfile.ZipFile(zipfilename)
    with open(dictionary, 'r', encoding='latin-1') as f:  # Specify the correct encoding (e.g., 'latin-1')
        print("[?] Cracking ZIP file: "+ zipfilename )
        for line in f.readlines():
            password = line.strip('\n')
            try: 
                zip_file.extractall(pwd=password)
                password = 'Password found: %s' % password
                break
            except:
                pass
    print("\033[31m[+] Password: "+ password)
    print(f"\033[32m[+] Decompress with command: unzip -P '{password}' {zipfilename}")
    print("\033[36")
    exit()

if __name__ == '__main__':
	main()
