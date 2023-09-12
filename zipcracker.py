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
	with open(dictionary, 'r') as f:
		print("[?] Cracking ZIP file: "+ zipfilename )
		for line in f.readlines():
			password = line.strip('\n')
			try: 
				if extract_zip(zip_file, password):
					zip_file.extractall(pwd=password)
			except:
				pass
	print("\033[31m[+] Password: "+ password)
	print(f"\033[32m[+] Decompress with command: unzip -P '{password}' {zipfilename}")
	print("\033[36")
	exit()

if __name__ == '__main__':
	main()
