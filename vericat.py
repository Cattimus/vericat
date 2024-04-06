import hashlib
import sys
import re

#EDGE CASE - hashes in hashfile are for different files

#TODO - clean up this stinky spaghetti mess I have created

#dictionary of hashing algorithms and their expected lengths
hashes = {
	32: "md5",
	40: "sha1",
	64: "sha256",
	96: "sha384",
	128: "sha512"
}

class vericat:
	#pattern match for hashes in file
	pattern = r"([0-9a-fA-F]+) +(\S+)"

	#for -g(en) option
	target_path = None

	#for -c(heck) option
	hashfile_path = None

	#for --algo=md5,sha256,sha... option
	reference_hashes = {
		"md5": hashlib.md5(),
		"sha1": hashlib.sha1(),
		"sha256": hashlib.sha256(),
		"sha384": hashlib.sha384(),
		"sha512": hashlib.sha512()
	}
	
	#Hashes that have been identified in a file
	hashfile_data = {}

	#for hashes
	arg_hashes = []

	#for -o(utput) option
	output_path = None
	output_data = ""

	#for -f=true/false (file format) option
	file_format = False
	manual_format = False
	
	#for -t (truncate path) option
	truncate_path = True

	#attempt to identify hashing algorithm by length of hash
	def identify_hash(self, hash):
		l = len(hash)
		if l in hashes:
			return hashes[l]
		
		print(f"Unable to detect hashing algorithm based on input: {hash}\n", file=sys.stderr)
		return None

	#check hash for a single algorithm
	def check_hash(self, hash):
		algo = self.identify_hash(hash)
		if algo == None:
			return False
		
		self.output_data += f"{algo :>7}: "

		#reference hash is a known good hash that has been computed by our program
		reference_hash = self.reference_hashes[algo].hexdigest()
		
		#TODO - move this into it's own function
		if reference_hash == hash:
			self.output_data += f"MATCH [{reference_hash}]\n"
		else:
			self.output_data += f"MISMATCH [{hash}]\n"
			self.output_data += f"{'EXPECTED ' :>18}" + f"[{reference_hash}]\n"

	#check all hashes from a file
	def load_hashfile(self):
		hash_data = None

		#standardize path to *nix
		self.hashfile_path = self.hashfile_path.replace("\\", "/")

		#get list of hashes from hashfile
		try:
			f = open(self.hashfile_path, "r")
			hash_data = f.read()
			f.close()
		except:
			print(f"Error opening file: {self.hashfile_path}", file=sys.stderr)
			return

		#read data from all lines of the hashfile
		for line in hash_data.split("\n"):
			info = re.search(self.pattern, line)

			#stop loop if we hit a line we can't parse
	 		#this avoids reading massive binary files by accident
			if info == None:
				break
			info = info.groups()

			#get the filename to check from the hashfile
			if self.target_path == None:
				#get the current working directory
				end_index = self.hashfile_path.rfind("/")+1
				base_path = ""

				#construct new file path given filename and working directory
				if end_index != -1:
					base_path = self.hashfile_path[:end_index]
				self.target_path = base_path + info[1]

			#identify hash algorithm
			hash = info[0]
			algo = self.identify_hash(hash)

			#add to our list of file hashes, we don't want any hashes that can't be identified
			if algo != None:
				self.hashfile_data[algo] = hash
		return
	
	#This should be called after load_hashfile.
	def check_hashes(self):
		#inform user of the file we're processing
		print(f"Checking hashes for file: {self.target_path}...")

		#make sure the list of hashes is up to date for the target file
		self.gen_hashes()

		#iterate through the list of hashes from the file
		for hash in self.hashfile_data:
			if hash in self.reference_hashes:
				self.check_hash(self.hashfile_data[hash])


	#generate a list of hashes for a file	
	def gen_hashes(self):
		self.output_data = ""
		print(f"Generating hashes for file: {self.target_path}...")

		#read file in 4kb chunks and update each hash
		file = open(self.target_path, "rb")
		while True:
			data = file.read(4096)

			#exit condition
			if not data:
				break

			#update each algorithm in chunks
			for algo in self.reference_hashes:
				self.reference_hashes[algo].update(data)
		file.close()

		#TODO - move this logic into it's own function
		for algo in self.reference_hashes:
			if self.file_format:
				self.output_data += f"{self.reference_hashes[algo].hexdigest()} {file.name}\n"
			else:
				self.output_data += f"{algo}: {self.reference_hashes[algo].hexdigest()}\n"

	#write output to user (or file if requested)
	def write_output(self):
		if self.output_path != None and self.output_data != "":
			f = open(self.output_path, "w")
			f.write(self.output_data)
			f.close()
			print(f"Output written to {self.output_path}\n")
		else:
			print(self.output_data)

		self.output_data = ""

def main():
	cat = vericat()

	#pattern to check if something is a hash or not
	hash_pattern = re.compile(r'[0-9a-fA-F]+')

	#start handling command line arguments
	for i in range(1, len(sys.argv)):
		arg = sys.argv[i]

		#check hashes
		if arg == "-check" or arg == "-c":
			cat.hashfile_path = sys.argv[i+1]
			i += 1
			
		#generate hashes
		elif arg == "-gen" or arg == "-g" or arg == "-i":
			cat.target_path = sys.argv[i+1]
			i += 1

		#output file
		elif arg == "-output" or arg == "-o":
			cat.output_path = sys.argv[i+1]
			i += 1

		#set file_format flag
		elif "-f=" in arg:
			cat.manual_format = True
			val = arg.split("=")[1]
			cat.file_format = val.lower() == "true"

		#select algorithm(s)
		#TODO - update this to work with the dictionary
		elif "--algo=" in arg:
			val = arg.split("=")[1]
			list = val.split(",")

			#do some python magic to only allow algorithms that are already in the default list
			l = [x for x in list if x in cat.reference_hashes]
			cat.reference_hashes = l

		#value is possibly a hash that is intended to be checked against
		else:
			match = hash_pattern.match(arg)
			if match != None and match.group() == arg:
				cat.arg_hashes.append(arg)

	if cat.target_path != None and cat.hashfile_path != None:
		cat.load_hashfile()
		cat.check_hashes()
		cat.write_output()

	#generate hashes for file
	elif cat.target_path != None:
		#automatically set file format to true for generating if an output file is set
		if cat.output_path != None and cat.manual_format == False:
			cat.file_format = True

		cat.gen_hashes()
		cat.write_output()
	
	#check hashes for file
	elif cat.hashfile_path != None:

		#we're checking against hashes provided as arguments
		if len(cat.arg_hashes) > 0:
			#inform user of the check
			print(f"Checking hashes for file {cat.hashfile_path}...")

			#make sure to generate hashes before checking
			cat.target_path = cat.hashfile_path
			cat.gen_hashes()

			#check each hash individually
			for hash in cat.arg_hashes:
				cat.check_hash(hash)
			cat.write_output()

		else:
			cat.load_hashfile()
			cat.check_hashes()
			cat.write_output()

if __name__ == '__main__':
	main()