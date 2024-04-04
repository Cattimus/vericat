import hashlib
import sys
import re

#EDGE CASE - hashes in hashfile are for different files

#dictionary of hashing algorithms and their expected lengths
hashes = {32: "md5", 40: "sha1", 64: "sha256", 96: "sha384", 128: "sha512"}

class vericat:
	#pattern match for hashes in file
	pattern = r"([0-9a-fA-F]+) +(\S+)"

	#for -i(nput file) option
	input_path = ""
	input_filename = ""

	#for --algo=md5,sha256,sha... option
	algo_list = ["md5", "sha1", "sha256", "sha384", "sha512"]

	#for -o(utput) option
	output_path = ""
	output_filename = ""

	#for -f (file format) option
	file_format = False

	#attempt to identify hashing algorithm by length of hash
	def identify_hash(self, hash):
		l = len(hash)
		if l in hashes:
			print("Detected hashing algorithm: ", hashes[l], "[", hash, "]")
			return hashes[l]
		
		print("Unable to detect hashing algorithm based on input", file=sys.stderr)
		return None

	#check hash for a single algorithm
	def check_hash(self, data, hash):
		algo = self.identify_hash(hash)
		if algo == None:
			return False

		reference_hash = self.gen_hash(data, algo)
		
		if reference_hash == hash:
			print("Match.")
		else:
			print("MISMATCH: ", reference_hash)

	#check all hashes from a file
	#by default, it will get the name of the file from the hash file on disk
	#can also optionally accept a filepath if the hash file is in another directory
	def check_hashes(self, hash_path, file_path=None):
		file_data = None
		hash_data = None

		#standardize path to *nix
		hash_path = hash_path.replace("\\", "/")

		#get file binary data from provided path
		if file_path != None:
			f = open(file_path, "rb")
			file_data = f.read()
			f.close()

		#get list of hashes from hashfile
		f = open(hash_path, "r")
		hash_data = f.read()
		f.close()

		hashes = {}

		#read data from all lines of the hashfile
		for line in hash_data.split("\n"):
			info = re.search(self.pattern, line)

			#stop loop if we hit a line we can't parse
	 		#this avoids reading massive binary files by accident
			if info == None:
				break
			info = info.groups()

			#read file data so we can check hashes in realtime
			if file_path == None:
				#construct new file path from base path
				end_index = hash_path.rfind("/")+1
				base_path = ""
				if end_index != -1:
					base_path = hash_path[:end_index]
				file_path = base_path + info[1]

				#read data from file
				f = open(file_path, "rb")
				file_data = f.read()
				f.close()
			
			#check hash
			hash = info[0]
			self.check_hash(file_data, hash)
		
		return

	#gen hash for single algorithm
	def gen_hash(self, data, algo):
		hash = None

		#we don't want too many hashes, so we will limit to the most common algorithms
		match algo:
			case "md5":
				hash = hashlib.md5
			case "sha1":
				hash = hashlib.sha1
			case "sha256":
				hash = hashlib.sha256
			case "sha384":
				hash = hashlib.sha384
			case "sha512":
				hash = hashlib.sha512

		#if the hash wasn't found
		if hash == None:
			return None
		
		#return hash as hex digest
		else:
			return hash(data).hexdigest()
				

	def gen_hashes(self, data):
		output = ""

		#iterate through the selected algorithms
		for algo in self.algo_list:

			#generate hash for the algorithm
			hash = self.gen_hash(data, algo)

			#list output with proper formatting
			if self.file_format:
				output += hash + " " + self.input_filename + "\n"
			else:
				output += algo + ": " + hash + "\n"
		
		#we remove the last newline off the file to not append an empty line
		return output

cat = vericat()
'''
cat.input_path = "test.cat"
cat.input_filename = "test.cat"

cat.file_format = True
cat.output_path = "test2.cat"
cat.output_filename = "test2.cat"

#read data from file
f = open(cat.input_path, "rb")
data = f.read()
f.close()


#output to file if requested
if cat.output_path != "":
	f = open(cat.output_path, "w")
	f.write(output)
	f.close()
	print("Output written to " + cat.output_path)
else:
	print(output)
	'''