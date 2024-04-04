import hashlib
import sys
import re

#EDGE CASE - hashes in hashfile are for different files

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

	#for -i(nput file) option
	input_path = ""

	#for --algo=md5,sha256,sha... option
	algo_list = ["md5", "sha1", "sha256", "sha384", "sha512"]

	#for -o(utput) option
	output_path = ""
	output_filename = ""

	output_data = ""

	#for -f (file format) option
	file_format = False
	
	#for -t (truncate path) option
	truncate_path = False

	#attempt to identify hashing algorithm by length of hash
	def identify_hash(self, hash):
		l = len(hash)
		if l in hashes:
			print("Detected algorithm from hash: " + hashes[l] + " [" + hash + "]")
			return hashes[l]
		
		print("Unable to detect hashing algorithm based on input: [", hash, "]", file=sys.stderr)
		return None

	#check hash for a single algorithm
	def check_hash(self, path, hash):
		algo = self.identify_hash(hash)
		if algo == None:
			return False

		#reference hash is a known good hash that has been computed by our program
		reference_hash = self.gen_hash(path, algo)
		
		if reference_hash == hash:
			print("Hashes match.")
		else:
			print("HASH MISMATCH: ", reference_hash)

	#check all hashes from a file
	#by default, it will get the name of the file from the hash file on disk
	#can also optionally accept a filepath if the hash file is in another directory
	def check_hashes(self, hash_path, file_path=None):
		hash_data = None

		if file_path != None:
			print("Checking hashes for file: " + file_path + "...\n")

		#standardize path to *nix
		hash_path = hash_path.replace("\\", "/")

		#TODO - Handle files that don't exist gracefully
		#get list of hashes from hashfile
		f = open(hash_path, "r")
		hash_data = f.read()
		f.close()

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

				print("Checking hashes for file: " + file_path + "...\n")
			
			#check hash
			hash = info[0]
			self.check_hash(file_path, hash)
		return

	#TODO - Handle files that don't exist gracefully
	#hash file from path
	def gen_hash(self, path, algo):
		if not algo in hashlib.algorithms_available:
			print("Hashing algorithm is not supported.")
			return None
		
		handle = open(path, "rb")
		hash = hashlib.file_digest(handle, algo).hexdigest()
		handle.close()
		return hash
				
	def gen_hashes(self, path):
		self.output_data = ""
		print("Generating hashes for file: " + path + "...\n")

		#iterate through the selected algorithms
		for algo in self.algo_list:

			#generate hash for the algorithm
			hash = self.gen_hash(path, algo)

			#truncate the inner path of file
			final_path = path
			if self.truncate_path:
				i = final_path.rfind("/")
				if i == -1:
					i = final_path.rfind("\\")
				final_path = final_path[i:]

			#list output with proper formatting
			if self.file_format:
				self.output_data += hash + " " + path + "\n"
			else:
				self.output_data += algo + ": " + hash + "\n"

	#write output to user (or file if requested)
	def write_output(self):
		if self.output_path != "" and self.output_data != "":
			f = open(self.output_path, "w")
			f.write(self.output_data)
			f.close()
			print("Output written to ", self.output_path)
		else:
			print(self.output_data)


cat = vericat()

'''
cat.input_path = "test.cat"
cat.input_filename = "test.cat"

cat.file_format = True
cat.output_path = "test2.cat"
cat.output_filename = "test2.cat"

#read data from file
f = open(cat.input_path, "rb")

cat.gen_hashes(f)
f.close()
cat.write_output()
'''

cat.check_hashes("test.cat")