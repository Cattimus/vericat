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
			self.output_data += f"{hashes[l] :>7}: "
			return hashes[l]
		
		self.output_data += f"Unable to detect hashing algorithm based on input: {hash}\n"
		return None

	#TODO - write this to output instead of to stdout directly
	#check hash for a single algorithm
	def check_hash(self, path, hash):
		algo = self.identify_hash(hash)
		if algo == None:
			return False

		#reference hash is a known good hash that has been computed by our program
		reference_hash = self.gen_hash(path, algo)
		
		if reference_hash == hash:
			self.output_data += f"MATCH [{reference_hash}]\n"
		else:
			self.output_data += f"MISMATCH [{hash}]\n"
			self.output_data += f"{'EXPECTED ' :>18}" + f"[{reference_hash}]\n"

	#check all hashes from a file
	#by default, it will get the name of the file from the hash file on disk
	#can also optionally accept a filepath if the hash file is in another directory
	def check_hashes(self, hash_path, file_path=None):
		hash_data = None

		if file_path != None:
			#this is written to stdout to display immediately
			print(f"Checking hashes for file: {file_path}...")

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

				print(f"Checking hashes for file: {file_path}...")
			
			#check hash
			hash = info[0]
			self.check_hash(file_path, hash)
		return

	#TODO - Handle files that don't exist gracefully
	#hash file from path
	def gen_hash(self, path, algo):
		if not algo in hashlib.algorithms_available:
			print("Hashing algorithm is not supported.", file=sys.stderr)
			return None
		
		handle = open(path, "rb")
		hash = hashlib.file_digest(handle, algo).hexdigest()
		handle.close()
		return hash
				
	def gen_hashes(self, path=None):
		#default to using input_path unless specified
		if path == None:
			path = self.input_path

		self.output_data = ""
		print(f"Generating hashes for file: {path}...")

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
				final_path = final_path[i+1:]

			#list output with proper formatting
			if self.file_format:
				self.output_data += f"{hash} {final_path}\n"
			else:
				self.output_data += f"{algo}: {hash}\n"

	#write output to user (or file if requested)
	def write_output(self):
		if self.output_path != "" and self.output_data != "":
			f = open(self.output_path, "w")
			f.write(self.output_data)
			f.close()
			print(f"Output written to {self.output_path}\n")
		else:
			print(self.output_data)

		self.output_data = ""


cat = vericat()

cat.input_path = "vericat.py"
cat.output_path = "test.cat"
cat.file_format = True
cat.gen_hashes()
cat.write_output()
cat.output_path = ""
cat.check_hashes("test.cat")
cat.write_output()