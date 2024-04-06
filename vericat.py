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
	input_path = None

	#for -c(heck) option
	hash_path = None

	#for --algo=md5,sha256,sha... option
	algo_list = ["md5", "sha1", "sha256", "sha384", "sha512"]

	#for hashes
	arg_hashes = []

	#for -o(utput) option
	output_path = None

	output_data = ""

	#for -f=true/false (file format) option
	file_format = False
	manual_format = False
	
	#for -t (truncate path) option
	truncate_path = False

	#attempt to identify hashing algorithm by length of hash
	def identify_hash(self, hash):
		l = len(hash)
		if l in hashes:
			return hashes[l]
		
		print(f"Unable to detect hashing algorithm based on input: {hash}\n", file=sys.stderr)
		return None

	#check hash for a single algorithm
	def check_hash(self, path, hash):
		algo = self.identify_hash(hash)
		if algo == None:
			return False
		
		self.output_data += f"{algo :>7}: "

		#reference hash is a known good hash that has been computed by our program
		reference_hash = self.gen_hash(path, algo)
		
		if reference_hash == hash:
			self.output_data += f"MATCH [{reference_hash}]\n"
		else:
			self.output_data += f"MISMATCH [{hash}]\n"
			self.output_data += f"{'EXPECTED ' :>18}" + f"[{reference_hash}]\n"

	#check all hashes from a file
	def check_hashes(self):
		hash_data = None

		#standardize path to *nix
		self.hash_path = self.hash_path.replace("\\", "/")

		#get list of hashes from hashfile
		try:
			f = open(self.hash_path, "r")
			hash_data = f.read()
			f.close()
		except:
			print(f"Error opening file: {self.hash_path}", file=sys.stderr)
			return None

		#read data from all lines of the hashfile
		for line in hash_data.split("\n"):
			info = re.search(self.pattern, line)

			#stop loop if we hit a line we can't parse
	 		#this avoids reading massive binary files by accident
			if info == None:
				break
			info = info.groups()

			#get the filename to check from the hashfile
			if self.input_path == None:
				#get the current working directory
				end_index = self.hash_path.rfind("/")+1
				base_path = ""

				#construct new file path given filename and working directory
				if end_index != -1:
					base_path = self.hash_path[:end_index]
				self.input_path = base_path + info[1]

			#inform user of the file we're processing
			print(f"Checking hashes for file: {self.input_path}...")
			
			#check hash
			hash = info[0]
			self.check_hash(self.input_path, hash)
		return

	#hash file from path
	def gen_hash(self, path, algo):
		if not algo in hashlib.algorithms_available:
			print("Hashing algorithm is not supported.", file=sys.stderr)
			return None
		
		try:
			handle = open(path, "rb")
			hash = hashlib.file_digest(handle, algo).hexdigest()
			handle.close()
			return hash
		except:
			print(f"Error opening file: {path}", file=sys.stderr)
			return None
				
	def gen_hashes(self):
		self.output_data = ""
		print(f"Generating hashes for file: {self.input_path}...")

		#iterate through the selected algorithms
		for algo in self.algo_list:

			#generate hash for the algorithm
			hash = self.gen_hash(self.input_path, algo)

			#give only the filename, remove the rest of the path
			final_path = self.input_path
			if self.truncate_path:
				i = final_path.rfind("/")
				if i == -1:
					i = final_path.rfind("\\")
				final_path = final_path[i+1:]

			#list output in either cmd style or file style
			if self.file_format:
				self.output_data += f"{hash} {final_path}\n"
			else:
				self.output_data += f"{algo}: {hash}\n"

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
			cat.hash_path = sys.argv[i+1]
			i += 1
			
		#generate hashes
		elif arg == "-gen" or arg == "-g" or arg == "-i":
			cat.input_path = sys.argv[i+1]
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
		elif "--algo=" in arg:
			val = arg.split("=")[1]
			list = val.split(",")

			#do some python magic to only allow algorithms that are already in the default list
			l = [x for x in list if x in cat.algo_list]
			cat.algo_list = l

		#value is a hash that is intended to be checked against
		elif hash_pattern.match(arg).group() == arg:
			cat.arg_hashes.append(arg)

	if cat.input_path != None and cat.hash_path != None:
		cat.check_hashes()
		cat.write_output()

	#generate hashes for file
	elif cat.input_path != None:
		#automatically set file format to true for generating if an output file is set
		if cat.output_path != None and cat.manual_format == False:
			cat.file_format = True

		cat.gen_hashes()
		cat.write_output()
	
	#check hashes for file
	elif cat.hash_path != None:

		#we're checking against hashes provided as arguments
		if len(cat.arg_hashes) > 0:
			print(f"Checking hashes for file {cat.hash_path}...")
			for hash in cat.arg_hashes:
				cat.check_hash(cat.hash_path, hash)

			cat.write_output()

		else:
			cat.check_hashes()
			cat.write_output()

if __name__ == '__main__':
	main()