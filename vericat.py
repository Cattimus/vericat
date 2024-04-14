import hashlib
import sys
import re

#TODO - make truncate_path work again

#dictionary of hashing algorithms and their expected lengths
hash_lengths = {
	32: "md5",
	40: "sha1",
	64: "sha256",
	96: "sha384",
	128: "sha512"
}

#list of algorithms to generate
accepted_algos = ["md5", "sha1", "sha256", "sha384", "sha512"]

#attempt to identify hashing algorithm by length of hash
def identify_hash(hash):
	l = len(hash)
	if l in hash_lengths:
		return hash_lengths[l]
	
	return "ERROR [Unidentifiable hash]"

#regex to extract data from hashfiles
hashfile_pattern = re.compile(r"([0-9a-fA-F]+) +(\S+)")

class output:
	path = None

	#true: algo: hash
	#false: hash filename
	file_format = False
	manual_format = False

	#flag for the output format
	check = False

	#add only the filename in output file
	truncate_path = True

	#generic write
	def write(self, file):
		#do not print file results if the file cannot be found
		if file.err:
			print()
			return

		#choose which output style to write based on file properties
		if self.check:
			self.write_hash_results(file)
		else:
			self.write_reference_hashes(file)

	#print the results of hash checking
	def write_hash_results(self, file):
		output = ""
		for hash in file.hashes:
			algo = identify_hash(hash)
			output += f"{algo :>7}: "
			if not hash in file.results.keys():
				output += f"Algorithm not supported or not enabled\n"
			else:
				if file.results[hash]:
					output += f"MATCH [{file.reference_hashes[algo].hexdigest()}]\n"
				else:
					output += f"MISMATCH [{hash}]\n"
					output += f"{'EXPECTED ' :>18}" + f"[{file.reference_hashes[algo].hexdigest()}]\n"
		
		if self.path != None:
			try:
				f = open(self.path, "w")
				f.write(output)
				f.close()
				print(f"Output written to file: {self.path}.")
			except Exception as e:
				print(f"Error processing output file: {e}", file=sys.stderr)
		else:
				print(output)

	#write reference hashes to stdout or file
	def write_reference_hashes(self, file):
		#assemble output
		output = ""
		for algo in file.reference_hashes:
			if self.file_format:
				output += f"{file.reference_hashes[algo].hexdigest()} {file.path}\n"
			else:
				output += f"{algo:>7}: {file.reference_hashes[algo].hexdigest()}\n"
		
		#write to file
		if self.path != None:
			try:
				f = open(self.path, "w")
				f.write(output)
				f.close()
				print(f"Output written to file: {self.path}.")
			except Exception as e:
				print(f"Error processing output file: {e}", file=sys.stderr)
		#print to terminal
		else:
			print(output)


class file:
	#for -g(en) option
	path = None

	#hashes generated from program
	reference_hashes = {}

	#results of hash checking
	results = {}

	#hashes passed from argument/other file
	hashes = []

	#flag for if an error has occured that should disable printing results
	err = False

	#with filename and list of hashes
	def __init__(self, filename: str, hashes: list = []):
		self.path = filename
		self.hashes = hashes
		
		self.results = {}
		self.hashes = []
		self.err = False

	def reset_reference(self):
		global accepted_algos

		self.reference_hashes = {
			"md5": hashlib.md5(),
			"sha1": hashlib.sha1(),
			"sha256": hashlib.sha256(),
			"sha384": hashlib.sha384(),
			"sha512": hashlib.sha512()
		}

		#do some python magic to only include algorithms from the input list
		l = {key:value for (key,value) in self.reference_hashes.items() if key in accepted_algos}
		self.reference_hashes = l

	#generic function to be run for each file
	def check(self):
		#reference hashes are initialized here to make sure the --algo flag works
		self.reset_reference()
		self.gen_hashes()
		self.check_hashes()
	
	#generate a list of hashes for a file	
	def gen_hashes(self):
		print(f"Generating reference hashes for file: {self.path}...")

		try:
			#read file in 4kb chunks and update each hash
			file = open(self.path, "rb")
			while True:
				data = file.read(4096)

				#exit condition
				if not data:
					break

				#update each algorithm in chunks
				for algo in self.reference_hashes:
					self.reference_hashes[algo].update(data)
			file.close()
		except Exception as e:
			print(f"Error processing reference hashes: {e}", file=sys.stderr)
			self.reference_hashes = {}
			self.err = True
			return

	#This should be called after load_hashfile.
	def check_hashes(self):
		#prevent this from running if there's no hashes to check
		if len(self.hashes) == 0:
			return
		
		#prevent this from running if reference hashes haven't been generated
		if len(self.reference_hashes.keys()) == 0:
			self.results = {}
			return

		#inform user of the file we're processing
		print(f"Checking hashes for file: {self.path}...")

		#iterate through the list of hashes from the file
		for hash in self.hashes:
			algo = identify_hash(hash)
			if algo in self.reference_hashes:
				self.results[hash] = self.reference_hashes[algo].hexdigest() == hash.lower()

class vericat:
	files = {}
	out = output()
	arg_hashes = []

	#add hashes to the first file in the list
	def add_hashes(self):
		for file in self.files.values():
			file.hashes.extend(self.arg_hashes)

	#perform hash checking for each file object
	def perform_checks(self):
		self.add_hashes()
		for file in self.files.values():
			file.check()
			self.out.write(file)

	#check all hashes from a file
	def load_hashfile(self, path):
		hash_data = None

		#standardize path to *nix
		path = path.replace("\\", "/")

		#get list of hashes from hashfile
		try:
			f = open(path, "r")
			hash_data = f.read()
			f.close()
		except Exception as e:
			print(f"Error processing hashfile: {e}", file=sys.stderr)
			sys.exit(-1)

		#read data from all lines of the hashfile
		for line in hash_data.split("\n"):
			info = hashfile_pattern.search(line)

			#stop loop if we hit a line we can't parse
	 		#this avoids reading massive binary files by accident
			if info == None:
				break
			info = info.groups()

			#extract filename
			file_path = ""

			#get the current working directory
			end_index = path.rfind("/")+1
			base_path = ""

			#construct new file path given filename and working directory
			if end_index != -1:
				base_path = path[:end_index]
			file_path = base_path + re.sub(r"[\<\>\|\?\*]+", "", info[1])

			#identify hash algorithm
			hash = info[0]

			#create new file object
			if not file_path in self.files.keys():
				self.files[file_path] = file(file_path)
				self.files[file_path].path = file_path

			self.files[file_path].hashes.append(hash)
		return
	
def main():
	cat = vericat()

	#pattern to check if something is a hash or not
	hash_pattern = re.compile(r'[0-9a-fA-F]+')

	#start handling command line arguments
	for i in range(1, len(sys.argv)):
		arg = sys.argv[i]

		#load hashes from file
		if arg == "-check" or arg == "-c":
			cat.out.check = True
			cat.load_hashfile(sys.argv[i+1])
			i += 1
			
		#generate hashes
		elif arg == "-gen" or arg == "-g":
			filename = sys.argv[i+1]
			cat.files[filename] = file(filename)
			i += 1

		#input file to check against hashes that are included
		elif arg == "-i":
			filename = sys.argv[i+1]
			cat.files[filename] = file(filename)
			cat.out.check = True
			i += 1

		#output file
		elif arg == "-output" or arg == "-o":
			output_filename = sys.argv[i+1]
			cat.out.path = output_filename
			cat.out.file_format = True
			i += 1

		#set file_format flag
		elif "-f=" in arg:
			cat.out.manual_format = True
			val = arg.split("=")[1]
			cat.out.file_format = val.lower() == "true"

		#select algorithm(s)
		elif "--algo=" in arg:
			global accepted_algos
			val = arg.split("=")[1]
			accepted_algos = val.split(",")

		#value is possibly a hash that is intended to be checked against
		else:
			match = hash_pattern.match(arg)
			if match != None and match.group() == arg:
				cat.arg_hashes.append(arg)

	#check hashes
	cat.perform_checks()

if __name__ == '__main__':
	main()