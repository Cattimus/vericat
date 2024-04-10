import hashlib
import sys
import re

#EDGE CASE - hashes in hashfile are for different files

#dictionary of hashing algorithms and their expected lengths
hash_lengths = {
	32: "md5",
	40: "sha1",
	64: "sha256",
	96: "sha384",
	128: "sha512"
}

#attempt to identify hashing algorithm by length of hash
def identify_hash(hash):
	l = len(hash)
	if l in hash_lengths:
		return hash_lengths[l]
	
	print(f"Unable to detect hashing algorithm based on input: {hash}\n", file=sys.stderr)
	return None

#regex to extract data from hashfiles
hashfile_pattern = re.compile(r"([0-9a-fA-F]+) +(\S+)")

class output:
	path = None

	#true: algo: hash
	#false: hash filename
	file_format = False
	manual_format = False

	#add only the filename in output file
	truncate_path = True

	#print the results of hash checking
	def write_hash_results(self, file):
		output = ""
		for hash in file.results:
			algo = identify_hash(hash)
			output += f"{algo :>7}: "
			if file.results[hash]:
				output += f"MATCH [{file.reference_hashes[algo].hexdigest()}]\n"
			else:
				output += f"MISMATCH [{hash}]\n"
				output += f"{'EXPECTED ' :>18}" + f"[{file.reference_hashes[hash].hexdigest()}]\n"
		
		if self.path != None:
			try:
				f = open(self.path, "w")
				f.write(output)
				f.close()
				print(f"Output written to file: {self.path}.")
			except Exception as e:
				print(f"Error processing output file: {e}", file=sys.stderr)
		else:
				print(output, end="")

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
			print(output, end="")


class file:
	#for -g(en) option
	path = None

	#for -c(heck) option
	hashfile = None

	#hashes generated from program
	reference_hashes = {
		"md5": hashlib.md5(),
		"sha1": hashlib.sha1(),
		"sha256": hashlib.sha256(),
		"sha384": hashlib.sha384(),
		"sha512": hashlib.sha512()
	}

	#results of hash checking
	results = {}

	#hashes passed from argument/other file
	hashes = []

	def reset_reference(self):
		self.reference_hashes = {
			"md5": hashlib.md5(),
			"sha1": hashlib.sha1(),
			"sha256": hashlib.sha256(),
			"sha384": hashlib.sha384(),
			"sha512": hashlib.sha512()
		}
	
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
			sys.exit(-1)

	#This should be called after load_hashfile.
	def check_hashes(self):
		#make sure the list of hashes is up to date for the target file
		self.gen_hashes()

		#inform user of the file we're processing
		print(f"Checking hashes for file: {self.path}...")

		#iterate through the list of hashes from the file
		for hash in self.hashes:
			algo = identify_hash(hash)
			if algo in self.reference_hashes:
				self.results[hash] = self.reference_hashes[algo].hexdigest() == hash

class vericat:
	files = {}

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
			file_path = base_path + info[1]

			#identify hash algorithm
			hash = info[0]

			#create new file object
			if not file_path in self.files:
				self.files[file_path] = file()
				self.files[file_path].path = file_path
			
			self.files[file_path].arg_hashes.append(hash)
		return
	
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
		elif "--algo=" in arg:
			val = arg.split("=")[1]
			selected = val.split(",")

			#do some python magic to only include algorithms from the input list
			l = {key:value for (key,value) in cat.reference_hashes.items() if key in selected}
			cat.reference_hashes = l

		#value is possibly a hash that is intended to be checked against
		else:
			match = hash_pattern.match(arg)
			if match != None and match.group() == arg:
				cat.arg_hashes.append(arg)

	if cat.target_path != None and cat.hashfile_path != None:
		cat.load_hashfile()
		cat.check_hashes()
		cat.write_hash_results()

	#generate hashes for file
	elif cat.target_path != None:
		#automatically set file format to true for generating if an output file is set
		if cat.output_path != None and cat.manual_format == False:
			cat.file_format = True

		cat.gen_hashes()
		cat.write_reference_hashes()
	
	#check hashes for file
	elif cat.hashfile_path != None:

		#we're checking against hashes provided as arguments
		if len(cat.arg_hashes) > 0:
			#make sure to generate hashes before checking
			cat.target_path = cat.hashfile_path

			#add hashes to hashfile dict to make checking easy
			for hash in cat.arg_hashes:
				algo = cat.identify_hash(hash)
				cat.hashfile_data[algo] = hash

		#get hashes from hashfile
		else:
			cat.load_hashfile()

		#perform comparison
		cat.check_hashes()
		cat.write_hash_results()

if __name__ == '__main__':
	#main()
	f = file()
	f.path = "vericat.py"
	f.gen_hashes()

	o = output()
	o.write_reference_hashes(f)