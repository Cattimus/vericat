import hashlib
import sys

class vericat:
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
		match len(hash):
			case 32:
				print("Detected hashing algorithm: md5")
				return "md5"
			case 40:
				print("Detected hashing algorithm: sha1")
				return "sha1"
			case 64:
				print("Detected hashing algorithm: sha256")
				return "sha256"
			case 96:
				print("Detected hashing algorithm: sha384")
				return "sha384"
			case 128:
				print("Detected hashing algorithm: sha512")
				return "sha512"
		
		print("Unable to detect hashing algorithm based on input", file=sys.stderr)
		return None

	#check hash for a single algorithm
	def check_hash(self, data, hash):
		#attempt to identify hash by string
		#this will need to be reworked later to return/display an error
		algo = self.identify_hash(hash)
		if algo == None:
			return False

		reference_hash = self.gen_hash(data, algo)
		
		if reference_hash == hash:
			return True
		else:
			return False

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
		
		return output

cat = vericat()
cat.input_path = "test.cat"
cat.input_filename = "test.cat"

cat.file_format = True
cat.output_path = "test2.cat"
cat.output_filename = "test2.cat"

#read data from file
f = open(cat.input_path, "rb")
data = f.read()
f.close()

output = cat.gen_hashes(data)

is_valid = cat.check_hash(data, "0d44314a33b8b4fed90909b5e8d501351669fe26d59c9cad7829ebadc12572c0bb910da5bcecc79ed2350bf9bdb66b8da079c66ff2fbc993a32461f1ed542821")
if is_valid:
	print("Hashes match.")
else:
	print("Hashes do not match.")

#output to file if requested
if cat.output_path != "":
	f = open(cat.output_path, "w")
	f.write(output)
	f.close()
	print("Output written to " + cat.output_path)
else:
	print(output)