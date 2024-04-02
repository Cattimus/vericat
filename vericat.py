import hashlib

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
				

	def gen_hashes(self):
		output = ""

		#get file data
		f = open(self.input_path, "rb")
		data = f.read()
		f.close()

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
cat.input_path = "vericat.py"
cat.input_filename = "vericat.py"

cat.file_format = True
cat.output_path = "test.cat"
cat.output_filename = "test.cat"

output = cat.gen_hashes()

#output to file if requested
if cat.output_path != "":
	f = open(cat.output_path, "w")
	f.write(output)
	f.close()
	print("Output written to " + cat.output_path)
else:
	print(output)