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

	def gen_hashes(self):
		output = ""

		#get file data
		f = open(self.input_path, "rb")
		data = f.read()
		f.close()

		#iterate through the selected algorithms
		for algo in self.algo_list:
			hash = None

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
		
			#list an error if the algorithm is unsupported
			if hash == None:
				output += algo + ": " + "Unsupported"
				continue

			#list output with proper formatting
			if self.file_format:
				output += hash(data).hexdigest() + " " + self.input_filename + "\n"
			else:
				output += algo + ": " + hash(data).hexdigest() + "\n"
		
		return output

cat = vericat()
cat.input_path = "vericat.py"
cat.input_filename = "vericat.py"

output = cat.gen_hashes()
print(output)