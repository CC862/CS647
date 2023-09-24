from subprocess import PIPE, Popen
import subprocess
import os
import argparse


class TestCase():

	def __init__(self, plaintext, shiftValue, ciphertext, pointValue=1):

		self.plaintext = plaintext
		self.shiftValue = shiftValue
		self.ciphertext = ciphertext
		self.pointValue = pointValue

	def test(self, ciphertext):
		return ciphertext == self.ciphertext


def log(msg, file=None):
	print(msg, end='')
	if file:
		file.write(msg)



def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser()
    
    # Positional arguments
    parser.add_argument("source_code_file", nargs=1, help="The path to the .s file.")
   
    return parser 

def test_program(program_name, test_case, score_file):


	try:

		log("\n==================== Test Case ====================\n\n", score_file)


		# Interact with program
		p = Popen([program_name], stdin=PIPE, stderr=PIPE, stdout=PIPE, encoding='UTF8')

		p.stdin.write(test_case.plaintext + "\n")
		p.stdin.flush()
		p.stdout.readline()

		p.stdin.write(test_case.shiftValue + "\n")
		p.stdin.flush()
		p.stdout.readline()

		ciphertext = p.stdout.readline().strip()
		if ciphertext[0] == '\0':
			ciphertext = ciphertext[1:]
		p.stdin.close()
		p.stdout.close()

		score = 0
		log("\tProgram output:    " + ciphertext + "\n", score_file)
		log("\tExpected output:   " + test_case.ciphertext + "\n", score_file)


		log("\n\tOutput in hex:     " + " ".join("{:02x}".format(ord(c)) for c in ciphertext))
		log("\n\tExpected hex:      " + " ".join("{:02x}".format(ord(c)) for c in ciphertext))

		if test_case.test(ciphertext):
			score =  test_case.pointValue
			log("\n\n\tResult:            Passed!", score_file)
			log("\n\tPoints:            " + str(test_case.pointValue) + "/" + str(test_case.pointValue), score_file)
		else:
			log("\n\n\tResult:            Failed.", score_file)
			log("\n\tPoints:            0/" + str(test_case.pointValue), score_file)

		log("\n")


		return score
	except UnicodeDecodeError as e:
		log("!! ERROR !!\n\n", score_file)
		log("Unicode decode error occured for this test case with plaintext: " + test_case.ciphertext + "\nPlease manually review your output.\n", score_file)
		return 0



def main():

	args = build_parser().parse_args()

	source_code_file = args.source_code_file[0]


	if source_code_file[-2:] != '.s':
		print("Input to the program should be the source code. i.e. the caesar.s file.")
		exit(1)

	score_file = open("test_report.txt", 'w')

	log("==================== Program Build ====================\n", score_file)
	score = 0

	log("\nAssembly: ", score_file)

	r = subprocess.run(['/usr/bin/as', '--32', '-g', '-o', 'caesar.o', source_code_file], stderr=PIPE)
	if r.returncode != 0:
		err_msg = "Failed. No test cases were run due to build failure.\n" + r.stderr.decode()
		log(err_msg, score_file)
		exit(1)

	log("Passed!", score_file)


	log("\nLinker: ", score_file)

	r = subprocess.run(['/usr/bin/ld', '-m', 'elf_i386', '-o', 'caesar', 'caesar.o'], stderr=PIPE)
	if r.returncode != 0:
		err_msg = "Failed. No test cases were run due to build failure.\n" + r.stderr.decode()
		log(err_msg, score_file)
		exit(1)

	log("Passed!\n", score_file)

	test_cases = [

		TestCase(plaintext='hello world',
				 shiftValue='41',
				 ciphertext='wtaad ldgas',
				 pointValue=25),

		TestCase(plaintext='HERE COME BUFFER OVERFLOWS',
				 shiftValue='23',
				 ciphertext='EBOB ZLJB YRCCBO LSBOCILTP',
				 pointValue=25),

		TestCase(plaintext='I can’t carry it for you, but I can carry you.',
				 shiftValue='193',
				 ciphertext='T nly’e nlccj te qzc jzf, mfe T nly nlccj jzf.',
				 pointValue=25),

		TestCase(plaintext='S3cuReP@ssW0rd?',
				 shiftValue='951',
				 ciphertext='H3rjGtE@hhL0gs?',
				 pointValue=25)
	]

	exe = os.path.abspath("./caesar")

	for t in test_cases:
		score += test_program(exe, t, score_file)

	log("\n\nTotal Score: " + str(score) + "/100\n", score_file)
	score_file.close()


if __name__ == '__main__':
	main()