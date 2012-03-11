import sys, os, getopt, struct

class get_bytes:

	def __init__(self):

		# c-types to format python module struct format strings
		self.types = { 	
			'char'   :   'b',
			'uchar'  :   'B',
			'short'  :   'h',
			'ushort' :   'H',
			'int'    :   'i',
			'uint'   :   'I',
			'long'   :   'l',
			'ulong'  :   'L',
			'llong'  :   'q',
			'ullong' :   'Q',
			'ptr'    :   'P' }

		self.kshf = 0xc0000000

        # get a null-terminated string from buf starting at ptr with max length max
	def get_string(self, buf, ptr, max=0):
	
		# make sure we don't unpack past the buffer under any circumstances;
		# in case the caller didn't supply a max string length
		if max == 0: 
			max = len(buf)

		
		string = ""
		done = False
		while not done and ptr < max:
			char = struct.unpack_from(self.types['char'], buf, ptr)[0]
			
			# stop on null, have a valid string
			if char == 0x0:
				done = True
			# else append the car we found on to the string
			else:
				string += chr(char)
				ptr += 1
                
		# we hit the max, and didn't find a string terminator - what we found
		# was not a valid string for our purposes
		if ptr == max:
			string = ""

		return string
        
	def kshf_to_phys(self, address):
		return address - self.kshf

	# return unpacked type from buf at offset
	def get_bytes(self, buf, offset, t):

		ltype = ""
						
		if t in self.types:
		  ltype = self.types[t]
		
		if t == "str":	
			return self.get_string(buf, offset)
			
		elif ltype != "":
			return struct.unpack_from(ltype, buf, offset )[0]
	
		else:
			
			return struct.unpack_from(t, buf, offset)
			


