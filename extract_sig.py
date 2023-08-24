from pdfreader import PDFDocument

filename = r"input.pdf"
fd = open(filename, "rb")
doc = PDFDocument(fd)
pdf_content = str(fd.read())
nr_of_obj = 0
nr_of_signatures = 0
signature_names = [] #in my case - emails
s_trailer = 'trailer'
s_startxref = 'startxref'

# +/- 2 at the end for new line character before and after the trailer
#Finding where last trailer of the document starts and ends

last_trailer_start = pdf_content.rfind(s_trailer)+len(s_trailer)+2
last_trailer_end = pdf_content.rfind(s_startxref)-2

#Putting the trailer together
trailer = ""
for i in range(last_trailer_start, last_trailer_end):
    trailer += pdf_content[i]

#Split the trailer attributes. Locate and read Size
trailer = trailer.split('/')
for attribute in trailer:
    if attribute.find('Size') >= 0:
        nr_of_obj = int(attribute.replace('Size','').strip())
        break

#Use the size to loop through objects. All the objects will not exist and not all will have Types. Hence try-catch.
for i in range(1, nr_of_obj):    
    try:
        raw_obj = doc.locate_object(i,0)
        obj = doc.build(raw_obj)
        if obj.Type == 'Sig':
            nr_of_signatures +=1
            print('Found a signature object', obj)
            signature_bytes = bytes.fromhex(obj['Contents'])
            # Write the signature to a DER file
            with open('signature.der', 'wb') as f:
                f.write(signature_bytes)
        else:
            if obj.Type == 'Page':
                print('Found a page object', obj)
    except:
        continue
print(nr_of_signatures)