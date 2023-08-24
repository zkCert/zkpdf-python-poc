import PyPDF2

def extract_signature_info(pdf_path):
    with open(pdf_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for i in range(len(reader.pages)):
            page = reader.pages[i]
            print("page", i)
            if page.get('/Annots'):
                annotations = page['/Annots']
                print("Found annotations on page", i)
                print(annotations)
                for annotation in annotations:
                    obj = annotation.get_object()
                    if obj.get('/Subtype') == '/Widget' and obj.get('/FT') == '/Sig':
                        print("Found signature on page", i)
                        # Further extraction can be done here



def print_annotations(pdf_path):
    with open(pdf_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for i, page in enumerate(reader.pages):
            annotations = page.get('/Annots')
            if annotations:
                print(f"Annotations on page {i + 1}:")
                for j, annotation in enumerate(annotations):
                    obj = annotation.get_object()
                    print(f"  Annotation {j + 1}:")
                    for key, value in obj.items():
                        print(f"    {key}: {value}")
            else:
                print(f"No annotations on page {i + 1}.")





pdf_path = "input.pdf"
print_annotations(pdf_path)

