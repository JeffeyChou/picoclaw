#!/usr/bin/env python3
import sys
import argparse
import fitz  # PyMuPDF

def parse_pdf(file_path):
    try:
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    except Exception as e:
        print(f"Error parsing PDF: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse PDF and output text")
    parser.add_argument("file", help="Path to PDF file")
    args = parser.parse_args()
    print(parse_pdf(args.file))
