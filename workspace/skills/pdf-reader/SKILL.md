---
name: pdf-reader
description: Process and extract text from uploaded PDF files.
---

# PDF Reader Skill

You have the ability to read and extract text from PDF files uploaded by the user.

When the user uploads a document, you will receive its URL in the chat. If it is a PDF file, you can process it using the provided Python script.

## Instructions
1. Download the PDF file using the `exec` tool (e.g., `wget "URL" -O /tmp/file.pdf`).
2. Run the PDF parsing script located at `/home/ubuntu/Project/picoclaw/scripts/pdf_parser.py` using the `exec` tool.
   Example: `python3 /home/ubuntu/Project/picoclaw/scripts/pdf_parser.py /tmp/file.pdf`
3. The script will output the extracted text from the PDF. Read the output and use it to answer the user's request.
4. Clean up the downloaded file using `rm /tmp/file.pdf`.

Never attempt to read a PDF file as plain text using `read_file`. Always use the `pdf_parser.py` script.
