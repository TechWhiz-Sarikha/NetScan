
from flask import Flask, request, jsonify, send_from_directory
import tempfile
import os
from werkzeug.utils import secure_filename
import openai
from PyPDF2 import PdfReader
import re
import json

app = Flask(__name__)

# Set your OpenAI API key here
openai.api_key = ""  # Replace with your actual OpenAI API key


def extract_text_from_pdf(pdf_file):
    """Extract all text from a PDF file."""
    pdf = PdfReader(pdf_file)
    text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    return text.strip()


@app.route('/')
def index():
    return send_from_directory('.', 'NetScanner.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and file.filename.lower().endswith('.pdf'):
        try:
            # Create a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp:
                file.save(temp.name)
                temp_path = temp.name

            # Extract text from the PDF
            text = extract_text_from_pdf(open(temp_path, 'rb'))

            # Clean up the temporary file
            os.unlink(temp_path)

            return jsonify({'text': text})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'File must be a PDF'}), 400


@app.route('/ask', methods=['POST'])
def ask_question():
    data = request.get_json()

    if not data or 'text' not in data or 'question' not in data:
        return jsonify({'error': 'Missing required parameters'}), 400

    text = data['text']
    question = data['question']

    try:
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system",
                 "content": "You are a network security expert analyzing Nmap scan results. Provide clear, concise, and actionable insights."},
                {"role": "user", "content": f"Here is an Nmap scan result:\n\n{text[:3000]}\n\nQuestion: {question}"}
            ],
            max_tokens=1000,
            temperature=0.5,
        )

        answer = response.choices[0].message.content
        return jsonify({'answer': answer})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
