from flask import Flask, render_template, request, jsonify
from PyPDF2 import PdfReader
import openai

# Initialize Flask app
app = Flask(__name__)

# Replace with your OpenAI API key
openai.api_key = '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'


def extract_text_from_pdf(pdf_file):
    pdf = PdfReader(pdf_file)
    text = ""
    for page in pdf.pages:
        text += page.extract_text() or ""
    return text


def chat_with_nmap_report(text, user_question, temperature=0.5):
    prompt = (
        f"You are an assistant helping to analyze an Nmap scan report.\n"
        f"The report content is below:\n{text}\n\n"
        f"Answer the user's question based on the report:\n{user_question}"
    )

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2000,
        temperature=temperature,
    )

    return response.choices[0].message.content.strip()


@app.route('/')
def index():
    return render_template('chatbot.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    pdf_text = extract_text_from_pdf(file)
    return jsonify({"text": pdf_text})


@app.route('/ask', methods=['POST'])
def ask():
    data = request.get_json()
    pdf_text = data.get('text', '')
    user_question = data.get('question', '')

    if not pdf_text or not user_question:
        return jsonify({"error": "Missing report text or question"}), 400

    answer = chat_with_nmap_report(pdf_text, user_question)
    return jsonify({"answer": answer})


if __name__ == '__main__':
    app.run(debug=True)

# Next, I'll provide the HTML file (index.html) for the UI! 🚀
