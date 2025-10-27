from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re
import spacy
import pandas as pd
import pdfplumber
import docx
import easyocr

# Initialize Flask app and enable CORS for React frontend
app = Flask(__name__)
CORS(app)

# Load spaCy's English model
nlp = spacy.load("en_core_web_sm")

# Initialize EasyOCR reader
reader = easyocr.Reader(['en'])

# Load the datasets
malware_data = pd.read_excel('Malware.xlsx')
tactics_data = pd.read_excel('TTP_Tactics.xlsx')
techniques_data = pd.read_excel('TTP_Techniques.xlsx')
threat_actors_data = pd.read_excel('ThreatActors.xlsx')
targeted_entities_data = pd.read_excel('TargetedEntities.xlsx')

# Function to extract text from a PDF file
def extract_text_from_pdf(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        text = "".join([page.extract_text() or "" for page in pdf.pages])
    return text

# Function to extract text from a .txt file
def extract_text_from_txt(txt_path):
    with open(txt_path, 'r', encoding='utf-8') as file:
        return file.read()

# Function to extract text from a .docx file
def extract_text_from_docx(docx_path):
    doc = docx.Document(docx_path)
    return "\n".join([para.text for para in doc.paragraphs])

# Function to extract text from an image file
def extract_text_from_image(image_path):
    return ''.join(reader.readtext(image_path, detail=0))

# Function to extract text based on file type
def extract_text_from_file(file_path):
    ext = os.path.splitext(file_path)[-1].lower()
    if ext == '.pdf':
        return extract_text_from_pdf(file_path)
    elif ext == '.txt':
        return extract_text_from_txt(file_path)
    elif ext == '.docx':
        return extract_text_from_docx(file_path)
    elif ext in ['.png', '.jpg', '.jpeg']:
        return extract_text_from_image(file_path)
    else:
        raise ValueError("Unsupported file type.")

# Function to match text with datasets and extract IoCs
def match_with_dataset(text):
    result = {}

    # Extract IoCs using regex patterns
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,}\b'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'  # MD5: 32 characters
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'  # SHA-1: 40 characters
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'  # SHA-256: 64 characters
    sha512_pattern = r'\b[a-fA-F0-9]{128}\b'  # SHA-512: 128 characters
    email_pattern = r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
    tlsh_pattern = r'\s*([a-fA-F0-9]{70,})'

    result['IP addresses'] = list(set(re.findall(ip_pattern, text)))
    result['Domains'] = list(set(re.findall(domain_pattern, text)))
    result['MD5'] = list(set(re.findall(md5_pattern, text)))
    result['SHA-1'] = list(set(re.findall(sha1_pattern, text)))
    result['SHA-256'] = list(set(re.findall(sha256_pattern, text)))
    result['SHA-512'] = list(set(re.findall(sha512_pattern, text)))
    result['Emails'] = list(set(re.findall(email_pattern, text, re.IGNORECASE)))
    result['TLSH'] = list(set(re.findall(tlsh_pattern, text)))

    # Extract TTPs (Tactics and Techniques)
    result['Tactics'] = []
    for _, row in tactics_data.iterrows():
        if row["Tactic Name"].lower() in text.lower():
            result['Tactics'].append({row["TTP ID"]: row["Tactic Name"]})
    
    result['Techniques'] = []
    for _, row in techniques_data.iterrows():
        if row["Technique Name"].lower() in text.lower():
            result['Techniques'].append({row["Technique ID"]: row["Technique Name"]})

    # Extract Threat Actors
    result['Threat Actors'] = []
    for _, row in threat_actors_data.iterrows():
        if row["Name"].lower() in text.lower():
            result['Threat Actors'].append(row["Name"])

    # Extract Targeted Entities
    result['Targeted Entities'] = []
    for _, row in targeted_entities_data.iterrows():
        if row["Entity"].lower() in text.lower():
            result['Targeted Entities'].append(row["Entity"])

    # Deduplicate and clean up the results
    for key in result:
        if isinstance(result[key], list):  # Convert nested dictionaries or lists of dictionaries to simple values
            result[key] = [str(item) if isinstance(item, dict) else item for item in result[key]]
        result[key] = list(set(result[key]))

    # Ensure that everything is a simple list or dictionary, and not unhashable types
    return {key: value if isinstance(value, list) else list(value) for key, value in result.items()}

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save the uploaded file temporarily
    file_path = os.path.join('/tmp', file.filename)
    file.save(file_path)

    try:
        # Extract text from the file
        file_text = extract_text_from_file(file_path)

        # Match datasets and extract IoCs
        threat_intelligence = match_with_dataset(file_text)

        return jsonify(threat_intelligence)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
