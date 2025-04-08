import streamlit as st
import openai
import os
import json
import pandas as pd
import docx
import fitz  # PyMuPDF
from streamlit_lottie import st_lottie
import requests
from datetime import datetime
from pathlib import Path

# Check if running in embedded mode
is_embedded = "embedded" in st.query_params

# Page configuration
st.set_page_config(
    page_title="Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed" if is_embedded else "auto"
)

# Set your OpenAI API Key
openai_api_key = ""  # Replace with your OpenAI key
client = openai.OpenAI(api_key=openai_api_key)

# Custom CSS for better embedding
st.markdown("""
    <style>
    /* General styles */
    html, body, [class*="css"] {
        font-family: 'Segoe UI', sans-serif;
        background-color: transparent;
    }
    
    /* Title styles */
    .title {
        text-align: center;
        font-size: 2.2em;
        color: #333333;
        font-weight: bold;
        margin-bottom: 5px;
    }
    
    .sub {
        text-align: center;
        font-size: 1em;
        color: #666;
        margin-bottom: 20px;
    }
    
    /* When embedded - hide unnecessary elements */
    .embedded .stDeployButton,
    .embedded footer,
    .embedded header,
    .embedded .block-container {
        padding-top: 0.5rem !important;
        padding-bottom: 0.5rem !important;
    }
    
    /* Hide hamburger menu in embedded mode */
    .embedded .css-1rs6os {
        visibility: hidden;
    }
    
    /* Hide "Made with Streamlit" footer */
    .embedded footer {
        display: none !important;
    }
    
    /* Hide top right menu */
    .embedded #MainMenu {
        visibility: hidden;
    }
    
    /* Compact the UI in embedded mode */
    .embedded .stAlert {
        padding: 0.5rem !important;
    }
    </style>
    
    <script>
    // Add embedded class if in iframe
    if (window !== window.parent) {
        document.documentElement.classList.add('embedded');
    }
    
    // Listen for messages from parent
    window.addEventListener('message', function(event) {
        if (event.data.type === 'theme') {
            // Apply theme changes from parent if needed
            const darkMode = event.data.darkMode;
            // You could change styles based on this
        }
    });
    </script>
""", unsafe_allow_html=True)

# Function to load animations
def load_lottie_url(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

# Conditional animation based on whether we're embedded
if not is_embedded:
    st.markdown('<div class="title">🛡️ Vulnerability NetScanner AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub">Upload your scan report for AI-powered analysis</div>', unsafe_allow_html=True)
    
    # Only show animation if not embedded
    lottie_scan = load_lottie_url("https://assets4.lottiefiles.com/packages/lf20_t24tpvcu.json")
    if lottie_scan:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st_lottie(lottie_scan, height=200, speed=1)
else:
    # Simplified header for embedded mode
    st.markdown('<div class="title" style="font-size:1.8em;">Upload Report for Analysis</div>', unsafe_allow_html=True)

# File uploader
uploaded_file = st.file_uploader(
    "📂 Choose your vulnerability scan report",
    type=["pdf", "docx", "csv", "json"],
    help="Upload Nmap, Nessus, OpenVAS, or other security scan reports"
)

# Extract functions
def extract_text_from_pdf(file):
    doc = fitz.open(stream=file.read(), filetype="pdf")
    return "".join([page.get_text() for page in doc])

def extract_text_from_docx(file):
    return "\n".join([p.text for p in docx.Document(file).paragraphs])

def extract_text_from_csv(file):
    return pd.read_csv(file).to_string()

def extract_text_from_json(file):
    return json.dumps(json.load(file), indent=4)

# AI analysis function
def get_chatgpt_summary(text_data, filename):
    try:
        prompt = f"""You are an expert cybersecurity analyst reviewing a vulnerability scan report named '{filename}'.
Please provide a concise executive summary covering:
1. Critical findings and their impact
2. List of vulnerabilities by severity level (Critical, High, Medium, Low)
3. Affected systems, ports, or services
4. Recommended remediation steps in priority order

Here is the scan report content:
{text_data[:3000]}"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability assessment."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.4,
            max_tokens=800
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"❌ Error with AI analysis: {e}"

# Create results directory if it doesn't exist
results_dir = Path("results")
results_dir.mkdir(exist_ok=True)

# Process the uploaded file
if uploaded_file:
    file_type = uploaded_file.type
    file_name = uploaded_file.name

    try:
        # Extract content based on file type
        with st.spinner("🔍 Analyzing report content..."):
            if file_type == "application/pdf":
                text_data = extract_text_from_pdf(uploaded_file)
            elif file_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
                text_data = extract_text_from_docx(uploaded_file)
            elif file_type == "application/json":
                text_data = extract_text_from_json(uploaded_file)
            elif file_type in ["text/csv", "application/vnd.ms-excel"]:
                text_data = extract_text_from_csv(uploaded_file)
            else:
                st.error("Unsupported file format.")
                st.stop()
        
        # Get AI summary
        with st.spinner("🧠 Generating AI insights..."):
            summary = get_chatgpt_summary(text_data, file_name)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_data = {
            "filename": file_name,
            "timestamp": timestamp,
            "summary": summary
        }

        output_path = results_dir / f"summary_{Path(file_name).stem}_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(summary_data, f, indent=4)

        # Success message and display summary
        st.success("✅ Analysis complete!")
        
        # Show results in tabs for better organization
        tab1, tab2 = st.tabs(["📊 Summary", "📋 Raw Data"])
        
        with tab1:
            st.markdown("### 🛡️ Vulnerability Analysis")
            st.markdown(summary)
            
            # Download button
            with open(output_path, "rb") as f:
                st.download_button(
                    label="📥 Download Report (JSON)",
                    data=f,
                    file_name=f"vulnerability_report_{Path(file_name).stem}.json",
                    mime="application/json"
                )
        
        with tab2:
            st.markdown("### 📄 Raw Extracted Content")
            st.text_area("First 5000 characters of content:", text_data[:5000], height=300)

    except Exception as e:
        st.error(f"⚠️ Error processing file: {e}")