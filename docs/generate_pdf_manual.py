#!/usr/bin/env python3
"""
YuBlog Manual PDF Generator

This script converts the Markdown user manual to a professionally formatted PDF.
It uses WeasyPrint for high-quality PDF generation with custom CSS styling.

Requirements:
- markdown
- weasyprint
- pygments (for syntax highlighting)

Install with: pip install markdown weasyprint pygments
"""

import markdown
from weasyprint import HTML, CSS
from pathlib import Path
import sys

def generate_pdf_manual():
    """Convert the Markdown manual to PDF"""
    
    # File paths
    md_file = Path(__file__).parent / "YUBLOG_USER_MANUAL.md"
    pdf_file = Path(__file__).parent / "YuBlog_User_Manual.pdf"
    
    # Check if markdown file exists
    if not md_file.exists():
        print(f"Error: Markdown file not found at {md_file}")
        sys.exit(1)
    
    # Read markdown content
    with open(md_file, 'r', encoding='utf-8') as f:
        markdown_content = f.read()
    
    # Configure markdown processor with extensions
    md = markdown.Markdown(extensions=[
        'toc',          # Table of contents
        'codehilite',   # Syntax highlighting
        'fenced_code',  # Fenced code blocks
        'tables',       # Tables support
        'attr_list',    # Attribute lists
        'def_list',     # Definition lists
    ])
    
    # Convert markdown to HTML
    html_content = md.convert(markdown_content)
    
    # CSS styles for professional PDF formatting
    css_styles = """
    @page {
        size: A4;
        margin: 2cm;
        @top-center {
            content: "YuBlog User Manual";
            font-family: 'Arial', sans-serif;
            font-size: 10pt;
            color: #666;
        }
        @bottom-center {
            content: "Page " counter(page);
            font-family: 'Arial', sans-serif;
            font-size: 10pt;
            color: #666;
        }
    }
    
    body {
        font-family: 'Arial', 'Helvetica', sans-serif;
        font-size: 11pt;
        line-height: 1.6;
        color: #333;
        max-width: none;
    }
    
    h1 {
        color: #2563eb;
        font-size: 24pt;
        font-weight: bold;
        margin-top: 30pt;
        margin-bottom: 20pt;
        page-break-before: always;
        border-bottom: 3pt solid #2563eb;
        padding-bottom: 10pt;
    }
    
    h1:first-child {
        page-break-before: avoid;
        text-align: center;
        border-bottom: none;
        margin-top: 0;
    }
    
    h2 {
        color: #1e40af;
        font-size: 18pt;
        font-weight: bold;
        margin-top: 25pt;
        margin-bottom: 15pt;
        border-bottom: 1pt solid #e5e7eb;
        padding-bottom: 5pt;
    }
    
    h3 {
        color: #1f2937;
        font-size: 14pt;
        font-weight: bold;
        margin-top: 20pt;
        margin-bottom: 10pt;
    }
    
    h4 {
        color: #374151;
        font-size: 12pt;
        font-weight: bold;
        margin-top: 15pt;
        margin-bottom: 8pt;
    }
    
    p {
        margin-bottom: 12pt;
        text-align: justify;
    }
    
    ul, ol {
        margin-bottom: 12pt;
        padding-left: 20pt;
    }
    
    li {
        margin-bottom: 6pt;
    }
    
    strong {
        color: #1f2937;
        font-weight: bold;
    }
    
    em {
        font-style: italic;
        color: #4b5563;
    }
    
    code {
        font-family: 'Courier New', monospace;
        font-size: 10pt;
        background-color: #f3f4f6;
        padding: 2pt 4pt;
        border-radius: 3pt;
        color: #dc2626;
    }
    
    pre {
        background-color: #f8fafc;
        border: 1pt solid #e5e7eb;
        border-radius: 6pt;
        padding: 12pt;
        margin: 12pt 0;
        font-family: 'Courier New', monospace;
        font-size: 9pt;
        line-height: 1.4;
        overflow-x: auto;
    }
    
    pre code {
        background-color: transparent;
        padding: 0;
        color: #374151;
    }
    
    blockquote {
        border-left: 4pt solid #3b82f6;
        margin: 12pt 0;
        padding-left: 16pt;
        color: #4b5563;
        font-style: italic;
    }
    
    .toc {
        background-color: #f8fafc;
        border: 1pt solid #e5e7eb;
        border-radius: 6pt;
        padding: 20pt;
        margin: 20pt 0;
    }
    
    .toc ul {
        list-style: none;
        padding-left: 0;
    }
    
    .toc > ul > li {
        margin-bottom: 8pt;
        font-weight: bold;
    }
    
    .toc a {
        color: #2563eb;
        text-decoration: none;
    }
    
    .toc a:hover {
        text-decoration: underline;
    }
    
    hr {
        border: none;
        border-top: 2pt solid #e5e7eb;
        margin: 30pt 0;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 12pt 0;
        font-size: 10pt;
    }
    
    th, td {
        border: 1pt solid #d1d5db;
        padding: 8pt;
        text-align: left;
    }
    
    th {
        background-color: #f3f4f6;
        font-weight: bold;
        color: #1f2937;
    }
    
    .page-break {
        page-break-before: always;
    }
    
    .no-break {
        page-break-inside: avoid;
    }
    
    /* Question and Answer styling for FAQ */
    p:has(strong:contains("Q:")) {
        margin-top: 15pt;
        margin-bottom: 5pt;
    }
    
    p:has(strong:contains("A:")) {
        margin-bottom: 15pt;
        padding-left: 10pt;
        border-left: 2pt solid #e5e7eb;
    }
    
    /* Print optimizations */
    @media print {
        body {
            font-size: 10pt;
        }
        
        h1 {
            font-size: 20pt;
        }
        
        h2 {
            font-size: 16pt;
        }
        
        h3 {
            font-size: 12pt;
        }
        
        h4 {
            font-size: 11pt;
        }
    }
    """
    
    # Create complete HTML document
    html_document = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>YuBlog User Manual</title>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    
    print("Converting Markdown to HTML...")
    
    try:
        # Generate PDF
        print("Generating PDF...")
        html_obj = HTML(string=html_document)
        css_obj = CSS(string=css_styles)
        
        html_obj.write_pdf(
            pdf_file,
            stylesheets=[css_obj],
            optimize_images=True,
            presentational_hints=True
        )
        
        print(f"✅ PDF manual successfully generated: {pdf_file}")
        print(f"📄 File size: {pdf_file.stat().st_size / 1024:.1f} KB")
        
    except Exception as e:
        print(f"❌ Error generating PDF: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("🚀 YuBlog Manual PDF Generator")
    print("=" * 40)
    
    try:
        generate_pdf_manual()
    except KeyboardInterrupt:
        print("\n⚠️  Generation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1) 