import os
from crewai_tools import (
    PDFSearchTool,
    TXTSearchTool,
    JSONSearchTool,
    MDXSearchTool,
    FileReadTool
)

os.environ["PDF_API_KEY"] = "Your Key"  # Replace with the key if required for PDF tool.
os.environ["OPENAI_API_KEY"] = "Your Key"


# Instantiate tools
pdf_tool = PDFSearchTool()
txt_tool = TXTSearchTool()
json_tool = JSONSearchTool()
mdx_tool = MDXSearchTool()
file_read_tool = FileReadTool()

