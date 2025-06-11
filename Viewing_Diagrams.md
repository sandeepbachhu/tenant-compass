# Viewing Mermaid Diagrams

The flow diagrams in this project are created using Mermaid syntax, which requires a compatible Markdown viewer to render properly. Here are several ways to view the diagrams:

## Option 1: VS Code Extensions

Install one of these VS Code extensions to render Mermaid diagrams directly in VS Code:

1. **Markdown Preview Mermaid Support**
   - Open VS Code Extensions (Ctrl+Shift+X)
   - Search for "Markdown Preview Mermaid Support"
   - Click Install
   - Open the Markdown file
   - Press Ctrl+Shift+V or click the "Open Preview" button in the top-right corner

2. **Markdown Preview Enhanced**
   - Open VS Code Extensions (Ctrl+Shift+X)
   - Search for "Markdown Preview Enhanced"
   - Click Install
   - Open the Markdown file
   - Press Ctrl+K V or right-click and select "Markdown Preview Enhanced: Open Preview"

## Option 2: Online Mermaid Live Editor

1. Copy the Mermaid code (the content between the triple backticks and "mermaid")
2. Go to [Mermaid Live Editor](https://mermaid.live)
3. Paste the code into the editor
4. The diagram will render on the right side
5. You can download the diagram as an image if needed

## Option 3: GitHub Rendering

If you push these files to a GitHub repository, GitHub will automatically render the Mermaid diagrams when viewing the Markdown files in the GitHub UI.

## Option 4: Export as Images

If you need static images, you can:

1. Use the Mermaid Live Editor to export diagrams as PNG/SVG
2. Use a command-line tool like `mmdc` (Mermaid CLI) to convert Mermaid to images:

```bash
# Install Mermaid CLI
npm install -g @mermaid-js/mermaid-cli

# Convert a diagram to PNG
mmdc -i AWS_Flow_Diagram.md -o diagram.png
```

## Example Diagram

Here's a simple example of what a rendered Mermaid diagram looks like:

![Example Mermaid Diagram](https://mermaid.ink/img/pako:eNptkLsKwzAMRX9F6JkO-YEMHQrtUujS1YNiK4lIbAVbgZbgf6_tQEMpdBCSzrmPyQU1GkIJB9c7e8XnQJ5iYNtbdmRRQXFGH_rYkRolXJxnNT9ULFasWM2XVbWt6vXmvgEJR_I0Oo-WQnRskLxnCpZGMpwwDMR3Cfu7_XfNJGwxeAqZJEg4Zxo9DRTz1J-xJZNrSJnE1KPFd6bRzJB_5X9kKVuUULfNrm7app7dtYQTxsFPRg?type=png)
