# Web Assembler

[<img src="example.png" alt="Web Assembler" style="height: 400px;">](https://tools.hiumee.com/assembler)

This is a client-side asm assebler for x86 and x86-64 architectures with a simple web interface.

# Usage

## Using the github pages website

You can use the website hosted on github pages [https://tools.hiumee.com/assembler](https://tools.hiumee.com/assembler).

## Self-hosting

Clone the repository and start a web server in the root directory. For example, using python:

```bash
git clone https://github.com/Hiumee/Web-x86-Assembler-Disassembler
cd Web-x86-Assembler-Disassembler
python3 -m http.server
```

Then open your browser and go to `http://localhost:8000`.

## Use the PWA

You can also install the web app as a PWA. This will allow you to use the app offline. To do this, open the website and click on the install button in the address bar.

# Development

For development, you can use the same setup, with the addition of compiling the tailwindcss stylesheets. You can do this by running:

```bash
npm install
npx tailwindcss -i ./input.css -o ./style.css
```

# Tools used

- [iced](https://github.com/icedland/iced) - x86/x86-64 assembler and disassembler - used to disassemble the code
- [nasm](https://www.nasm.us/) - x86/x86-64 assembler - used to assemble the code - wasm from [tweetx86](https://github.com/AntoineViau/tweetx86)
- [x86 and amd64 instruction reference](https://www.felixcloutier.com/x86/) - Online x86 and amd64 (x86-64) instruction reference - used for documentation when clicking on an instruction
- [Tailwindcss](https://tailwindcss.com/) - Stylesheets
- [highlight.js](https://highlightjs.org/) - Syntax highlighting for the disassembled code