# Quiz Validator Tool

This standalone script validates quiz answers against a provided transcript using the Gemini API.

## Setup

1. Make sure you have the required dependencies installed:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up your Gemini API key in the `.env` file:
   ```
   GEMINI_API_KEY=your_api_key_here
   ```

3. Make the script executable:
   ```bash
   chmod +x validate_quiz.py
   ```

## Usage

Basic usage:
```bash
./validate_quiz.py --pdf path/to/quiz.pdf --transcript path/to/transcript.txt
```

Or with a text string as transcript:
```bash
./validate_quiz.py --pdf path/to/quiz.pdf --transcript "This is the source text content..."
```

## Options

- `--pdf` or `-p`: Path to the quiz PDF file (required)
- `--transcript` or `-t`: Path to transcript file or transcript text (required)
- `--output` or `-o`: Path to save results JSON (optional)
- `--dpi` or `-d`: DPI for PDF rendering (default: 150)
- `--prompt-file` or `-pf`: Path to custom prompt template file (optional)

## Customizing the Prompt

You can customize the prompt by creating a text file with your prompt template and using the `--prompt-file` option:

```bash
./validate_quiz.py --pdf quiz.pdf --transcript transcript.txt --prompt-file sample_prompt.txt
```

In your prompt template, use `{transcript}` as a placeholder for the transcript content.

## Examples

1. Validate a quiz with default settings:
   ```bash
   ./validate_quiz.py -p quiz_user.pdf -t transcript.txt
   ```

2. Save results to a file:
   ```bash
   ./validate_quiz.py -p quiz_user.pdf -t transcript.txt -o results.json
   ```

3. Use a higher DPI for better image quality:
   ```bash
   ./validate_quiz.py -p quiz_user.pdf -t transcript.txt -d 300
   ```

4. Use a custom prompt template:
   ```bash
   ./validate_quiz.py -p quiz_user.pdf -t transcript.txt -pf sample_prompt.txt
   ```

5. USE THIS
python ./validate_quiz.py -p quiz_user.pdf -t transcript.txt -pf sample_prompt.txt -d 300 -o results.json