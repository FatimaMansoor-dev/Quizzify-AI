#!/usr/bin/env python3
import os
import re
import json
import argparse
import logging
from pathlib import Path

# Required for PDF processing
import fitz  # PyMuPDF
from PIL import Image
import io

# Import Gemini API
import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted

from pydantic import BaseModel, ValidationError, conlist
from typing import List


# Define Pydantic models for response validation

class QuizValidationItem(BaseModel):
    question: str
    given_answer: str
    is_correct: bool
    source: str



# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def load_env_variables():
    """Load environment variables or use defaults"""
    from dotenv import load_dotenv

    load_dotenv()

    # Get the Gemini API key from environment
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set")

    return api_key


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Validate quiz answers against a transcript"
    )

    parser.add_argument("--pdf", "-p", required=True, help="Path to the quiz PDF file")

    parser.add_argument(
        "--transcript",
        "-t",
        required=True,
        help="Path to the transcript text file or the transcript text itself",
    )

    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Path to output JSON file (defaults to console output)",
    )

    parser.add_argument(
        "--dpi",
        "-d",
        type=int,
        default=150,
        help="DPI for PDF rendering (default: 150)",
    )

    parser.add_argument(
        "--prompt-file",
        "-pf",
        default=None,
        help="Path to a file containing a custom prompt template",
    )

    return parser.parse_args()


def get_transcript_text(transcript_path_or_text):
    """Get transcript text from file or direct input"""
    # Check if it's likely a file path
    if len(transcript_path_or_text) < 1000 and (
        os.path.exists(transcript_path_or_text)
        or Path(transcript_path_or_text).exists()
    ):
        with open(transcript_path_or_text, "r", encoding="utf-8") as f:
            return f.read().strip()
    else:
        # Assume it's the transcript text itself
        return transcript_path_or_text.strip()


def extract_images_from_pdf(pdf_path, dpi=600):
    """Extract images from PDF pages"""
    logging.info(f"Processing PDF: {pdf_path}")

    try:
        # Open the PDF file
        doc = fitz.open(pdf_path)

        # Extract images from each page
        page_images = []
        for page_num, page in enumerate(doc):
            logging.info(f"Processing page {page_num + 1}/{doc.page_count}")
            pix = page.get_pixmap(dpi=dpi)
            png_bytes = pix.tobytes(output="png")
            pil_img = Image.open(io.BytesIO(png_bytes))
            page_images.append(pil_img)

        logging.info(f"Successfully extracted {len(page_images)} page images")
        return page_images

    except Exception as e:
        logging.error(f"Failed to extract images from PDF: {e}")
        raise


def get_prompt_template(prompt_file=None):
    """Get prompt template from file or use default"""
    default_prompt = (
        "You are a quiz validator. You need to check the user's quiz answers "
        "against the provided source material. Analyze the quiz (shown in the images) "
        "and the source text to determine if the selected answers are correct.\n\n"
        "Respond with a JSON array of objects with these keys:\n"
        "- question: The full text of each question\n"
        "- given_answer: The answer that was selected or provided in the quiz\n"
        "- is_correct: Boolean indicating if the answer is correct according to the source\n"
        "- source: The specific text from the source material that supports the correct answer\n\n"
        "The quiz is shown in the images, and the source material is: {transcript}"
    )

    if prompt_file and os.path.exists(prompt_file):
        try:
            with open(prompt_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            logging.warning(f"Failed to read prompt file: {e}")
            logging.info("Using default prompt instead")
    else:
        logging.info("No prompt file provided or file not found. Using default prompt.")

    return default_prompt


def validate_quiz(pdf_path, transcript, dpi=150, prompt_template=None):
    """Validate quiz using Gemini API"""
    # Initialize Gemini API
    api_key = load_env_variables()
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-flash-preview-04-17")

    # Extract images from PDF
    page_images = extract_images_from_pdf(pdf_path, dpi)

    # Get prompt template
    if not prompt_template:
        prompt_template = get_prompt_template()

    # Build prompt
    prompt = prompt_template.format(transcript=transcript)
    logging.info("Sending request to Gemini API")

    # Define generation configuration
    # You can adjust these parameters as needed
    generation_config = genai.types.GenerationConfig(
        temperature=0.2,  # Lower temperature for more deterministic output
        top_p=0.95,
        top_k=40,
        max_output_tokens=8192, # Increased for potentially long JSON
        response_mime_type="application/json", # Request JSON output
        response_schema=list[QuizValidationItem]
    )

    try:
        # Call Gemini API
        response = model.generate_content(
            [prompt] + page_images,
            generation_config=generation_config
        )
        # Access the text directly as we requested JSON
        content = response.text

        try:
            # Parse the JSON string first
            raw_result = json.loads(content)

            validated_result = [QuizValidationItem(**item) for item in raw_result]
            logging.info("Successfully parsed and validated validation results")
            # Return the list of Pydantic model instances
            return [item.model_dump() for item in validated_result]
        except json.JSONDecodeError:
            logging.error(f"Failed to parse JSON from Gemini response: {content}")
            raise ValueError("Invalid JSON response from AI")
        except ValidationError as e:
            logging.error(f"Response validation failed: {e.errors()}")
            logging.error(f"Raw response content: {content}")
            raise ValueError(f"AI response does not match expected schema: {e.errors()}")

    except ResourceExhausted:
        logging.error("Gemini API quota exceeded")
        raise Exception("Quota exceeded. Please try again later.")
    except Exception as e:
        logging.exception("Gemini API call failed")
        raise


def main():
    """Main entry point for the script"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Get transcript text
        transcript_text = get_transcript_text(args.transcript)
        
        # Get prompt template if provided
        prompt_template = get_prompt_template(args.prompt_file)
        
        # Validate the quiz
        validation_results = validate_quiz(
            pdf_path=args.pdf,
            transcript=transcript_text,
            dpi=args.dpi,
            prompt_template=prompt_template
        )
        
        # Output the results
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(validation_results, f, indent=2)
            logging.info(f"Results saved to {args.output}")
        else:
            # Print to console
            print(json.dumps(validation_results, indent=2))
            
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
