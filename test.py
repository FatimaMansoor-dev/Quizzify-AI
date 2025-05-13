import os
from dotenv import load_dotenv

import google.generativeai as genai

# Load environment variables from .env file (if you have an API key stored there)
load_dotenv()

# Set the API key
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    print("Warning: No API key found in environment variables.")
    api_key = "YOUR_API_KEY"  # Replace with your actual API key if not using env vars

genai.configure(api_key=api_key)

def list_gemini_models():
    """List all available Gemini models."""
    try:
        # Get all available models
        all_models = genai.list_models()
        
        # Filter for Gemini models
        gemini_models = [model for model in all_models if "gemini" in model.name.lower()]
        
        print("Available Gemini Models:")
        for i, model in enumerate(gemini_models, 1):
            print(f"{i}. {model.name}")
            print(f"   - Description: {model.description}")
            print(f"   - Input token limit: {model.input_token_limit}")
            print(f"   - Output token limit: {model.output_token_limit}")
            print(f"   - Supported generation methods: {', '.join(model.supported_generation_methods)}")
            print()
        
        return gemini_models
    except Exception as e:
        print(f"Error listing Gemini models: {e}")
        return []

if __name__ == "__main__":
    print("Listing available Gemini models...")
    list_gemini_models()