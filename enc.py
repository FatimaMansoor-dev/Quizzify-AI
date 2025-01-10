import random
import string
import json

# Define the characters
chars = " " + string.punctuation + string.digits + string.ascii_letters
chars = list(chars)

# Create a shuffled copy of chars for the key
key = chars.copy()
random.shuffle(key)

# Create the dictionary mapping
d = {chars[i]: key[i] for i in range(len(chars))}

# Save the dictionary as a JSON file
output_file = "char_key_mapping.json"
with open(output_file, "w") as f:
    json.dump(d, f, indent=4)

print(f"Character mapping saved to {output_file}")
