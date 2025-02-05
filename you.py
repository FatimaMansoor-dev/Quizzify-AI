from youtube_transcript_api import YouTubeTranscriptApi

def get_transcript_as_paragraph(video_id):
    transcript = YouTubeTranscriptApi.get_transcript(video_id)
    text_paragraph = " ".join([entry['text'] for entry in transcript])
    return text_paragraph

# Example usage:
video_id = "n8s9DjPDBEw"  # Use only the video ID
print(get_transcript_as_paragraph(video_id))

