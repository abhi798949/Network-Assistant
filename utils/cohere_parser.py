
import cohere

co = cohere.Client("iJjTtzEhLHr1tWrn5TtWm7qxNmXt4VucN5gD3bXs")  # Replace with your API key

def get_action_from_prompt(prompt):
    # Always returns config commands to apply or audit
    response = co.generate(
        model='command-r-plus',
        prompt=f"Generate only Cisco IOS CLI commands (no explanation) based on this prompt:\n{prompt}",
        temperature=0.3,
        max_tokens=300,
    )
    return response.generations[0].text.strip()

def extract_config_commands(response):
    lines = response.splitlines()
    return [line.strip() for line in lines if line.strip()]
