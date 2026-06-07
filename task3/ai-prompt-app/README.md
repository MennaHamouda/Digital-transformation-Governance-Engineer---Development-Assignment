# AI Prompt Studio — Flask App

A minimal Flask web application that accepts a user prompt and returns an AI-generated response using the Anthropic API.

## Project Structure

```
ai-prompt-app/
├── app.py               # Flask backend
├── requirements.txt     # Python dependencies
├── README.md
└── templates/
    └── index.html       # Single-page frontend
```

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set your API key

**Never hardcode API keys.** Export the key as an environment variable:

```bash
# Linux / macOS
export ANTHROPIC_API_KEY="sk-ant-..."

# Windows (PowerShell)
$env:ANTHROPIC_API_KEY="sk-ant-..."
```

Or create a `.env` file and use `python-dotenv` (not included by default):

```
ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Run the app

```bash
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

## API Endpoint

### `POST /generate`

**Request body (JSON):**
```json
{ "prompt": "Explain quantum entanglement simply." }
```

**Success response:**
```json
{ "response": "Quantum entanglement is..." }
```

**Error response:**
```json
{ "error": "Prompt cannot be empty." }
```

## Error Handling

| Scenario | HTTP Status | Behaviour |
|---|---|---|
| Empty prompt | 400 | Returns `{ "error": "..." }` |
| Anthropic API error | 502 | Returns `{ "error": "API error: ..." }` |
| Unexpected exception | 500 | Returns `{ "error": "Unexpected error: ..." }` |
| Network failure (frontend) | — | Shows inline error message |

## Keyboard Shortcut

Press **Ctrl + Enter** (or **Cmd + Enter** on Mac) to submit a prompt without clicking the button.

## Swapping the AI Model

To use OpenAI instead, replace the `anthropic` client in `app.py` with the `openai` package:

```python
from openai import OpenAI
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}]
)
response_text = response.choices[0].message.content
```
