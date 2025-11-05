# app/__init__.py
from pathlib import Path
from dotenv import load_dotenv

# Carica .env dalla root del progetto appena si importa "app"
env_path = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(env_path)
