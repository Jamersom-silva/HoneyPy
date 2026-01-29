import os

DATA_DIR = os.path.dirname(__file__)

def ensure_directories():
    """Garante que todos os diretórios de dados existam"""
    directories = [
        os.path.join(DATA_DIR, 'logs'),
        os.path.join(DATA_DIR, 'reports', 'daily'),
        os.path.join(DATA_DIR, 'reports', 'weekly'),
        os.path.join(DATA_DIR, 'reports', 'monthly'),
        os.path.join(DATA_DIR, 'state'),
        os.path.join(DATA_DIR, 'databases', 'geoip'),
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    return True