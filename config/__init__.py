import os
import json

def load_config_file(filename):
    """Carrega arquivo de configuração"""
    config_path = os.path.join(os.path.dirname(__file__), filename)
    with open(config_path, 'r') as f:
        return json.load(f)

default_config = load_config_file('default_config.json')
production_config = load_config_file('production_config.json')
development_config = load_config_file('development_config.json')