import sys
import os
from src.core.honeypy_system import HoneyPySystem
from src.utils.helpers import setup_logging, load_config

def main():
    """Função principal"""
    # Configurações iniciais
    setup_logging()
    config = load_config()
    
    # Inicializa o sistema
    honeypy = HoneyPySystem(config)
    
    # Executa o sistema
    return honeypy.run()

if __name__ == "__main__":
    sys.exit(main())