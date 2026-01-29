#!/usr/bin/env python3

import sys
import os
import json
import argparse
from typing import Set

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.tracker import IPTracker
from utils.validators import Validators

def load_ips_from_file(filename: str) -> Set[str]:
    ips = set()
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if parts:
                    ip = parts[0]
                    if Validators.validate_ip_address(ip):
                        ips.add(ip)
    except Exception as e:
        print(f"Erro ao ler arquivo {filename}: {e}")
    
    return ips

def load_ips_from_json(filename: str) -> Set[str]:
    ips = set()
    
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and Validators.validate_ip_address(item):
                        ips.add(item)
                    elif isinstance(item, dict) and 'ip' in item:
                        ip = item['ip']
                        if Validators.validate_ip_address(ip):
                            ips.add(ip)
            elif isinstance(data, dict):
                for key, value in data.items():
                    if key == 'ips' and isinstance(value, list):
                        for ip in value:
                            if Validators.validate_ip_address(ip):
                                ips.add(ip)
    except Exception as e:
        print(f"Erro ao ler JSON {filename}: {e}")
    
    return ips

def load_ips_from_csv(filename: str) -> Set[str]:
    ips = set()
    
    try:
        import csv
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                for cell in row:
                    cell = cell.strip()
                    if Validators.validate_ip_address(cell):
                        ips.add(cell)
    except Exception as e:
        print(f"Erro ao ler CSV {filename}: {e}")
    
    return ips

def load_ips_from_url(url: str) -> Set[str]:
    ips = set()
    
    try:
        import urllib.request
        import ssl
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(url, context=context) as response:
            content = response.read().decode('utf-8')
            
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if parts:
                    ip = parts[0]
                    if Validators.validate_ip_address(ip):
                        ips.add(ip)
    except Exception as e:
        print(f"Erro ao carregar URL {url}: {e}")
    
    return ips

def main():
    parser = argparse.ArgumentParser(description='Importar IPs para o HoneyPy')
    parser.add_argument('--type', choices=['block', 'whitelist'], required=True,
                       help='Tipo de importação (block ou whitelist)')
    parser.add_argument('--source', required=True,
                       help='Fonte dos IPs (arquivo, URL)')
    parser.add_argument('--format', choices=['auto', 'txt', 'json', 'csv', 'url'],
                       default='auto', help='Formato da fonte')
    parser.add_argument('--config', default='/etc/honeypy/config.json',
                       help='Arquivo de configuração do HoneyPy')
    parser.add_argument('--dry-run', action='store_true',
                       help='Apenas mostrar o que seria importado')
    
    args = parser.parse_args()
    
    print(f"Iniciando importação de IPs...")
    print(f"Tipo: {args.type}")
    print(f"Fonte: {args.source}")
    print(f"Formato: {args.format}")
    
    ips = set()
    
    if args.format == 'auto':
        if args.source.startswith('http://') or args.source.startswith('https://'):
            args.format = 'url'
        elif args.source.endswith('.json'):
            args.format = 'json'
        elif args.source.endswith('.csv'):
            args.format = 'csv'
        else:
            args.format = 'txt'
    
    if args.format == 'txt':
        ips = load_ips_from_file(args.source)
    elif args.format == 'json':
        ips = load_ips_from_json(args.source)
    elif args.format == 'csv':
        ips = load_ips_from_csv(args.source)
    elif args.format == 'url':
        ips = load_ips_from_url(args.source)
    
    print(f"IPs encontrados: {len(ips)}")
    
    if not ips:
        print("Nenhum IP válido encontrado para importação")
        return
    
    print("\nIPs para importação:")
    for i, ip in enumerate(sorted(ips)):
        print(f"  {i+1}. {ip}")
    
    if args.dry_run:
        print("\nDry-run: Nenhuma ação realizada")
        return
    
    confirm = input(f"\nImportar {len(ips)} IPs para {args.type}? (s/N): ")
    if confirm.lower() != 's':
        print("Importação cancelada")
        return
    
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
        
        tracker = IPTracker(config)
        
        imported = 0
        failed = 0
        
        for ip in ips:
            try:
                if args.type == 'block':
                    result = tracker.block_ip(ip, 0)
                    if result['success']:
                        imported += 1
                        print(f"✓ IP bloqueado: {ip}")
                    else:
                        failed += 1
                        print(f"✗ Falha ao bloquear {ip}: {result.get('error', 'Erro desconhecido')}")
                
                elif args.type == 'whitelist':
                    if tracker.add_to_whitelist(ip):
                        imported += 1
                        print(f"✓ IP adicionado à whitelist: {ip}")
                    else:
                        failed += 1
                        print(f"✗ Falha ao adicionar à whitelist: {ip}")
            
            except Exception as e:
                failed += 1
                print(f"✗ Erro ao processar {ip}: {e}")
        
        tracker.save_blocked_ips()
        
        print(f"\nResumo da importação:")
        print(f"  Total de IPs: {len(ips)}")
        print(f"  Importados com sucesso: {imported}")
        print(f"  Falhas: {failed}")
        
        if args.type == 'block':
            total_blocked = len(tracker.blocked_ips)
            print(f"  Total de IPs bloqueados: {total_blocked}")
        elif args.type == 'whitelist':
            total_whitelisted = len(tracker.whitelist_ips)
            print(f"  Total de IPs na whitelist: {total_whitelisted}")
    
    except Exception as e:
        print(f"Erro durante a importação: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()