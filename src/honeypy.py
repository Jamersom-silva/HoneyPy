#!/usr/bin/env python3
import sys
import os
import argparse
import json
import logging
from datetime import datetime

from src.core.honeypy_system import HoneyPySystem
from src.utils.helpers import setup_logging, load_config, create_directory_structure

def main():
    parser = argparse.ArgumentParser(
        description='HoneyPy - Sistema de Detecção de Ataques de Brute Force',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --monitor
  %(prog)s --report
  %(prog)s --list-ips --limit 20
  %(prog)s --ip-info 192.168.1.100
  %(prog)s --block-ip 203.0.113.45 --duration 48
        """
    )
    
    parser.add_argument('--config', type=str, default='/etc/honeypy/config.json',
                       help='Caminho para arquivo de configuração')
    parser.add_argument('--monitor', action='store_true',
                       help='Iniciar monitoramento contínuo')
    parser.add_argument('--report', action='store_true',
                       help='Gerar relatório de segurança')
    parser.add_argument('--report-type', choices=['daily', 'weekly', 'monthly'],
                       default='daily', help='Tipo de relatório')
    parser.add_argument('--list-ips', action='store_true',
                       help='Listar IPs suspeitos')
    parser.add_argument('--limit', type=int, default=50,
                       help='Limite de resultados')
    parser.add_argument('--ip-info', type=str,
                       help='Obter informações sobre um IP específico')
    parser.add_argument('--block-ip', type=str,
                       help='Bloquear um IP específico')
    parser.add_argument('--unblock-ip', type=str,
                       help='Desbloquear um IP específico')
    parser.add_argument('--whitelist-ip', type=str,
                       help='Adicionar IP à whitelist')
    parser.add_argument('--duration', type=int, default=24,
                       help='Duração do bloqueio em horas')
    parser.add_argument('--version', action='store_true',
                       help='Mostrar versão')
    parser.add_argument('--test-config', action='store_true',
                       help='Testar configuração')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.version:
        print("HoneyPy v1.0.0")
        return 0
    
    try:
        if args.test_config:
            return test_configuration(args.config)
        
        if not os.path.exists(args.config):
            print(f"Arquivo de configuração não encontrado: {args.config}")
            print("Use --config para especificar o caminho correto")
            return 1
        
        config = load_config(args.config)
        setup_logging(config.get('logging', {}))
        
        create_directory_structure()
        
        honeypy = HoneyPySystem(args.config)
        
        if args.monitor:
            return run_monitoring_mode(honeypy)
        elif args.report:
            return generate_report(honeypy, args.report_type)
        elif args.list_ips:
            return list_suspicious_ips(honeypy, args.limit)
        elif args.ip_info:
            return show_ip_info(honeypy, args.ip_info)
        elif args.block_ip:
            return block_ip(honeypy, args.block_ip, args.duration)
        elif args.unblock_ip:
            return unblock_ip(honeypy, args.unblock_ip)
        elif args.whitelist_ip:
            return whitelist_ip(honeypy, args.whitelist_ip)
        else:
            parser.print_help()
            return 0
            
    except KeyboardInterrupt:
        print("\n\nOperação interrompida pelo usuário")
        return 0
    except Exception as e:
        print(f"Erro: {e}")
        return 1

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║                    HoneyPy v1.0                          ║
║          Sistema de Detecção de Ataques                  ║
║                  Monitor de Ameaças                      ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def test_configuration(config_path):
    print("Testando configuração...")
    
    try:
        config = load_config(config_path)
        
        print("✓ Configuração carregada com sucesso")
        
        required_sections = ['system', 'monitoring', 'detection', 'logging']
        for section in required_sections:
            if section in config:
                print(f"✓ Seção '{section}' presente")
            else:
                print(f"✗ Seção '{section}' faltando")
        
        print("\nResumo:")
        print(f"  Modo: {config.get('system', {}).get('mode', 'N/A')}")
        print(f"  Intervalo: {config.get('monitoring', {}).get('interval_seconds', 'N/A')}s")
        print(f"  Limite SSH: {config.get('detection', {}).get('thresholds', {}).get('ssh', {}).get('max_attempts', 'N/A')}")
        
        return 0
        
    except Exception as e:
        print(f"✗ Erro: {e}")
        return 1

def run_monitoring_mode(honeypy):
    print("Iniciando modo de monitoramento...")
    print("Pressione Ctrl+C para parar\n")
    
    try:
        honeypy.start()
        return 0
    except KeyboardInterrupt:
        print("\nParando monitoramento...")
        honeypy.stop()
        return 0

def generate_report(honeypy, report_type):
    print(f"Gerando relatório {report_type}...")
    
    report = honeypy.generate_report(report_type)
    
    if 'error' in report:
        print(f"Erro: {report['error']}")
        return 1
    
    summary = report.get('summary', {})
    
    print(f"\nRelatório {report_type} gerado com sucesso!")
    print(f"Arquivo: {report.get('metadata', {}).get('file_path', 'N/A')}")
    print(f"\nResumo:")
    print(f"  Tentativas de ataque: {summary.get('total_attack_attempts', 0)}")
    print(f"  Atacantes únicos: {summary.get('unique_attackers', 0)}")
    print(f"  IPs bloqueados: {summary.get('blocked_ips', 0)}")
    
    if 'top_attackers' in report and report['top_attackers']:
        print(f"\nTop atacantes:")
        for attacker in report['top_attackers'][:3]:
            print(f"  {attacker['ip_address']}: {attacker['total_attempts']} tentativas")
    
    return 0

def list_suspicious_ips(honeypy, limit):
    suspicious = honeypy.list_suspicious_ips(limit)
    
    if not suspicious:
        print("Nenhum IP suspeito encontrado")
        return 0
    
    print(f"IPs suspeitos (últimos {len(suspicious)}):\n")
    print(f"{'IP':<20} {'Tentativas':<12} {'Serviços':<20} {'Última':<25}")
    print("-" * 80)
    
    for ip_info in suspicious:
        ip = ip_info.get('ip_address', 'N/A')
        attempts = ip_info.get('total_attempts', 0)
        services = ', '.join(list(ip_info.get('services_attacked', {}).keys())[:2])
        last_seen = ip_info.get('last_attempt', 'N/A')[:19]
        
        print(f"{ip:<20} {attempts:<12} {services:<20} {last_seen:<25}")
    
    return 0

def show_ip_info(honeypy, ip_address):
    info = honeypy.get_ip_info(ip_address)
    
    if not info or 'ip_address' not in info:
        print(f"IP não encontrado: {ip_address}")
        return 1
    
    print(f"\nInformações para IP: {ip_address}")
    print("=" * 50)
    
    print(f"Status: ", end="")
    if info.get('is_blocked'):
        print("🚫 BLOQUEADO")
    elif info.get('is_suspicious'):
        print("⚠️  SUSPEITO")
    elif info.get('is_whitelisted'):
        print("✅ WHITELIST")
    else:
        print("📊 MONITORADO")
    
    stats = info.get('statistics', {})
    if stats:
        print(f"\nEstatísticas:")
        print(f"  Tentativas totais: {stats.get('total_attempts', 0)}")
        print(f"  Primeira tentativa: {stats.get('first_attempt', 'N/A')}")
        print(f"  Última tentativa: {stats.get('last_attempt', 'N/A')}")
        
        services = stats.get('services_attacked', {})
        if services:
            print(f"\nServiços atacados:")
            for service, data in services.items():
                attempts = data.get('attempts', 0)
                threshold = data.get('threshold', 0)
                status = "⚠️ " if attempts >= threshold else "✓ "
                print(f"  {status} {service}: {attempts}/{threshold}")
    
    if 'geoip' in info:
        geo = info['geoip']
        location = geo.get('location', {})
        print(f"\nLocalização:")
        if location.get('country_name'):
            print(f"  País: {location.get('country_name')} ({location.get('country_code')})")
        if location.get('city'):
            print(f"  Cidade: {location.get('city')}")
    
    return 0

def block_ip(honeypy, ip_address, duration):
    print(f"Bloqueando IP: {ip_address} por {duration} horas...")
    
    result = honeypy.block_ip(ip_address, duration)
    
    if result.get('success'):
        print(f"✅ IP bloqueado com sucesso")
        print(f"   Duração: {duration} horas")
        if 'blocked_until' in result:
            print(f"   Desbloqueio: {result['blocked_until']}")
        return 0
    else:
        print(f"❌ Falha ao bloquear IP")
        print(f"   Erro: {result.get('error', 'Desconhecido')}")
        return 1

def unblock_ip(honeypy, ip_address):
    print(f"Desbloqueando IP: {ip_address}...")
    
    result = honeypy.unblock_ip(ip_address)
    
    if result.get('success'):
        print(f"✅ IP desbloqueado com sucesso")
        return 0
    else:
        print(f"❌ Falha ao desbloquear IP")
        print(f"   Erro: {result.get('error', 'Desconhecido')}")
        return 1

def whitelist_ip(honeypy, ip_address):
    print(f"Adicionando IP à whitelist: {ip_address}...")
    
    success = honeypy.add_to_whitelist(ip_address)
    
    if success:
        print(f"✅ IP adicionado à whitelist com sucesso")
        return 0
    else:
        print(f"❌ Falha ao adicionar IP à whitelist")
        return 1

if __name__ == '__main__':
    sys.exit(main())