import argparse
import socket
import threading
import json
from tqdm import tqdm
from termcolor import colored
from IPython.display import clear_output

class ScanThread(threading.Thread):
    def __init__(self, target, port, timeout, scan_type):
        super().__init__()
        self.target = target
        self.port = port
        self.timeout = timeout
        self.scan_type = scan_type
        self.result = None

    def run(self):
        try:
            # Cria um socket e conecta no host e porta
            client = socket.socket(socket.AF_INET, self.scan_type)
            client.settimeout(self.timeout)
            client.connect((self.target, self.port))
            print(colored(f"[+] Porta {self.port} aberta. \n", "green"))
            try:
                # Banner Grabbing
                banner = socket.get_banner(self.target, self.port)
                version = socket.get_service_version(self.target, self.port)
                print(f"Banner na porta {self.port}: {banner.strip()}")
                print(f"Versão do serviço - Porta {self.port}: {version}")

                # Valida Vuln em FTP
                if "FTP" in version and "2.2" in version:
                    print(colored(f"[!] Vulnerabilidade detectada: FTP service version {version} is vulnerable to exploit.", "yellow"))
            except:
                print(f"Unable to get banner and service version for port {self.port}")
            try:
                client.send(b"GET /get_banner HTTP/1.1\r\nHost: %s\r\n\r\n")
                response = client.recv(1024).decode("utf-8")

                if "FTP" in response:
                    print(f"Serviço rodando {self.port}: FTP")
                    # Check for known vulnerabilities in FTP response
                    if "vsftpd 2.3.4" in response:
                        print(colored(f"[!] Vulnerabilidade detectada: FTP response from port {self.port} indicates that the service is vulnerable to exploit.", "yellow"))
                elif "SSH" in response:
                    print(f"Serviço rodando {self.port}: SSH")
                elif "SMTP" in response:
                    print(f"Serviço rodando {self.port}: SMTP")
                elif "HTTP" in response:
                    print(f"Serviço rodando {self.port}: HTTP")    
                elif "POP3" in response:
                    print(f"Serviço rodando {self.port}: POP3")
                elif "DNS" in response:
                    print(f"Serviço rodando {self.port}: DNS")
                elif "IMAP" in response:
                    print(f"Serviço rodando {self.port}: IMAP")
                elif "HTTPS" in response:
                    print(f"Serviço rodando {self.port}: HTTPS")    
                elif "SNMP" in response:
                    print(f"Serviço rodando {self.port}: SNMP")
                elif "Telnet" in response:
                    print(f"Serviço rodando {self.port}: Telnet")
                elif "NetBIOS" in response:
                    print(f"Serviço rodando {self.port}: NetBIOS")
                elif "SMB" in response:
                    print(f"Serviço rodando {self.port}: SMB")    
                elif "RDP" in response:
                    print(f"Serviço rodando {self.port}: RDP")
                elif "SMTPS" in response:
                    print(f"Serviço rodando {self.port}: SMTPS")
                elif "POP3S" in response:
                    print(f"Serviço rodando {self.port}: POP3S")
                elif "IMAPS" in response:
                    print(f"Serviço rodando {self.port}: IMAPS")
                elif "SQL" in response:
                    print("Vulnerabilidade encontrada na porta {}: SQL injection".format(self.port))
                elif "XSS" in response:
                    print("Vulnerabilidade encontrada na porta {}: Cross-site scripting (XSS)".format(self.port))
                elif "Directory listing" in response:
                    print("Vulnerabilidade encontrada na porta {}: Directory listing enabled".format(self.port))
    
                # Adicionar novas assinaturas aqui
                else:
                    print(f"Serviço rodando {self.port}: {response.strip()}")
                if "SQL" in response:
                    print("Vulnerabilidade encontrada na porta {}: SQL injection".format(self.port))
                elif "XSS" in response:
                    print("Vulnerabilidade encontrada na porta {}: Cross-site scripting (XSS)".format(self.port))
                elif "Directory listing" in response:
                    print("Vulnerabilidade encontrada na porta {}: Directory listing enabled".format(self.port))    
            except:
                print(f"Não foi possível determinar o serviço em execução na porta {self.port}")    
            
            # Salva a porta aberta em self.result
            self.result = self.port
            
        except:
            print(colored(f"[-] Porta {self.port} fechada.\n", "red"))
            
        client.close()        

# Função para validar as portas abertas
def scan_targets(targets, port_range, timeout, num_threads, output_file):
    for target in targets:
        all_open_ports = []
        clear_output(wait=False)
        print(colored(f"\n[+] Scanning {target}...", "yellow"))
        if target.startswith('http'):
            target = target.split('//')[1]
        if ':' in target:
            target = target.split(':')[0]
        # Parsing 
        start_port, end_port = parse_port_range(port_range)
        threads = []
        for port in range(start_port, end_port+1):
            thread = ScanThread(target, port, timeout, socket.SOCK_STREAM)
            threads.append(thread)
        # Multiplas threads
        for i in tqdm(range(0, len(threads), num_threads), desc="Scanning ports"):
            batch = threads[i:i+num_threads]
            for thread in batch:
                thread.start()
            for thread in batch:
                thread.join()
                if thread.result is not None:
                    all_open_ports.append(thread.result)        
    return all_open_ports

# Função analise intervalo de portas
def parse_port_range(port_range):
    if port_range.lower() == 'all':
        # se for todas as portas, analisa tudo
        start_port = 1
        end_port = 65535
    else:
        # se não, pega as portas inicial e final da string
        start_port, end_port = port_range.split('-')
        start_port = int(start_port)
        end_port = int(end_port)
    return start_port, end_port

def main():
    # opções
    parser = argparse.ArgumentParser(description='TCP port scanner')
    parser.add_argument('-t', '--targets', required=True, nargs='+', help='target IP addresses or domain names')
    parser.add_argument('-p', '--port-range', default='1-100', help='range of ports to scan (e.g. 1-100 or all)')
    parser.add_argument('-T', '--timeout', default=1.0, type=float, help='timeout value in seconds (default: 1.0)')
    parser.add_argument('-n', '--num-threads', default=10, type=int, help='number of threads to use for scanning (default: 10)')
    parser.add_argument('-o', '--output', help='output file to save results to (ex. output.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    args = parser.parse_args()

    # Alvos especificos
    for target in args.targets:
        all_open_ports = scan_targets([target], args.port_range, args.timeout, socket.SOCK_STREAM, args.output)

        # Mostra ou salva o resultado
        if len(all_open_ports) > 0:
            # Porta aberta mostra em verde
            open_ports_str = ', '.join([str(port) for port in all_open_ports])
            print(colored(f"\n[+] Portas abertas em {target}: {open_ports_str}", "green"))
            if args.output:
                # Se a saida for especificada, grava o resultado nele
                with open(args.output, 'a') as f:
                    output = {
                        'target': target,
                        'open_ports': all_open_ports
                    }
                    json.dump(output, f)
        else:
            # Sem porta aberta mostra em vermelho
            print(colored(f"\n[-] Sem portas abertas em: {target}.", "red"))
            if args.output:
                # Se a saida for especificada, grava o resultado nele
                with open(args.output, 'a') as f:
                    output = {
                        'target': target,
                        'open_ports': []
                    }
                    json.dump(output, f)

    if args.output:
        # Resultados salvos no arquivo
        print(colored(f"\n[+] Resultado salvo em: {args.output}", "green"))
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Scan interrompido por ação do usuário")
    except:
        print("Um erro ocorreu ao escanear as portas")