# PortScan
A simple Python-based TCP port scanner

# Primeiros Passos

Pre-requisitos:
 - Python 3.x
 - pip

Instalação: 

1. Clone o repositório:
  
```bash
git clone https://github.com/jvcarmona/PortScan.git
```
2. Entre na pasta do projeto

```bash
cd PortScan
```

3. Instale os requisitos

```bash
pip install -r requirements.txt
```

# Como usar

```bash
python portscan.py -t seu_alvo -p <port_range> -T <timeout> -n <threads> -o <output> -v
```

# Opções
 - -t, --targets: Especifique os endereços IP ou o dominio (obrigatório).
 - -p, --port-range: Especifique o intervalo de portas a ser verificado (80, 443, 21, 1-65535). O padrão é 1-100.
 - -T, --timeout: Especifique o valor do tempo limite em segundos. O padrão é 1s.
 - -n, --num-threads: Especifique o número de threads a serem usados. O padrão é 10 threads.
 - -o, --output: Especifique um arquivo de saída para salvar os resultados (Ex: output.json).
 - -v, --verbose: habilita a saída detalhada.


# Exemplos práticos

- Scan básico
```bash
python portscan.py -t https://meu_site.com.br
```

- Multiplos alvos
```bash
python portscan.py -t https://meu_site.com.br 10.10.10.5 -p 1-65535 
```

- Salvando a saida
```bash
python portscan.py -t https://meu_site.com.br -o saida.json
```

- Saida detalhada
```bash
python portscan.py -t https://meu_site.com.br -v
```
