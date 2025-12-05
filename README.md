# IPLookup Studio

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green)]()
[![Status](https://img.shields.io/badge/Status-Stable-success)]()

Ferramenta desktop desenvolvida em Python e Tkinter para análise
completa de IPs e hostnames, incluindo:

-   Validação de IP (IPv4 e IPv6)
-   Resolução DNS (A/AAAA)
-   DNS reverso
-   Consulta ASN e Geolocalização via ip-api
-   Identificação de propriedades do IP (privado, reservado, global,
    classe)
-   Histórico persistente em JSON
-   Exportação do resultado em arquivo .txt

## Recursos Principais

### 1. Validação de Entrada

-   Verifica se o texto é um IP válido (IPv4/IPv6).
-   Caso não seja IP, tenta resolver como hostname.
-   Usa socket.getaddrinfo para DNS A/AAAA.

### 2. DNS Reverso

-   Executado localmente via socket.gethostbyaddr.
-   Retorna o PTR se disponível.

### 3. Geolocalização e ASN

Consulta realizada via:

    http://ip-api.com/json/{ip}?fields=status,message,query,reverse,country,regionName,city,isp,as,org,zip,lat,lon,timezone,query

Retorna: - País, região, cidade - Latitude/Longitude - Fuso horário -
ISP e Organização - ASN - Reverse DNS retornado pela API

### 4. Dados sobre o IP

-   Versão IP (4 ou 6)
-   Se é privado, reservado ou global
-   Classe de IP (A/B/C) quando IPv4

### 5. Histórico de Consultas

-   Armazenado em JSON
-   Limitado a 200 entradas
-   Exportável para arquivo externo

### 6. Interface Gráfica

-   Tkinter + ttk
-   Campo de entrada
-   Área de resultado com rolagem
-   Botões de consulta, limpar, exportar e histórico

## Execução

    python teste.py

## Licença

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

