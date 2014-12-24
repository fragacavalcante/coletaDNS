# coding: utf-8

import requests 
import Queue
import time
from datetime import date
from datetime import datetime

def baixa_evidencia_site(ip, fqdn):
    url ='http://' + str(ip) + '/CFI/'
    headers = {'Host': str(fqdn)}
    resposta = requests.get(url, headers=headers)
    with open(str(ip) + '-' + str(fqdn) + '.html', 'w') as f:
    	f.write(resposta.text.encode('ISO-8859-1'))

#baixa_evidencia_site('37.49.224.111', 'www.bb.com.br')


def enche_fila():
    global fila_ips_dns
    fila_ips_dns = Queue.Queue()
    arquivo_dns_ips = open(
                            'D:\\projetos_python\\coletaDNS\\arquivos para consutas\\lista_ip_dns_refinada.txt', 'r')
    
    dns_ips = [ip.rstrip('\n') for ip in arquivo_dns_ips]
    arquivo_dns_ips.close()

    for ip in dns_ips:
        fila_ips_dns.put(ip)

    while True:
     	item = fila_ips_dns.get()
     	print (item)

def verifica_acesso_internet():
    url ='http://www.google.com.br'   
    mensagem_erro = "erro na comunicação com a Internet"
    while True:
        try:
            resposta = requests.get(url)           
        except requests.ConnectionError:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            time.sleep(20)
            continue
        except requests.HTTPError:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            time.sleep(20)
            continue

        if resposta.status_code == requests.codes.ok :
            pass    
        else:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            time.sleep(20)
            continue
            

def grava_arquivo_status_internet(texto):
	data_hora = str(datetime.now())
	nome_arquivo = str(date.today()) + '-' + 'status_conexao.txt'

	with open( nome_arquivo, 'a+' ) as f:
		f.write(data_hora + '-' + texto + '\n')


#baixa_evidencia_site('201.18.18.94','web.bndes.gov.br')
verifica_acesso_internet()

#enche_fila()

