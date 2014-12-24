# coding: utf-8
# Coleta de Servidores DNS
import dns.resolver
import dns.exception
import dns.query
import threading
import requests
import Queue
import time
from datetime import date
from datetime import datetime

registros_verificados = 0
andamento_verificacao = 0
total_ip_dns = 0
contador_status_conexao = 0

fila_ips_dns = Queue.Queue()
lock = threading.Lock()

def gerencia_verificacao():
    global total_ip_dns
# Lê arquivo com endereços IPs dos servidores DNS que serão consultados e
# adiciona em uma lista

# Define o total de  threads que será criada e a quantidade de ips por
# thread que serão verificados
    tamanho_fila = popula_fila()
    total_ip_dns = tamanho_fila
    total_thread = 100
    contador_thread = 0

    t2 = threading.Thread(name='Thread_verifica_acesso', target=verifica_acesso_internet)
    t2.start()

    for i in range(total_thread):
        contador_thread += 1
        t1 = threading.Thread(name='Thread' + str(contador_thread), target=verifica_servidores_dns)
        t1.start()
    

def popula_fila():
    global fila_ips_dns
    fila_ips_dns = Queue.Queue()
    arquivo_dns_ips = open(
                            'D:\\projetos_python\\coletaDNS\\arquivos para consutas\\lista_ip_dns_refinada.txt', 'r')   
    dns_ips = [ip.rstrip('\n') for ip in arquivo_dns_ips]
    arquivo_dns_ips.close()

    for ip in dns_ips:
        fila_ips_dns.put(ip)

    return fila_ips_dns.qsize()


def verifica_servidores_dns():    
    global lock
    global registros_verificados
    global contador_status_conexao

    # Lê arquivo com os FQDNs que serão consultados juntamente com o endereço(s) IPs relacionados
    # Transformar em um dicionário onde a chave é o fqdn e as tuplas são os
    # IPs dos servidores DNS
    
    arquivo_fqdn_ips = open(
        'D:\\projetos_python\\coletaDNS\\arquivos para consutas\\listafqdn.txt', 'r')
    fqdn_ips = [ip.rstrip('\n') for ip in arquivo_fqdn_ips]
    arquivo_fqdn_ips.close()

# Transforma ips dos FQDNs em um conjunto que será utilizado para validar
# se existe dns spoofados
    fqdn_definido = str(fqdn_ips[0]).split(',')[0]
    conjunto_ip_fqdn_definido = set(str(fqdn_ips[0]).split(',')[1:])

    conf_dns = dns.resolver.Resolver()

    # CONFIGURAÇÃO DE TEMPO DE RESPOSTA PARA CONSULTAS DNS
    conf_dns.timeout = 2
    conf_dns.lifetime = 2

    # Realiza a consulta DNS para cada servidor DNS informado e guarda o resultado
    # Para posterior comparação com os ips legítimos dos FQDNs

    while True:
        ip_dns = (fila_ips_dns.get())
        fila_ips_dns.task_done()
        lock.acquire()
        registros_verificados += 1
        andamento_verificacao = int(registros_verificados / float(total_ip_dns) * 100)
        print ('Andamento: ' + str(registros_verificados) + ' de: ' + str(total_ip_dns)
                + '---' + str(andamento_verificacao) + '%')
        lock.release()

        if contador_status_conexao >= 5:
            return -1
        
        if fila_ips_dns.empty():
            return 1            

        for linha_fqdn in fqdn_ips:
            fqdn_definido = str(linha_fqdn).split(',')[0]
            conjunto_ip_fqdn_definido = set(str(linha_fqdn).split(',')[1:])

            try:
                # DEFINE O HIPOTÉTICO SERVIDOR DNS QUE SERÁ CONSULTADO
                conf_dns.nameservers = [ip_dns]
                # REALIZA A BUSCA. FQDN FOI RECEBIDO PELA FUNÇÃO.
                resposta = conf_dns.query(fqdn_definido, 'A')
                ips_resposta = ["".join(str(i).split(':')) for i in resposta]
                conjunto_ips_reposta = set(ips_resposta)
                resultado_verificacao_consulta_dns = conjunto_ips_reposta.difference(
                                                     conjunto_ip_fqdn_definido)

                if resultado_verificacao_consulta_dns:
                    baixa_evidencia_site(list(ips_resposta)[0], fqdn_definido, lock)
                    grava_informacoes_dns(ip_dns, fqdn_definido, ips_resposta, lock)
                # Verifica se a reposta contém registros possivelmente maliciosos            
                    print resultado_verificacao_consulta_dns
                    print "Consistência encontrada"                

            except dns.resolver.NXDOMAIN:
                grava_arquivo_resultado_consulta(ip_dns, 'NXDOMAIN', lock)                                
            except dns.resolver.Timeout:
                grava_arquivo_resultado_consulta(ip_dns, 'TIMEOUT', lock)                
                break
            except dns.resolver.NoNameservers:
                grava_arquivo_resultado_consulta(ip_dns, 'NONAMESERVERS', lock)                
            except dns.exception.DNSException, erro:
                grava_arquivo_resultado_consulta(ip_dns, 'OUTROSERROS', lock)


def baixa_evidencia_site(ip, fqdn, lock):       
    url ='http://' + str(ip)
    headers = {'Host': str(fqdn)}
    
    try:
        resposta = requests.get(url, headers=headers)
    except requests.ConnectionError:
        return
    except requests.HTTPError:
        return

    if resposta.status_code == requests.codes.ok :
        with open('downloads\\' + str(ip) + '-' + str(fqdn) + '.html', 'w') as f:
            f.write(resposta.content)
    else:
        print "não há nada a baixar"

def grava_informacoes_dns(ip_definido, fqdn, resposta, lock):
    lock.acquire()
    nome_arquivo = str(date.today()) + '-' + str(fqdn) + '-' + 'resultado_validacao_dns.txt'
    print str(threading.currentThread()) + ip_definido + "Gravando arquivo"
    resultado_consuta_ips = open(nome_arquivo, 'a+')
    resultado_consuta_ips.writelines(ip_definido)
    resultado_consuta_ips.writelines(",")
    resultado_consuta_ips.writelines(fqdn)
    resultado_consuta_ips.writelines(",")
    resultado_consuta_ips.writelines(str(resposta[0:]))
    resultado_consuta_ips.writelines("\n")
    resultado_consuta_ips.close()
    lock.release()



def verifica_acesso_internet():
    global contador_status_conexao
    url ='http://www.google.com.br'   
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    mensagem_erro = "erro na comunicação com a Internet"

    while True:
        try:
            resposta = requests.get(url, headers=headers)         

            if contador_status_conexao > 0:
                contador_status_conexao -= 1  
            time.sleep(60)
        except requests.ConnectionError:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            contador_status_conexao += 1
            print contador_status_conexao
            time.sleep(60)            
        except requests.HTTPError:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            contador_status_conexao += 1
            time.sleep(60)

        if contador_status_conexao >= 5:
                return -1


def grava_arquivo_resultado_consulta(ip, texto, lock):
    data_hora = str(datetime.now())
    nome_arquivo = str(date.today()) + '-' + 'resultado_consulta_dns.txt'
    lock.acquire()
    with open( nome_arquivo, 'a+' ) as f:
        f.write(data_hora + ';' + str(ip) + ';' + texto + '\n')
    lock.release()


def grava_arquivo_status_internet(texto):
    data_hora = str(datetime.now())
    nome_arquivo = str(date.today()) + '-' + 'status_conexao.txt'
    with open( nome_arquivo, 'a+' ) as f:
        f.write(data_hora + '-' + texto + '\n')


if __name__ == "__main__":
    gerencia_verificacao()
