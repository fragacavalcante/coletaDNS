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
import os

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

    t1 = threading.Thread(name='Thread_verifica_acesso', target=verifica_acesso_internet)
    t1.start()

    for i in range(total_thread):
        contador_thread += 1
        t2 = threading.Thread(name='Thread' + str(contador_thread), target=verifica_servidores_dns)
        t2.start()
    
    return 0

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
        # if fila_ips_dns.empty():
        #     print "Aguarde 1 minutos para todas as threads serem encerradas adequadamente"            
        #     return -1         

        try:
            ip_dns = (fila_ips_dns.get(False))
            fila_ips_dns.task_done()
        except Queue.Empty:
            print "Aguarde 1 minutos para todas as threads serem encerradas adequadamente"            
            return -1
        
        if contador_status_conexao >= 5:
            return -1               

        lock.acquire()
        registros_verificados += 1
        andamento_verificacao = int(registros_verificados / float(total_ip_dns) * 100)
        print ('Andamento: ' + str(registros_verificados) + ' de: ' + str(total_ip_dns)
                + '---' + str(andamento_verificacao) + '%')
        lock.release()

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
            # Verifica se a reposta contém registros possivelmente maliciosos            
                if resultado_verificacao_consulta_dns:
                    baixa_evidencia_site(list(ips_resposta)[0], fqdn_definido, lock)
                    grava_informacoes_dns(ip_dns, fqdn_definido, ips_resposta, lock)            

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
    diretorio_resultados = 'Resultado Consultas\\' + str(date.today()) + '\\'

    url ='http://' + str(ip)
    headers = {'Host': str(fqdn)}
    
    try:
        resposta = requests.get(url, headers=headers)
    except requests.ConnectionError:
        return
    except requests.HTTPError:
        return

    if resposta.status_code == requests.codes.ok :
        with open(diretorio_resultados + str(ip) + '-' + str(fqdn) + '.html', 'w') as f:
            f.write(resposta.content)

def grava_informacoes_dns(ip_definido, fqdn, resposta, lock):
    diretorio_resultados = 'Resultado Consultas\\' + str(date.today())

    lock.acquire()    
    if not os.path.exists(diretorio_resultados):
        os.makedirs(diretorio_resultados)
    
    nome_arquivo = diretorio_resultados + '\\' + str(date.today()) + '-' + str(fqdn) + '-' + 'resultado_validacao_dns.txt'
    #print str(threading.currentThread()) + ip_definido + "Gravando arquivo"
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

        if fila_ips_dns.empty():
            envia_email()            
            return 1    

        try:
            resposta = requests.get(url, headers=headers)         
            time.sleep(60)

            if contador_status_conexao > 0:
                contador_status_conexao -= 1  
            
        except requests.ConnectionError:
            grava_arquivo_status_internet(mensagem_erro)
            contador_status_conexao += 1
            time.sleep(60)            
        except requests.HTTPError:
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

def envia_email():
    import smtplib

    gmail_user = "teste.professor.claudio@gmail.com"
    gmail_pwd = "colocar senha "
    FROM = 'teste.professor.claudio@gmail.com'
    TO = ['claudio.cavalcante@gmail.com'] #must be a list
    SUBJECT = "Processo de verificação DNS encerrado"
    TEXT = "Processo de verificação DNS encerrado"



    # Prepare actual message
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
    try:
        #server = smtplib.SMTP(SERVER) 
        server = smtplib.SMTP("smtp.gmail.com", 587) #or port 465 doesn't seem to work!
        server.ehlo()
        server.starttls()
        server.login(gmail_user, gmail_pwd)
        server.sendmail(FROM, TO, message)
        #server.quit()
        server.close()
        print 'successfully sent the mail'
    except:
        print "failed to send mail"


if __name__ == "__main__":
    gerencia_verificacao()
