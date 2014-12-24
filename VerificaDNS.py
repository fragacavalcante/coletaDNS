# coding: utf-8
# Coleta de Servidores DNS
import dns.resolver
import dns.exception
import dns.query
import threading
import requests
from datetime import date
import time
from datetime import datetime

registros_verificados = 0

def gerencia_verificacao():
    lock = threading.Lock()

# Lê arquivo com endereços IPs dos servidores DNS que serão consultados e
# adiciona em uma lista
    arquivo_dns_ips = open(
        'D:\\projetos_python\\coletaDNS\\arquivos para consutas\\lista_ip_dns_refinada.txt', 'r')
    dns_ips = [ip.rstrip('\n') for ip in arquivo_dns_ips]
    arquivo_dns_ips.close()

# Define o total de  threads que será criada e a quantidade de ips por
# thread que serão verificados
    total_thread = 500
    divisao_endereco_thread = len(dns_ips) / total_thread
    resto_endereco_thread = len(dns_ips) % total_thread
    
    contador_thread = 0
    for i in range(total_thread):
        contador_thread += 1
        inicio = i * divisao_endereco_thread
        fim = (i + 1) * divisao_endereco_thread
        item_buscar = (dns_ips[inicio : fim], lock)
        t1 = threading.Thread(name='Thread' + str(contador_thread), target=verifica_servidores_dns,
                             args=item_buscar)
        t1.start()

    print "Verificar o resto"
    
    if resto_endereco_thread > 0:
        inicio = total_thread * divisao_endereco_thread
        fim = total_thread * divisao_endereco_thread + resto_endereco_thread
        item_buscar = (dns_ips[inicio: fim], lock)
        t2 = threading.Thread(name='Thread' + str(contador_thread), target=verifica_servidores_dns,
                             args=item_buscar)
        t2.start()

    t3 = threading.Thread(name='Thread_verifica_acesso', target=verifica_acesso_internet)
    t3.start()


def verifica_servidores_dns(dns_ips, lock):
    global registros_verificados
    # Lê arquivo com os FQDNs que serão consultados juntamente com o endereço(s) IPs relacionados
    # Transformar em um dicionário onde a chave é o fqdn e as tuplas são os
    # IPs dos servidores DNS
    arquivo_fqdn_ips = open(
        'D:\\projetos_python\\coletaDNS\\arquivos para consutas\\listafqdn.txt', 'r')
    fqdn_ips = [ip.rstrip('\n') for ip in arquivo_fqdn_ips]
    arquivo_fqdn_ips.close()

    # Transforma ips dos FQDNs em um conjunto que será utilizado para validar
    # se existe dns spoofados

    conf_dns = dns.resolver.Resolver()

    # CONFIGURAÇÃO DE TEMPO DE RESPOSTA PARA CONSULTAS DNS
    conf_dns.timeout = 2
    conf_dns.lifetime = 2

    # Realiza a consulta DNS para cada servidor DNS informado e guarda o resultado
    # Para posterior comparação com os ips legítimos dos FQDNs

    for dns_definido in dns_ips:
        lock.acquire()
        print dns_definido
        print registros_verificados
        registros_verificados += 1
        lock.release()

        for linha_fqdn in fqdn_ips:
            fqdn_definido = str(linha_fqdn).split(',')[0]
            conjunto_ip_fqdn_definido = set(str(linha_fqdn).split(',')[1:])

            try:
                # DEFINE O HIPOTÉTICO SERVIDOR DNS QUE SERÁ CONSULTADO
                conf_dns.nameservers = [dns_definido]
                # REALIZA A BUSCA. FQDN FOI RECEBIDO PELA FUNÇÃO.
                resposta = conf_dns.query(fqdn_definido, 'A')
                ips_resposta = ["".join(str(i).split(':')) for i in resposta]
                conjunto_ips_reposta = set(ips_resposta)
                resultado_verificacao_consulta_dns = conjunto_ips_reposta.difference(
                                                     conjunto_ip_fqdn_definido)

                if resultado_verificacao_consulta_dns:
                    baixa_evidencia_site(list(ips_resposta)[0], fqdn_definido, lock)
                    grava_informacoes_dns(dns_definido, fqdn_definido, ips_resposta, lock)
                # Verifica se a reposta contém registros possivelmente maliciosos            
                    print resultado_verificacao_consulta_dns
                    print "Consistência encontrada"                

            except dns.resolver.NXDOMAIN:
                grava_arquivo_resultado_consulta(dns_definido, 'NXDOMAIN', lock)
                print ('NXDOMAIN')
                pass
            except dns.resolver.Timeout:
                grava_arquivo_resultado_consulta(dns_definido, 'TIMEOUT', lock)
                print('Timeout')
                break
            except dns.resolver.NoNameservers:
                grava_arquivo_resultado_consulta(dns_definido, 'NONAMESERVERS', lock)
                print ('NoNameservers')
                pass
            except dns.exception.DNSException, erro:
                print ("Outros erros DNS %s" % str(erro))
                grava_arquivo_resultado_consulta(dns_definido, 'OUTROSERROS', lock)




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
    url ='http://www.google.com.br'   
    mensagem_erro = "erro na comunicação com a Internet"
    while True:
        try:
            resposta = requests.get(url)           
        except requests.ConnectionError:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            time.sleep(60)
            continue
        except requests.HTTPError:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            time.sleep(60)
            continue

        if resposta.status_code == requests.codes.ok :
            pass    
        else:
            print mensagem_erro
            grava_arquivo_status_internet(mensagem_erro)
            time.sleep(60)
            continue           


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
