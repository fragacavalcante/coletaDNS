#coding: utf-8
#Coleta de Servidores DNS
import dns.resolver
import dns.exception
import dns.query
import threading
import time

inicio_time = time.time()

#FAIXA_IP_LACNIC = [ '155.211/16','150.92/16','152.84/16','150.165/16','150.164/16','150.163/16','150.162/16','150.161/16','147.65/16','146.164/16','146.134/16','143.106/15', '143.108/16','139.82/16','143.0/16','177/8','179/8','181/8','186/8','187/8','189/8','190/8','191/8','200/8','201/8' ]

def coleta_servidores_dns():   

# VARIAVEL THREADING SERA UTILIZADO EM ALGUNS MOMENTOS PARA BLOQUEAR RECURSOS ACESSADOS PELAS THREADS DA APLICAÇÃO
    lock = threading.Lock()

    range_ip = list()

# DEFINE A RANGE DE ENDEREÇOS QUE SERÃO CONSULTADOS, OS VALORES SÃO COLOCADOS EM UMA LISTA (RANGE_IP).
# A MASCARA DE SUB-REDE, O DOMÍNIO QUE SERÁ CONSULTADO, O TIPO DE CONSULTA JUNTAMENTE COM A VARÍAVEL DE BLOQUEIO SÃO INCLUÍDOS.
# O CONTADOR I REPRESENTA O 2º OCTETO DO ENDEREÇO IP.

    for i in range(0, 256):
        ip = '177' + '.' + str(i) + '.' + '0' + '.' + '0'
        item_buscar = (str(ip), 16,'www.google.com.br', 'A', lock)
        range_ip.append(item_buscar)

## GERA UMA THREAD DE BUSCA PARA CADA SUB-REDE, ATRAVÉS DA LISTA RANGE_IP.
    contador_thread = 0    
    for consulta in range_ip:
        contador_thread += 1
        t = threading.Thread(name='Thread' + str(contador_thread), target=consulta_dns, args = consulta)
        t.start()


       
def consulta_dns(ip, mascara, fqdn, tipo_busca, lock):
    global inicio_time


    # DIVISÃO DO ENDEREÇO IP EM OCTETOS
    # DEFINIÇÃO DE BITS DE REDE E BITS DE HOST
    
    QTD_BITS_IPV4 = 32
    bits_parte_rede = mascara
    bits_parte_host = QTD_BITS_IPV4 - bits_parte_rede

    octeto1, octeto2, octeto3, octeto4 = ip.split(".")
    # O SLICE UTILIZADO [2:] TEM COMO OBJETIVO RETIRAR A STRING Ob QUE É ADICIONADA NO MOMENTO DA CONVERSÃO DE DECIMAL PARA BINÁRIO
    # TAMBÉM É UTILIZADO O VALOR 8 NA FUNÇÃO RJUST PARA COMPLEMENTAR A QUANTIDADE DE BITS EM OCTETO, CASO SEJA MENOR QUE 8 DEPOIS DA CONVERSÃO.
    octeto1 = bin(int(octeto1))[2:].rjust(8,'0')
    octeto2 = bin(int(octeto2))[2:].rjust(8,'0')
    octeto3 = bin(int(octeto3))[2:].rjust(8,'0')
    octeto4 = bin(int(octeto4))[2:].rjust(8,'0')

    #DEFINIÇÃO DE QUANTOS ENDEREÇOS IPs SERÃO PROCURADOS NA INTERNET, O CALCULO BASEIA-SE NA QUANTIDADE DE BITS DA PARTE DO HOST.
    quantidade_ips = 2 ** bits_parte_host

    #OBJETO RESPONSÁVEL EM FAZER CONSULTAS AOS SERVIDORES DNS
    conf_dns = dns.resolver.Resolver()
    
    #CONFIGURAÇÃO DE TEMPO DE RESPOSTA PARA CONSULTAS DNS
    conf_dns.timeout = 0.4
    conf_dns.lifetime = 0.5

    #REALIZA A CONSULTA DNS PARA CADA ENDEREÇO IP DEFINIDO
    # É UTILIZADO UMA THREAD PARA CADA REDE IP
    # O ENDEREÇO IP É DEFINIDO UTILIZANDO OS OCTETOS DO ENDEREÇO IP RECEBIDO (IP REDE) NESTA FUNÇÃO E SOMADOS DE FORMA INCREMENTAL.
    for i in range(quantidade_ips):
        endereco_ip_bits = bin(i)[2:].rjust(32,'0') # UTILIZADO PARA TRANSFORMAR UM VALOR DECIMAL EM NÚMERO BINÁRIO DE 32 BITS.
        octeto1t = int(octeto1, 2) + int(endereco_ip_bits[0:8], 2) 
        octeto2t = int(octeto2, 2) + int(endereco_ip_bits[8:16], 2)
        octeto3t = int(octeto3, 2) + int(endereco_ip_bits[16:24], 2)
        octeto4t = int(octeto4, 2) + int(endereco_ip_bits[24:32], 2)
        ip_definido = str(octeto1t) + '.' + str(octeto2t) + '.' + str(octeto3t) + '.' + str(octeto4t) # O IP QUE SERÁ CONSULTADO
        
        lock.acquire()     
        print str(threading.currentThread()) + ip_definido
        lock.release()
        
        try:            
            conf_dns.nameservers=[ ip_definido ] # DEFINE O HIPOTÉTICO SERVIDOR DNS QUE SERÁ CONSULTADO
            resposta = conf_dns.query(fqdn, tipo_busca) # REALIZA A BUSCA. FQDN FOI RECEBIDO PELA FUNÇÃO.            
            grava_informacoes_dns(ip_definido, fqdn, resposta, lock) # ENVIA VARIAVEL LOCK QUE SERÁ UTILIZADO PARA BLOQUEAR O ACESSO AO ARQUIVO
        except dns.resolver.NXDOMAIN:           
##            print (u"Consulta a um DNS publico sobre uma zona ou fqdn que não existe")          
            grava_informacoes_dns(ip_definido, fqdn, "Servidor público - Zona não existe",lock)            
        except dns.resolver.Timeout:
            pass
##            print (u"Servidor não existe ou não respondeu dentro do tempo definido")
        except dns.resolver.NoNameservers:          
##            print (u"Consulta a um DNS privado sobre uma zona ou fqdn para qual le não é autoritativo")           
            grava_informacoes_dns(ip_definido, fqdn, "Servidor privado - não é autoritativo para a zona",lock)           
        except dns.exception.DNSException, erro:
            lock.acquire() 
            print ("Outros erros DNS %s" % str(erro))
            lock.release()
            
    fim_time = time.time() - inicio_time       
    print (u"Coleta concluída")
    print (str(fim_time))
  
def grava_informacoes_dns(ip_definido, fqdn, resposta,lock):
    lock.acquire()
    print str(threading.currentThread()) + ip_definido + "Gravando arquivo"
    resultado_consuta_ips = open('resultado_consulta_ips_177.txt', 'a+')
    resultado_consuta_ips.writelines(ip_definido)
    resultado_consuta_ips.writelines(",")
    resultado_consuta_ips.writelines(fqdn)
    resultado_consuta_ips.writelines(",")
    resultado_consuta_ips.writelines(str(resposta[0:]))
    resultado_consuta_ips.writelines("\n")    
    resultado_consuta_ips.close()
    lock.release()

if __name__ == "__main__":
    coleta_servidores_dns()
    
