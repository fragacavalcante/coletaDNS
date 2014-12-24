#coding: utf-8

import threading
import dns.resolver
import dns.exception
import dns.query


def gerencia_refina_enderecos_DNS(arquivo_dns_antes_refinamento):
    lock = threading.Lock()
    total_thread = 100

    arquivo_dns_ips = open(arquivo_dns_antes_refinamento,'r')
    dns_ips = [ ip.rstrip('\n') for ip in arquivo_dns_ips ]
    arquivo_dns_ips.close()

## Cria 256 threads para fazer a validação
    divisao_endereco_lista_dns_ips = len(dns_ips)/total_thread

    contador_thread = 0    

    for i in range(total_thread):
        contador_thread += 1
        inicio = i *  divisao_endereco_lista_dns_ips
        fim = (i + 1) * divisao_endereco_lista_dns_ips
        lista_item_buscar = (dns_ips[ inicio : fim ], lock)
        t = threading.Thread(name='Thread' + str(contador_thread), target=refina_enderecos_DNS,
                             args = lista_item_buscar)
        t.start()   

def refina_enderecos_DNS(dns_ips, lock):
    conf_dns = dns.resolver.Resolver()   
    
    #CONFIGURAÇÃO DE TEMPO DE RESPOSTA PARA CONSULTAS DNS
    conf_dns.timeout = 0.4
    conf_dns.lifetime = 0.5

    fdqn_fake = 'www.teste123zxc.com.br'

    for dns_definido in dns_ips:
        lock.acquire()
        print dns_definido
        lock.release()             
        
        try:
            conf_dns.nameservers = [ dns_definido ] # DEFINE O HIPOTÉTICO SERVIDOR DNS QUE SERÁ CONSULTADO
            resposta = None                
            resposta_teste_fake = conf_dns.query( fdqn_fake, 'A')
            if resposta_teste_fake:                    
                continue               
        except dns.resolver.NXDOMAIN:
            grava_informacoes_dns(dns_definido, lock)

        except dns.resolver.Timeout:
            continue            

        except dns.resolver.NoNameservers:          
            grava_informacoes_dns(dns_definido, lock)

        except dns.exception.DNSException, erro:       
            continue


def grava_informacoes_dns(dns_definido, lock):  
    lock.acquire()
    print str(threading.currentThread()) + dns_definido + "Gravando arquivo"
    resultado_consuta_ips = open('lista_ip_dns_refinada.txt', 'a+')
    resultado_consuta_ips.writelines(dns_definido)
    resultado_consuta_ips.writelines("\n")    
    resultado_consuta_ips.close()   
    lock.release()

if __name__ == "__main__":
    gerencia_refina_enderecos_DNS('D:\\projetos_python\\coletaDNS\\arquivos para consutas\\listadns.txt')    
    