#coding: utf-8

# Coleta de endereços IPs separados por país
# A coleta é realizada no Whois da LACNIC utilizando números de Sistema Autonômo
# Os dados são tratados e gravados em um arquivo CSV
# Dados gravados: AS, Entidade, Operador, Faixa IP, país, status
# O processo é realizado através do WebServices RestFul

import json
import requests
import time
import random
import os


def extraiIP():       
    j = 1
    start_time = time.time()
    #inicio=52000
    inicio=53659
    fim=1

    # Busca AS 16 bits
    
    for i in range(inicio,fim,-1):
        URL_LACNIC_BUSCA_AS = "http://restfulwhoisv2.labs.lacnic.net/restfulwhois/autnum/" + str(i) + "/"

    #Consulta LACNIC utilizando AS (Sistemas Autonomous)
        j+=1
        elapsed_time = time.time() - start_time
        print str(j) + "-" + str(i) + "-" + str(elapsed_time)
                                   
        headers = {'Accept': 'application/json'}
        
        try:
            resposta = requests.get(URL_LACNIC_BUSCA_AS, headers=headers)              

            resultado_analise_resposta = analisa_manipula_resposta(resposta)
            
            if resultado_analise_resposta == 0:
                continue
            elif resultado_analise_resposta > 1:
                time.sleep(resultado_analise_resposta)
                resposta = requests.get(URL_LACNIC_BUSCA_AS, headers=headers)
                resultado_analise_resposta = analisa_manipula_resposta(resposta)
                
                if resultado_analise_resposta == 0 or resposta.status_code > 1:
                    continue
                else:
##                  trata_resposta_json('AS', resposta):
                    resposta_json = json.loads(resposta.content)  
            else:
##                trata_resposta_json('AS', resposta):
                resposta_json = json.loads(resposta.content)
           
            AS = str(resposta_json['startAutnum']) + "-" + str(resposta_json['endAutnum'])
            pais = str(resposta_json['country'])
            status = str(resposta_json['status']).strip('[').strip(']').strip('\'')
            operador = str(resposta_json['entities'][0]['vcardArray'][1][5][3]).strip('[').strip(']').strip('\'')
            entidade_tmp = resposta_json['entities'][0]['links'][0]['value']
            entidade=str((entidade_tmp.split("/"))[-1])


            URL_LACNIC_BUSCA_IP = "http://restfulwhoisv2.labs.lacnic.net/restfulwhois/entity/" + entidade + "/ip"
            resposta = requests.get(URL_LACNIC_BUSCA_IP, headers=headers)
            resultado_analise_resposta = analisa_manipula_resposta(resposta)
             
            if resultado_analise_resposta == 0:
                continue
            elif resultado_analise_resposta > 1:
                time.sleep(resultado_analise_resposta)
                resposta = requests.get(URL_LACNIC_BUSCA_AS, headers=headers)
                resultado_analise_resposta = analisa_manipula_resposta(resposta)
                
                if resultado_analise_resposta == 0 or resposta.status_code > 1:
                    continue
                else:
##                  trata_resposta_json('NET', resposta):
                    resposta_json = json.loads(resposta.content)  
            else:
##                trata_resposta_json('NET', resposta)
                resposta_json = json.loads(resposta.content)
                
            if resposta_json.has_key('network'):       
                faixa_ip_redes = resposta_json['network']
                faixa_ip_redes =  ",".join(faixa_ip_redes)
                print AS, pais, status, operador, entidade, faixa_ip_redes
            else:
                continue      
        except requests.ConnectionError:
            time.sleep(120)
            continue
        
        #Salvar em arquivo
        grava_informacoes_dns(AS, pais, status, operador, entidade, faixa_ip_redes)


def grava_informacoes_dns(AS, pais, status, operador, entidade, faixa_ip_redes):
    arquivo_redes_ip_coletadas = open("ips_redes_pais_lacnic.txt","a+")
    arquivo_redes_ip_coletadas.writelines(AS + "," + pais + "," + status + "," + operador + "," + entidade + "|")
    arquivo_redes_ip_coletadas.writelines(faixa_ip_redes)    
    arquivo_redes_ip_coletadas.writelines("\n")
    arquivo_redes_ip_coletadas.close()


def analisa_manipula_resposta(resposta):   
    if resposta.status_code == 404:
        return 0
    elif resposta.status_code == 429:
        arquivo_tempo_aguardar_api_lacnic = open("tempo_aguardar_api_lacnic.txt","a+")
        arquivo_tempo_aguardar_api_lacnic.writelines(resposta.content)
        arquivo_tempo_aguardar_api_lacnic.close()
        
        arquivo_tempo_aguardar_api_lacnic = open("tempo_aguardar_api_lacnic.txt","r")
        tempo_aguardar_api = arquivo_tempo_aguardar_api_lacnic.readline()
        print tempo_aguardar_api
        tempo_aguardar_api = tempo_aguardar_api.split(',')[3].split()[1]
        tempo_aguardar_api = int(tempo_aguardar_api) + 1       
        print tempo_aguardar_api               
        print resposta.content
        arquivo_tempo_aguardar_api_lacnic.close()        
        os.remove("tempo_aguardar_api_lacnic.txt")
        return int(tempo_aguardar_api)*60                           
    else:
        return 1   

##def gera_arquivo_network_ip(arquivo_redes_ip_coletadas):
##
##    arquivo_redes_ip_coletadas = open(arquivo,'r')
##    linha = arquivo_redes_ip_coletadas.readline()
##    print linha
##
##def trata_resposta_json(tipo_resposta_json, resposta):
##    
##    if tipo_resposta_json == 'AS':
##        resposta_json = json.loads(resposta.content)
##        AS = str(resposta_json['startAutnum']) + "-" + str(resposta_json['endAutnum'])
##        pais = str(resposta_json['country'])
##        status = str(resposta_json['status']).strip('[').strip(']').strip('\'')
##        operador = str(resposta_json['entities'][0]['vcardArray'][1][5][3]).strip('[').strip(']').strip('\'')
##        entidade_tmp = resposta_json['entities'][0]['links'][0]['value']
##        entidade=str((entidade_tmp.split("/"))[-1])
##        return (codigo_retorno, AS, pais, status, operador, entidade)
##    
##    elif tipo_resposta_json == 'NET':
##        if resposta_json.has_key('network'):       
##            faixa_ip_redes = resposta_json['network']
##            faixa_ip_redes =  ",".join(faixa_ip_redes)
##            print AS, pais, status, operador, entidade, faixa_ip_redes
##            return (codigo_retorno, faixa_ip_redes)            
##        else:
##            return (codigo_retorno,)
##    else:
##        return (codigo_retorno, )
    

if __name__ == "__main__":
    extraiIP()    
