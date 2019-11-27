# /usr/local/bin/python3

import requests
import sys
from requests.auth import HTTPBasicAuth
from output import *

url = "http://"+loadBalancerDNS+":5000"  # "http://127.0.0.1:5000"
suffix = "/todo/api/v1.0"
auth = HTTPBasicAuth('miguel', 'python')

print(url+suffix)
#headers = {""}


def listTasks():
    print(url + suffix + '/tasks')
    r = requests.get(url + suffix + '/tasks',
                     auth=auth)
    print(r.text)


def searchTasks(id):
    r = requests.get(url + suffix + '/tasks/' + id,
                     auth=auth)
    print(r.text)


def addTasks(obj):
    r = requests.post(url + suffix + '/tasks',
                      json=obj, auth=auth)
    print(r.text)


def changeTasks(id, obj):
    r = requests.put(url + suffix + '/tasks/' + id,
                     json=obj, auth=auth)
    print(r.text)


def removeTasks(id):
    r = requests.delete(url + suffix + '/tasks/' + id,
                        auth=auth)
    print(r.text)


def healthCheck():
    r = requests.get(url + suffix + '/',
                     auth=auth)
    print(r.text)


def showHelp():
    print("""

    Comandos disponíveis
    – $ tarefa adicionar [lista de valores dos atributos da classe]
    – $ tarefa listar
    – $ tarefa buscar
    – $ tarefa apagar
    – $ tarefa atualizar [lista de valores dos atributos da classe]
    – $ tarefa saude
    """)


if __name__ == '__main__':

    call = sys.argv[1]

    # Listar
    if call == "listar":
        listTasks()

    # Buscar
    elif call == "buscar":
        try:
            searchTasks(sys.argv[2])
        except:
            print("Erro de parse")
            showHelp()

    # Adicionar
    elif call == "adicionar":
        try:
            title = sys.argv[2]
            description = sys.argv[3]
            obj = {"title": title,
                   "description": description
                   }

            addTasks(obj)

        except:
            print("Erro de parse")
            showHelp()

    # Atualizar
    elif call == "atualizar":
        try:
            id = sys.argv[2]
            title = sys.argv[3]
            description = sys.argv[4]
            done = sys.argv[5]
            obj = {"title": title,
                   "description": description,
                   "done": done == 'True',
                   }

            changeTasks(id, obj)

        except:
            print("Erro de parse")
            showHelp()

    # Apagar
    elif call == "apagar":
        try:
            removeTasks(sys.argv[2])
        except:
            print("Erro de parse")
            showHelp()

    # Saude
    elif call == "saude":
        healthCheck()

    else:
        showHelp()
