#!/usr/bin/env python3

import subprocess
import sys
import io
import numpy as np
import pandas as pd

#Интервал времени в секундах деления пакетов
DATE_INTERVAL = 60
#Список конечных параметров для сравнения. В коде почечены темиже числами для ориентирования
FEATURES = [
    'client_package_size_mean', #1 Средний размер пакета от клиента
    'client_package_size_std', #2 Среднеквадратическое отклонение размера пакета от клента
    'server_package_size_mean', #3 Средний размер пакета от сервера
    'server_package_size_std', #4 Среднеквадратическое отклонение размера пакета от сервера
    'client_batch_sizes_mean',z #5 Средний размер партии данных от клиента
    'client_batch_sizes_std', #6 Среднеквадратическое отклонение размера партии данных от клента
    'server_batch_sizes_mean', #7 Средний размер партии данных от сервера
    'server_batch_sizes_std', #8 Среднеквадратическое отклонение размера партии данных от сервера
    'client_batch_counts_mean', #9 Среднее количество пакетов в партии от клиента --------------------
    'server_batch_counts_mean', #10 Среднее количество пакетов в партии от сервера
    'client_efficiency', #11
    'server_efficiency', #12
    'ratio_sizes', #13
    'ratio_application_size', #14
    'ratio_packages', #15
    'client_package_size_sum', #16
    'client_application_size_sum', #17
    'client_package_count', #18
    'client_batch_counts_sum', #19
    'server_package_size_sum', #20
    'server_application_size_sum', #21
    'server_package_count', #22
    'server_batch_counts_sum', #23
    'transport_protocol', #24
    'ip_protocol_version', #25
]

def read_pcap_and_return_dataframe(filePath):
    '''
        Рассчитать статистические метрики потока.
        Аргументы:
            filePath - путь к PCAP файлу
        Возвращает:
            Объект Pandas.Dataframe со значениями полученными при экспорте используя tshark.
            Также  локальной директории записывает одноменный PCAP файлу файл csv с анологичными даннными.
    '''
    #Читаем .pcap файл и экспортируем в cvs
    pcapToCVSCom = 'tshark -r '+ filePath + ' -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e frame.len -e ip.version \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.hdr_len -e tcp.hdr_len \
    -E separator=, -E quote=d -E header=y -E occurrence=f'
    proc = subprocess.Popen(pcapToCVSCom.split() + ['-Y', 'ip.proto==6 or ip.proto==17'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = proc.communicate()
    data = ''
    if error:
        sys.exit(error.decode("utf-8")) #или "ISO-8859-1"
    else:
        data = output.decode("utf-8")
        new_file = filePath.split("/")[-1].split(".")
        new_file[-1] = "csv"
        new_file[-2] += "."
        f = open("".join(new_file), "w")
        f.write(output.decode("utf-8"))
        f.close()

    # Чтение csv файлы. В данной случае читается из созданного потока, для чтения файла использовать:
    # traffic = pd.read_csv('./traffic.csv', encoding = "ISO-8859-1", low_memory=False)
    traffic = pd.read_csv(io.StringIO(data), sep=',')
    return traffic

def preprocess_dataframe(traffic):
    '''
        Предобработка данных для заполнения пустых ячеек и расчета необходимах столбцов.
        Аргументы:
            traffic - объект Pandas.Dataframe со след полями: 'frame.time_epoch', 'ip.src, ip.dst', 'ip.proto',
            'frame.len', 'ip.version', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ip.hdr_len', 'tcp.hdr_len'.
        Возвращает:
            Объект Pandas.Dataframe с предобработанными данными
    '''
    #Преобразование портов в один стобец
    traffic['srcport'] = traffic['udp.srcport'].combine(traffic['tcp.srcport'], lambda x,y: x if np.isnan(y) else y).astype(int)
    traffic['dstport'] = traffic['tcp.dstport'].combine(traffic['udp.dstport'], lambda x,y: x if np.isnan(y) else y).astype(int)
    traffic = traffic.drop(['tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport'], axis=1)

     #Получение ip клиента
    clientIP = pd.concat([traffic['ip.src'], traffic['ip.dst']]).value_counts().idxmax()

    #Получение конечных точек (<IP>:<port>) и указание направления трафика для пакета
    traffic['isFromClient'] = traffic['ip.src'] == clientIP
    traffic['src'] = traffic['ip.src'] + ":"  + traffic['srcport'].apply(str)
    traffic['dest'] = traffic['ip.dst'] + ":" + traffic['dstport'].apply(str)
    traffic = traffic.drop(['srcport', 'dstport', 'ip.src', 'ip.dst'], axis=1)

    #Подстановка длины хэддера для UDP
    traffic = traffic.rename(columns={"tcp.hdr_len": "transport_header"})
    traffic.loc[traffic['ip.proto'] == 17, 'transport_header'] = int(8)

    #рассчет прикладной нагрузки пакета
    traffic['application_size'] = traffic['frame.len'] - 14 - traffic['ip.hdr_len'] - traffic['transport_header']

    #Преобразование UNIX-времени к pandas.datetime64 группировка с интервалом DATE_INTERVAL секунд
    traffic['frame.time_epoch'] = pd.to_datetime(traffic['frame.time_epoch'], unit='s')

    return traffic

def group_by_time_intervals_and_route(traffic):
    '''
        Предобработка данных для заполнения пустых ячеек и расчета необходимах столбцов.
        Аргументы:
            traffic - объект Pandas.Dataframe со след полями: 'frame.time_epoch'  'ip.proto'  'frame.len'
            'ip.version''ip.hdr_len' 'transport_header'  'isFromClient' 'src' 'dest' 'application_size'.
        Возвращает:
            Объект массив кортежей (<интервал времени>, <конечные точки>, <пакеты>).
            Пакеты в Pandas.Dataframe с идентичным вхоным полями.
    '''
    intervalledPackeges = list()
    #Делю на интервалы времени с разным смешением. Ниже колличество разнообразные смешений
    intarval_offset_count = 4
    base_delta = DATE_INTERVAL / 4
    for i in range(intarval_offset_count):
        grouped = traffic.groupby(pd.Grouper(freq=str(DATE_INTERVAL) + 'S', key='frame.time_epoch', base=base_delta*i))
        for key, _ in grouped:
            intervalledPackeges.append((key, grouped.get_group(key)))

    #Разделение пакетов в каждом интервале на потоки (пакеты между двумя конечными точками)
    intervalledFlows = []
    for timeGroup in intervalledPackeges:
        grouped = timeGroup[1].groupby(['src', 'dest'])
        finallMap = {}
        for key, dataframe in grouped:
            route = frozenset(key)
            if route in finallMap:
                finallMap[route] = pd.concat([finallMap[route], dataframe])
            else:
                finallMap[route] = dataframe
        intervalledFlows.append((timeGroup[0], finallMap))

    #Выпрямление стркутуры хранения, чтобы хранить все датасеты в массиве кортежей
    #Кортеж (<интервал времени>, <конечные точки>, <пакеты>)
    allFlowsList = []
    for intervals in intervalledFlows:
        for flowName in intervals[1]:
            allFlowsList.append((intervals[0], flowName, intervals[1][flowName]))

    return allFlowsList

def getStatisticDataFromFlow(flow_data):
    flow = flow_data[2].sort_values(by='frame.time_epoch', ascending=True)
    statistic_data = {}

    #Пакетовые показатели клиента
    client_flow = flow[flow['isFromClient'] == True]
    statistic_data['client_package_size_mean'] = client_flow['frame.len'].mean()#1
    statistic_data['client_package_size_std'] = client_flow['frame.len'].std()#2
    statistic_data['client_package_size_sum'] = client_flow['frame.len'].sum()#16
    statistic_data['client_application_size_sum'] = client_flow['application_size'].sum() if  client_flow['application_size'].sum() != 0 else 1#17
    statistic_data['client_package_count'] = client_flow.shape[0]#18
    if statistic_data['client_package_count'] < 6:
        return
    statistic_data['client_efficiency'] = statistic_data['client_application_size_sum'] / statistic_data['client_package_size_sum']#11

    #Пакетовые показатели сервера
    server_flow = flow[flow['isFromClient'] == False]
    statistic_data['server_package_size_mean'] = server_flow['frame.len'].mean()#3
    statistic_data['server_package_size_std'] = server_flow['frame.len'].std()#4
    statistic_data['server_package_size_sum'] = server_flow['frame.len'].sum()#20
    statistic_data['server_application_size_sum'] = server_flow['application_size'].sum() if  server_flow['application_size'].sum() != 0 else 1#21
    statistic_data['server_package_count'] = server_flow.shape[0]#22
    if statistic_data['server_package_count'] < 6:
        return
    statistic_data['server_efficiency'] = statistic_data['server_application_size_sum'] / statistic_data['server_package_size_sum']#12


    #Пакетовые показатели отношения клиент к сервер
    statistic_data['ratio_sizes'] = statistic_data['client_package_size_sum'] / statistic_data['server_package_size_sum']#13
    statistic_data['ratio_application_size'] = statistic_data['client_application_size_sum'] / statistic_data['server_application_size_sum'] #14
    statistic_data['ratio_packages'] = statistic_data['client_package_count'] / statistic_data['server_package_count']#15

    statistic_data['transport_protocol'] = flow['ip.proto'].value_counts().idxmax()#24
    statistic_data['ip_protocol_version'] = flow['ip.version'].value_counts().idxmax()#25


    #Расчет партий(batch) пакетов
    #batch_conf = (<количество полезных(имеющих прикладную нагрузку) пакетов>, <суммарный размер пакетов в партии>)
    isClientSender = flow['isFromClient'].iloc[0]
    client_batches = []
    server_batches = []
    current_batch_size = 0
    current_useful_package_count = 0
    for index, row in flow.iterrows():

        #Нет полезной нагрузки
        if row['application_size'] == 0:
            continue

        #Направление нагрузки не изменилось
        if row['isFromClient'] == isClientSender:
            current_batch_size += row['frame.len']
            current_useful_package_count += 1
            continue

        #Направление нагрузки изменилось, поэтому записываем и подготоваливаем счетчики
        batch_conf = (current_useful_package_count, current_batch_size)
        client_batches.append(batch_conf) if isClientSender else server_batches.append(batch_conf)
        current_batch_size = row['frame.len']
        current_useful_package_count = 1
        isClientSender = row['isFromClient']
    batch_conf = (current_useful_package_count, current_batch_size)
    client_batches.append(batch_conf) if isClientSender else server_batches.append(batch_conf)

    #Перевод в массивы numpy.array для статистических расчетов
    client_batches_countes = np.array(list(map(lambda x: x[0], client_batches)))
    client_batches_sizes = np.array(list(map(lambda x: x[1], client_batches)))
    server_batches_countes = np.array(list(map(lambda x: x[0], server_batches)))
    server_batches_sizes = np.array(list(map(lambda x: x[1], server_batches)))

    #Партийные метрики клиента
    statistic_data['client_batch_sizes_mean'] = client_batches_sizes.mean()#5
    statistic_data['client_batch_sizes_std'] = client_batches_sizes.std()#6
    statistic_data['client_batch_counts_mean'] = client_batches_countes.mean()#9
    statistic_data['client_batch_counts_sum'] = len(client_batches_countes)#19

    #Партийные метрики сервера
    statistic_data['server_batch_sizes_mean'] = server_batches_sizes.mean()#7
    statistic_data['server_batch_sizes_std'] = server_batches_sizes.std()#8
    statistic_data['server_batch_counts_mean'] = server_batches_countes.mean()#10
    statistic_data['server_batch_counts_sum'] = len(server_batches_countes)#23

    #Создает массив со всеми параметрами потока ля конечного датасета
    df_row = [flow_data[1], flow_data[0]]
    for name in FEATURES:
        df_row.append(statistic_data[name])
    return df_row

def main():
    pcap_file_path = sys.argv[1] if len(sys.argv) > 1 else sys.exit('No file name: plese enter input PCAP file name')
    dataframe = read_pcap_and_return_dataframe(pcap_file_path)
    preprocessed_dataframe = preprocess_dataframe(dataframe)
    interval_flowed_packages = group_by_time_intervals_and_route(preprocessed_dataframe)

    df = pd.DataFrame(columns= ['route', 'timestamp'] + FEATURES)
    for i, flow in enumerate(interval_flowed_packages):
        stats = None
        stats = getStatisticDataFromFlow(flow)
        if stats:
            df.loc[i] = getStatisticDataFromFlow(flow)
    df = df.fillna(0)

    #saving prepared data
    dataframe_file = pcap_file_path.split("/")[-1].split(".")
    dataframe_file[-1] = "pkl"
    dataframe_file[-2] += "."
    df.to_pickle("".join(dataframe_file))

if __name__ == "__main__":
    main()