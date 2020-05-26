#!/usr/bin/env python3


from sklearn.model_selection import train_test_split
from sklearn import metrics
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Activation
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.svm import OneClassSVM
import xml.dom.minidom
import os
import io
import pandas as pd
import numpy as np
import subprocess
import sys

#названия файл для хранения тренировочных и тестовых pcap
template_file_name = ".model_packages"

def create_train_and_test_data(file_path):
	file_size = int(os.stat(file_path).st_size/1000)
	pack_count = output.decode("utf-8")
	subprocess.Popen(["tcpdump", "-r", input_packet_capture.pcap, "-w",  template_file_name, "-C", file_size*0.8])

	#Вставка аномальных пакетов
	subprocess.Popen("./id2t", "-i ", template_file_name + "1", "-o", "attacked.pcap", "-a", "EternalBlueExploit",  "ip.src=92.168.178.1", "duration=120")
	subprocess.Popen("./id2t", "-i ", "attacked.pcap" + "1", "-a", "attacked.pcap",  "ip.src=92.168.178.2", "duration=120")
	lastInjection = subprocess.Popen("./id2t", "-i ", "attacked.pcap" + "1", "-a", "attacked.pcap",  "inject.at-timestamp=1589458731", "ip.src=92.168.178.3", "duration=120")

	#Чтение и предобработка тренировочны данных
	proc = subprocess.Popen(["./prepare_data", template_file_name],
							stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output, error = proc.communicate()
	train_data = ''
	if error:
		sys.exit(error.decode("utf-8"))
	else:
		train_data = output.decode("utf-8")

	#Чтение и предобработка тестовых данных
	proc = subprocess.Popen(["./prepare_data", "attacked.pcap"],
							stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output, error = proc.communicate()
	test_data = ''
	if error:
		sys.exit(error.decode("utf-8"))
	else:
		test_data = output.decode("utf-8")
	
	xml_path = lastInjection.communicate()
	xml_path = xml_path.decode("utf-8")
	xml_path = xml_path.split("\n")[-1]
	xml = xml.dom.minidom.parse(xml_path)
	
	return (train_data, test_data, xml)


def autoencoder_calculation(train_data, test_data, y_val)):
	encode_numeric_zscore(train_data)
	encode_numeric_zscore(test_data)

	# Создание модели
	model = Sequential()
	model.add(Dense(25, input_dim=x_normal.shape[1], activation='tanh'))
	model.add(Dense(3, activation='relu'))
	model.add(Dense(25, activation='tanh'))
	model.add(Dense(x_normal.shape[1]))
	model.compile(loss='mse', optimizer='adadelta')
	monitor = EarlyStopping(monitor='val_loss', min_delta=1e-3, 
                        patience=5, verbose=1, mode='auto'
	model.fit(train_data,train_data,verbose=1,epochs=1000, callbacks=[monitor])
	
	prediction = model.predict(test_data)

	print("-------------Autoencoder Report Start-------------")
	print(classification_report(y_val, prediction))

# Нормализация числовых данных, так как некоторые модели лучше работают с такими данными (z score)
def encode_numeric_zscore(df):
	features = [
		'client_package_size_mean',
		'client_package_size_std',
		'server_package_size_mean',
		'server_package_size_std',
		'client_batch_sizes_mean',
		'client_batch_sizes_std',
		'server_batch_sizes_mean',
		'server_batch_sizes_std',
		'client_batch_counts_mean',
		'server_batch_counts_mean',
		'client_efficiency', 
		'server_efficiency',
		'ratio_sizes',
		'ratio_application_size',
		'ratio_packages',
		'client_package_size_sum',
		'client_application_size_sum',
		'client_package_count',
		'client_batch_counts_sum',
		'server_package_size_sum',
		'server_application_size_sum',
		'server_package_count',
		'server_batch_counts_sum',
	]
	for param in features:
        mean = df[param].mean()
        sd = df[param].std()
		df[param] = (df[param] - mean) / sd

def oneclass_svm_calculation(train_data, test_data, y_val):

	clsfir = OneClassSVM(gamma=0.01, kernel='rbf', nu=0.001)
	clsfir.fit(train_data)
	prediction = clsfir.predict(test_data)
	print("-------------One-Class SVM Report Start-------------")
	print(classification_report(y_val, prediction))

def isolation_forest_calculation(train_data, test_data, y_val)):

	print("-------------Isolation Forest Report Start-------------")
	print(classification_report(y_val, prediction))



def main():
	pcap_file_path = sys.argv[1] if len(sys.argv) > 1 else sys.exit('No file name: plese enter input PCAP file name')

	train_data, test_data, xml = create_train_and_test_data(pcap_file_path)

	#Массив маркоров для тестового датасета
	y_val = []
	for _,  route in test_data['route'].items():
		y.append(1)
		for ip in xml['object.src.ip']:
			if route.contains("ip"):
				y[-1] = -1
				break

	isolation_forest_calculation(train_data, test_data)
	oneclass_svm_calculation(train_data, test_data)
	autoencoder_calculation(train_data, test_data)


if __name__ == "__main__":
	main()