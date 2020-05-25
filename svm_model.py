from sklearn.svm import OneClassSVM
import pandas as pd

df = pd.read_pickle("./dimapac.pkl")
print(df)

# clf = OneClassSVM(gamma='auto')