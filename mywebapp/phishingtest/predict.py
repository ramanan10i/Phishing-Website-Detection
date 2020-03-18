import pandas as pd
import numpy as np
from . import second
from tensorflow.keras.models import model_from_json
from tensorflow.keras.optimizers import Adam

def predict_result(url):
	X = second. generate_list(url)
	X_pred = np.array(X)
	X_pred = np.reshape(X_pred,(1,24))


# X = dataset.iloc[:,0:30].values.astype(int)
# y = dataset.iloc[:,30].values.astype(int)

# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
#         random_state=np.random.seed(7))


# loading the trained model to predict

	json_file = open('model_final.json','r')
	loaded_model_json = json_file.read()
	json_file.close()
	model = model_from_json(loaded_model_json)


# loading the weights for the model
	model.load_weights("model_final.h5")

	model.compile(loss='binary_crossentropy', optimizer=Adam(), metrics=['accuracy'])
# scores = model.evaluate(X_test, y_test)
	result = model.predict(X_pred)
	return result[0][0]



