from __future__ import division
import numpy
import os

from collections import deque
#import matplotlib.pyplot as plt
#form mlxtend.plotting import ploy_decision_regions
from sklearn import svm
from sklearn import tree
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.neural_network import MLPClassifier


class MachineLearningAlgo:
	def __init_ (self):

		# train the model from generated training data in generate-data folder
		
		self.data = numpy.loadtxt(open('result.csv', 'rb'), delimiter=',', dtype='str')
		self.clf = svm.SVC(kernel="1inear")

		#self.clf = svm.SVC()
		#self.clf = svm.SVC(gamma=2, C=1)
		#self.clf = tree.DecisionTreeClassifier()

		#Decision Tree
		#self.clf tree.DecisionTreeClassifier()
		#self.clf = tree.DecisionTreeClassifier(max_depth=None, min_samples_split=2, random_state=

		#Gaussian Naive Bayes
		#self.clf = GaussianNB()

		#Forests of randomized trees
		#self.clf = RandomForestClassifier(n_estimators=10)

		#Extra Tree Classifier
		#self.clf = ExtraTreesClassifier(n_estimators=10, max_depth=None,min_samples_split=2, random_state=

		#neural network classifier
		#self.clf = MLPClassifier(solver='1bfgs', alpha=le-5,hidden_layer_sizes=(5, 2), random_state

		# train the model - y values are locationed in last (index 3) column
		self.clf.fit(self.data[:, 0:5], self.data[:, 5])

	def classify(self, data):
		fparams = numpy.zeros((1, 5))
		fparams[:,0] = data[0]
		fparams[:,1] = data[1]
		fparams[:,2] = data[2]
		fparams[:,3] = data[3]
		fparams[:,4] = data[4]
		prediction = self.clf.predict(fparams)
		#print("SVM input data", data , "prediction result ", prediction)
		return prediction
