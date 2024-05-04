import base64
import io
import os
import pickle
import random

import matplotlib.pyplot as plt
import nltk
import numpy as np
import pandas as pd
import pymysql
import seaborn as sns
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponse
from django.shortcuts import render
from django.template import RequestContext
from nltk.corpus import stopwords
from sklearn import svm
from sklearn.ensemble import VotingClassifier
from sklearn.feature_extraction.text import \
    TfidfVectorizer  # loading tfidf vector
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier

global username, X_train, X_test, y_train, y_test, X, Y, ensemble_classifier, img_b64
global accuracy, precision, recall, fscore, vectorizer
stop_words = set(stopwords.words('english'))

def PredictAction(request):
    if request.method == 'POST':
        global ensemble_classifier, vectorizer
        myfile = request.FILES['t1']
        name = request.FILES['t1'].name
        if os.path.exists("VulnerApp/static/testData.csv"):
            os.remove("VulnerApp/static/testData.csv")
        fs = FileSystemStorage()
        filename = fs.save('VulnerApp/static/testData.csv', myfile)
        df = pd.read_csv('VulnerApp/static/testData.csv')
        temp = df.values
        X = vectorizer.transform(df['Test_data'].astype('U')).toarray()
        predict = ensemble_classifier.predict(X)
        output = '<table border="1" align="center" width="100%" ><tr><th><font size="" color="black">Test Data</th>'
        output += '<th><font size="" color="black">Predicted Vulnerability</th></tr>'
        for i in range(len(predict)):
            if predict[i] == 0:
                status = "Normal"
            if predict[i] == 1:
                status = "SQL Injection"
            if predict[i] == 2:
                status = "JS Vulnerability"
            out = str(temp[i,0])
            out = out.replace("<","")
            out = out.replace(">","")
            output+='<tr><td><font size="" color="black">'+out+'</td>'
            output+='<td><font size="" color="black">'+status+'</td></tr>'
        output+="</table><br/><br/><br/><br/><br/><br/>"
        context= {'data':output}
        return render(request, 'UserScreen.html', context)        

def UploadAction():
    global X_train, X_test, y_train, y_test, X, Y, vectorizer
    df = pd.read_csv('VulnerApp/static/Data.csv')
    df['Label'] = df['Label'].astype(str).astype(int)
    vectorizer = TfidfVectorizer(stop_words=stop_words, use_idf=True, smooth_idf=False, norm=None, decode_error='replace', max_features=300)
    X = vectorizer.fit_transform(df['Sentence'].astype('U')).toarray()
    temp = pd.DataFrame(X, columns=vectorizer.get_feature_names())
    Y = df['Label'].ravel()
    indices = np.arange(X.shape[0])
    np.random.shuffle(indices)
    X = X[indices]
    Y = Y[indices]
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size = 0.1)
    print("Dataset Loading & Processing Completed")
    print("Dataset Length : "+str(len(X)))
    print("Splitted Training Length : "+str(len(X_train)))
    print("Splitted Test Length : "+str(len(X_test)))
UploadAction()

def calculateMetrics(algorithm, predict, y_test):
    global accuracy, precision, recall, fscore, img_b64
    a = accuracy_score(y_test,predict)*100
    p = precision_score(y_test, predict,average='macro') * 100
    r = recall_score(y_test, predict,average='macro') * 100
    f = f1_score(y_test, predict,average='macro') * 100
    accuracy.append(a)
    precision.append(p)
    recall.append(r)
    fscore.append(f)
    labels = ['No Attack', 'SQL Injection', 'JS Vulnerability']
    conf_matrix = confusion_matrix(y_test, predict) 
    plt.figure(figsize =(6, 3)) 
    ax = sns.heatmap(conf_matrix, xticklabels = labels, yticklabels = labels, annot = True, cmap="viridis" ,fmt ="g");
    ax.set_ylim([0,len(labels)])
    plt.title(algorithm+" Confusion matrix") 
    plt.ylabel('True class') 
    plt.xlabel('Predicted class')
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    img_b64 = base64.b64encode(buf.getvalue()).decode()    

def RunEnsemble():
    global accuracy, precision, recall, fscore, X_train, X_test, y_train, y_test, ensemble_classifier
    accuracy = []
    precision = []
    recall = []
    fscore = []
    nb_cls = GaussianNB()
    svm_cls = svm.SVC()
    knn_cls = KNeighborsClassifier(n_neighbors=2)
    if os.path.exists("model/ensemble.pckl"):
        f = open('model/ensemble.pckl', 'rb')
        ensemble_classifier = pickle.load(f)
        f.close()    
    else:
        estimators = [('nb', nb_cls), ('svm', svm_cls), ('knn', knn_cls)]
        ensemble_classifier = VotingClassifier(estimators = estimators)
        ensemble_classifier.fit(X_train, y_train)
        f = open('model/ensemble.pckl', 'wb')
        pickle.dump(ensemble_classifier, f)
        f.close()
    X_test = X_test[0:2000]
    y_test = y_test[0:2000]
    predict = ensemble_classifier.predict(X_test)
    calculateMetrics("Ensemble Classifier", predict, y_test)
    algorithms = ['Ensemble Classifier']
    output={}
    for i in range(len(algorithms)):
        print(algorithms[i],":")
        output["accuracy"]=str(accuracy[i])
        output["precision"]=str(precision[i])
        output["recall"]=str(recall[i])
        output["fscore"]=str(fscore[i])
    print(output)
RunEnsemble()

def Predict(request):
    if request.method == 'GET':
        return render(request, 'Predict.html', {})

def index(request):
    if request.method == 'GET':
        return render(request, 'Predict.html', {})

