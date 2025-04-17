# Hybrid_Spam_Classification

The CSV file named spam_assassin.csv contains the raw emails (ham and easy spam emails) and its labels (spam or not). This CSV file is inputted into the feature_extraction.py. This python file extracts metadata features and actual email contents from raw emails and writes to a CSV file named features.csv. 

The folder named hard_spam contains json files, and each json file is one   hard spam raw emails. This folder is inputted into the feature_extraction_hard_spam.py. This python file extracts metadata features and actual email contents from hard spam raw emails and writes to a csv file named features_hard_spam.csv.

The jupyter notebook named model_creation.ipynb reads and combines the features.csv and features_hard_spam.csv and runs model. It also contains the analysis results which are graphs and training, validation, and testing accuracy reports of each model. 

Link to the weekly meeting notes: 
https://docs.google.com/document/d/1IzyrSq61aiMvW-IleKIe7ImTHHuGpwhMGpqNoUm7e-g/edit?usp=sharing
