from flask import Flask, request, jsonify
import joblib
import pandas as pd
from urllib.parse import urlparse
import re

# Load the trained model
model = joblib.load('phishing_model.pkl')

# Function to extract features from URLs
def extract_features(url):
    features = []
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    path = parsed_url.path
    
    # Length of URL
    features.append(len(url))
    
    # Number of dots in URL
    features.append(url.count('.'))
    
    # Presence of special characters
    features.append(int('@' in url))
    features.append(int('-' in url))
    features.append(int('_' in url))
    
    # Use of IP address
    features.append(int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', hostname))))
    
    # Suspicious words
    suspicious_words = ['login', 'verify', 'account', 'update']
    features.append(int(any(word in url for word in suspicious_words)))
    
    # Top-level domain
    tld = hostname.split('.')[-1]
    features.append(tld)
    
    return features

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.json['url']
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=['length', 'num_dots', 'has_at', 'has_hyphen', 'has_underscore', 'has_ip', 'has_suspicious_word', 'tld'])
    features_df = pd.get_dummies(features_df, columns=['tld'])
    
    # Ensure all possible columns are present
    missing_cols = set(model.feature_names_in_) - set(features_df.columns)
    for col in missing_cols:
        features_df[col] = 0
    
    features_df = features_df[model.feature_names_in_]  # Reorder columns to match training data
    
    prediction = model.predict(features_df)
    return jsonify({'phishing': bool(prediction[0])})

if __name__ == '__main__':
    app.run(debug=True)
