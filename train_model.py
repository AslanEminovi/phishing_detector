import re
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

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

# Create a sample dataset
data = {
    'url': [
        'http://example.com/login', 
        'http://malicious.xyz/verify',
        'http://safe-site.com/home', 
        'http://phishingsite.com/account'
    ],
    'label': [0, 1, 0, 1]
}
df = pd.DataFrame(data)

# Extract features and labels
X = df['url'].apply(extract_features).tolist()
y = df['label'].tolist()

# Convert to DataFrame for ease of use
X = pd.DataFrame(X, columns=['length', 'num_dots', 'has_at', 'has_hyphen', 'has_underscore', 'has_ip', 'has_suspicious_word', 'tld'])

# One-hot encode categorical features (TLD)
X = pd.get_dummies(X, columns=['tld'], drop_first=True)

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train the model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))

# Save the model
joblib.dump(model, 'phishing_model.pkl')
