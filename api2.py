from flask import Flask, request, jsonify
import pickle
import pandas as pd
import featureextractor as fe

app = Flask(__name__)

# Load the phishing detection model
with open("model/XGBoostClassifier.pickle.dat", "rb") as f:
    model = pickle.load(f)

# Define the feature names
feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 
                 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards']

@app.route('/predict', methods=['POST'])
def predict():
    # Get the URL from the request data
    url = request.json.get('url')

    # Extract features from the URL
    features = fe.featureExtraction(url)

    # Create a DataFrame with the features
    df = pd.DataFrame([features[1:]], columns=feature_names)

    # Predict using the loaded model
    prediction = model.predict(df)

    # Map the prediction to human-readable output
    result = "Legitimate" if prediction == 0 else "Phishing"

    # Return the prediction as JSON response
    return jsonify({'prediction': result})

if __name__ == '__main__':
    app.run(debug=True)
