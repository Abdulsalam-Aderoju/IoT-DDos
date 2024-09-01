import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

# Set page configuration
st.set_page_config(
    page_title="Attack Detection App",
    page_icon="🚀",
    layout="wide",
)

# Load saved models
@st.cache_resource
def load_models():
    scaler = joblib.load('scaler.joblib')
    pca = joblib.load('pca.joblib')
    model = joblib.load('decision_tree.joblib')
    return scaler, pca, model

scaler, pca, model = load_models()

# Mapping of full feature names to abbreviated names
feature_mapping = {
    'Flow Duration': 'flow_duration',
    'Protocol Type': 'Protocol Type',
    'Rate': 'Rate',
    'Source Rate (Srate)': 'Srate',
    'Destination Rate (Drate)': 'Drate',
    'FIN Flag Count': 'fin_flag_number',
    'SYN Flag Count': 'syn_flag_number',
    'RST Flag Count': 'rst_flag_number',
    'PSH Flag Count': 'psh_flag_number',
    'ACK Flag Count': 'ack_flag_number',
    'ECE Flag Count': 'ece_flag_number',
    'CWR Flag Count': 'cwr_flag_number',
    'ACK Count': 'ack_count',
    'SYN Count': 'syn_count',
    'FIN Count': 'fin_count',
    'URG Count': 'urg_count',
    'HTTP': 'HTTP',
    'HTTPS': 'HTTPS',
    'DNS': 'DNS',
    'Inter Arrival Time (IAT)': 'IAT'
}

st.title("🚀 Web Based Attack Detection")

st.header("Enter Input Values")

# Create two columns
col1, col2 = st.columns(2)

# Create input fields for all features using full names
with col1:
    st.subheader("Features - Part 1")
    user_input = {}
    for i, (full_name, short_name) in enumerate(feature_mapping.items()):
        if i < len(feature_mapping) // 2:  # First half of features
            value = st.number_input(f"Enter value for {full_name}", value=0.0, format="%.5f")
            user_input[short_name] = value

with col2:
    st.subheader("Features - Part 2")
    for i, (full_name, short_name) in enumerate(feature_mapping.items()):
        if i >= len(feature_mapping) // 2:  # Second half of features
            value = st.number_input(f"Enter value for {full_name}", value=0.0, format="%.5f")
            user_input[short_name] = value

if st.button("Predict"):
    # Ensure the DataFrame columns match the feature names used during training
    input_df = pd.DataFrame([user_input], columns=[feature_mapping[full_name] for full_name in feature_mapping])
    
    # Preprocessing
    X_scaled = scaler.transform(input_df)
    X_pca = pca.transform(X_scaled)
    
    # Prediction
    prediction = model.predict(X_pca)
    prediction_proba = model.predict_proba(X_pca)
    
    # Display Results
    st.subheader("Prediction Result")
    result = "Attack" if prediction[0] == 1 else "Benign Traffic"
    st.write(f"The model predicts: **{result}**")
    
    st.subheader("Prediction Probability")
    proba_df = pd.DataFrame(prediction_proba, columns=["Benign Traffic", "Attack"])
    st.write(proba_df)

