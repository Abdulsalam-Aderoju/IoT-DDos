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
    models = {
        "Random Forest": joblib.load('random_forest.joblib'),
        "Decision Tree": joblib.load('decision_tree.joblib'),
        "SVM": joblib.load('svm.joblib'),
        "Naive Bayes": joblib.load('naive_bayes.joblib'),
        "Extra Trees": joblib.load('extra_trees.joblib')
    }
    return scaler, pca, models

scaler, pca, models = load_models()

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

predefined_samples = {
    "Sample 1": {
        'flow_duration': 42.868034, 'Protocol Type': 2.0, 'Rate': 77.26135, 'Srate': 77.26135, 'Drate': 0.0,
        'fin_flag_number': 1.0, 'syn_flag_number': 0.0, 'rst_flag_number': 0.0, 'psh_flag_number': 0.0,
        'ack_flag_number': 1.0, 'ece_flag_number': 0.0, 'cwr_flag_number': 0.0, 'ack_count': 0.0,
        'syn_count': 0.4, 'fin_count': 0.0, 'urg_count': 202.6, 'HTTP': 0.0, 'HTTPS': 1.0, 'DNS': 0.0,
        'IAT': 0.00004817
    },
    "Sample 2": {
        'flow_duration': 2.768939, 'Protocol Type': 13.0, 'Rate': 0.230653, 'Srate': 0.230653, 'Drate': 0.0,
        'fin_flag_number': 0.0, 'syn_flag_number': 1.0, 'rst_flag_number': 0.0, 'psh_flag_number': 0.0,
        'ack_flag_number': 0.0, 'ece_flag_number': 0.0, 'cwr_flag_number': 0.0, 'ack_count': 0.0,
        'syn_count': 0.0, 'fin_count': 0.0, 'urg_count': 0.0, 'HTTP': 0.0, 'HTTPS': 0.0, 'DNS': 0.0,
        'IAT': 902972879.775784
    },
    "Sample 3": {
        'flow_duration': 1.2345, 'Protocol Type': 17.0, 'Rate': 0.47893, 'Srate': 0.47893, 'Drate': 0.0,
        'fin_flag_number': 0.0, 'syn_flag_number': 1.0, 'rst_flag_number': 0.0, 'psh_flag_number': 0.0,
        'ack_flag_number': 0.0, 'ece_flag_number': 0.0, 'cwr_flag_number': 0.0, 'ack_count': 0.0,
        'syn_count': 0.0, 'fin_count': 0.0, 'urg_count': 0.0, 'HTTP': 0.0, 'HTTPS': 0.0, 'DNS': 0.0,
        'IAT': 803007569.428856
    }
}


# Sidebar for model and sample selection
st.sidebar.title("Settings")
selected_model_name = st.sidebar.selectbox(
    "Select Model",
    options=list(models.keys())
)

selected_sample_name = st.sidebar.selectbox(
    "Select a Sample",
    options=[None] + list(predefined_samples.keys())
)

# Get the selected model and sample
model = models[selected_model_name]
selected_sample = predefined_samples.get(selected_sample_name, {})

# Main content
st.title("🚀 Web Based Attack Detection")
st.write("") 
st.write("") 

st.header("Enter Input Values")
st.write("") 

# Create two columns for input fields
col1, col2 = st.columns(2)

# Create input fields for all features using full names
user_input = {}
with col1:
    st.subheader("Features - Part 1")
    for i, (full_name, short_name) in enumerate(feature_mapping.items()):
        if i < len(feature_mapping) // 2:  # First half of features
            value = float(selected_sample.get(short_name, 0.0))
            user_input[short_name] = st.number_input(f"Enter value for {full_name}", value=value, format="%.5f")

with col2:
    st.subheader("Features - Part 2")
    for i, (full_name, short_name) in enumerate(feature_mapping.items()):
        if i >= len(feature_mapping) // 2:  # Second half of features
            value = float(selected_sample.get(short_name, 0.0))
            user_input[short_name] = st.number_input(f"Enter value for {full_name}", value=value, format="%.5f")

if st.button("Predict"):
    # Ensure the DataFrame columns match the feature names used during training
    input_df = pd.DataFrame([user_input], columns=[feature_mapping[full_name] for full_name in feature_mapping])
    
    # Preprocessing
    X_scaled = scaler.transform(input_df)
    X_pca = pca.transform(X_scaled)
    
    # Prediction
    prediction = model.predict(X_pca)
    
    # Display Results
    st.subheader("Prediction Result")
    result = "Attack" if prediction[0] == 1 else "Benign Traffic"
    st.write(f"The model predicts: **{result}**")
    

