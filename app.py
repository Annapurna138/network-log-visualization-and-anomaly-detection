from flask import Flask, render_template
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.dates as mdates

app = Flask(__name__)

# Read the log file and create DataFrame
def read_log_file(log_file):
    with open(log_file, "r") as f:
        log_data = f.readlines()

    timestamps = []
    ip_addresses = []
    methods = []
    urls = []
    status_codes = []
    user_agents = []

    for log_entry in log_data:
        parts = log_entry.split()
        if len(parts) >= 12:
            timestamps.append(parts[0] + " " + parts[1])
            ip_addresses.append(parts[2])
            methods.append(parts[5][1:])
            urls.append(parts[6])
            status_codes.append(int(parts[8]))
            user_agents.append(" ".join(parts[11:])[1:-1])
        else:
            print(f"Ignoring malformed log entry: {log_entry}")

    df = pd.DataFrame({
        "Timestamp": timestamps,
        "IP Address": ip_addresses,
        "Method": methods,
        "URL": urls,
        "Status Code": status_codes,
        "User Agent": user_agents
    })

    df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    return df

# Function to count occurrences of each value and return as dictionary
def count_values(df, column):
    counts = {}
    unique_values = df[column].unique()
    for value in unique_values:
        count = df[df[column] == value].shape[0]
        counts[value] = count
    return counts

# Function to generate Events Over Time plot
def generate_events_over_time_plot(df):
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    grouped_by_ip = df.groupby('IP Address')
    plt.figure(figsize=(12, 8))
    for ip, group_data in grouped_by_ip:
        event_counts = group_data.groupby(pd.Grouper(key='Timestamp', freq='T')).size()  # 'T' for minutes
        plt.plot(event_counts.index, event_counts.values, label=ip)
    plt.title('Events Over Time for Different IP Addresses')
    plt.xlabel('Time')
    plt.ylabel('Event Frequency')
    plt.legend(title='IP Address')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gca().xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
    plt.gcf().autofmt_xdate()
    plt.tight_layout()
    plt.savefig('static/events_over_time.png')
    plt.close()

# Function to generate Frequency of HTTP Methods Over Time plot
def generate_http_methods_plot(df):
    method_frequency = df.groupby(['Timestamp', 'Method']).size().reset_index(name='Frequency')
    plt.figure(figsize=(12, 8))
    sns.lineplot(data=method_frequency, x='Timestamp', y='Frequency', hue='Method', palette='pastel', linewidth=2.5)
    plt.title('Frequency of HTTP Methods Over Time')
    plt.xlabel('Time')
    plt.ylabel('Frequency Count')
    plt.legend(title='HTTP Method', loc='upper left')
    plt.savefig('static/frequency_of_http_methods_over_time.png')
    plt.close()

# Function to generate Anomaly Detection Plot using Isolation Forest
def generate_isolation_forest_anomaly_detection_plot(df):
    # Feature engineering
    df['Hour'] = df['Timestamp'].dt.hour
    df['Minute'] = df['Timestamp'].dt.minute
    df['Second'] = df['Timestamp'].dt.second
    df['Time'] = df['Timestamp'].dt.floor('T')  # Floor to the nearest minute

    ip_request_counts = df.groupby(['IP Address', 'Time', 'Hour', 'Minute']).size().reset_index(name='Request Count')

    # Prepare the data for the Isolation Forest
    ip_request_counts['IP Address Encoded'] = ip_request_counts['IP Address'].astype('category').cat.codes
    features = ['IP Address Encoded', 'Hour', 'Minute', 'Request Count']
    X = ip_request_counts[features]

    # Train Isolation Forest
    model = IsolationForest(contamination=0.05, random_state=42)
    ip_request_counts['Anomaly'] = model.fit_predict(X)

    # Anomalies are marked as -1 in the 'Anomaly' column
    anomalies = ip_request_counts[ip_request_counts['Anomaly'] == -1]

    # Visualization
    plt.figure(figsize=(14, 7))
    sns.lineplot(data=ip_request_counts, x='Time', y='Request Count', hue='IP Address', palette='viridis', legend=None)
    anomaly_times = anomalies['Time'].unique()
    for anomaly_time in anomaly_times:
        plt.axvline(x=anomaly_time, color='red', linestyle='--', alpha=0.5)
    plt.title('IP Address Request Count Over Time with Anomalies Highlighted (Isolation Forest)')
    plt.xlabel('Time')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/isolation_forest_anomaly_detection_plot.png')
    plt.close()

# Function to generate Anomaly Detection Plot using Local Outlier Factor
def generate_local_outlier_factor_anomaly_detection_plot(df):
    # Feature engineering
    df['Hour'] = df['Timestamp'].dt.hour
    df['Minute'] = df['Timestamp'].dt.minute
    df['Second'] = df['Timestamp'].dt.second
    df['Time'] = df['Timestamp'].dt.floor('T')  # Floor to the nearest minute

    ip_request_counts = df.groupby(['IP Address', 'Time', 'Hour', 'Minute']).size().reset_index(name='Request Count')

    # Prepare the data for Local Outlier Factor
    ip_request_counts['IP Address Encoded'] = ip_request_counts['IP Address'].astype('category').cat.codes
    features = ['IP Address Encoded', 'Hour', 'Minute', 'Request Count']
    X = ip_request_counts[features]

    # Train Local Outlier Factor
    model = LocalOutlierFactor(contamination=0.05)
    ip_request_counts['Anomaly'] = model.fit_predict(X)

    # Anomalies are marked as -1 in the 'Anomaly' column
    anomalies = ip_request_counts[ip_request_counts['Anomaly'] == -1]

    # Visualization
    plt.figure(figsize=(14, 7))
    sns.lineplot(data=ip_request_counts, x='Time', y='Request Count', hue='IP Address', palette='viridis', legend=None)
    anomaly_times = anomalies['Time'].unique()
    for anomaly_time in anomaly_times:
        plt.axvline(x=anomaly_time, color='blue', linestyle='--', alpha=0.5)
    plt.title('IP Address Request Count Over Time with Anomalies Highlighted (Local Outlier Factor)')
    plt.xlabel('Time')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/local_outlier_factor_anomaly_detection_plot.png')
    plt.close()

# Function to generate Anomaly Detection Plot using One-Class SVM
def generate_one_class_svm_anomaly_detection_plot(df):
    # Feature engineering
    df['Hour'] = df['Timestamp'].dt.hour
    df['Minute'] = df['Timestamp'].dt.minute
    df['Second'] = df['Timestamp'].dt.second
    df['Time'] = df['Timestamp'].dt.floor('T')  # Floor to the nearest minute

    ip_request_counts = df.groupby(['IP Address', 'Time', 'Hour', 'Minute']).size().reset_index(name='Request Count')

    # Prepare the data for One-Class SVM
    ip_request_counts['IP Address Encoded'] = ip_request_counts['IP Address'].astype('category').cat.codes
    features = ['IP Address Encoded', 'Hour', 'Minute', 'Request Count']
    X = ip_request_counts[features]

    # Train One-Class SVM
    model = OneClassSVM(nu=0.05)
    ip_request_counts['Anomaly'] = model.fit_predict(X)

    # Anomalies are marked as -1 in the 'Anomaly' column
    anomalies = ip_request_counts[ip_request_counts['Anomaly'] == -1]

    # Visualization
    plt.figure(figsize=(14, 7))
    sns.lineplot(data=ip_request_counts, x='Time', y='Request Count', hue='IP Address', palette='viridis', legend=None)
    anomaly_times = anomalies['Time'].unique()
    for anomaly_time in anomaly_times:
        plt.axvline(x=anomaly_time, color='purple', linestyle='--', alpha=0.5)
    plt.title('IP Address Request Count Over Time with Anomalies Highlighted (One-Class SVM)')
    plt.xlabel('Time')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/one_class_svm_anomaly_detection_plot.png')
    plt.close()

# Function to calculate accuracy of anomaly detection
def calculate_accuracy(true_anomalies, predicted_anomalies):
    true_positives = len(set(true_anomalies) & set(predicted_anomalies))
    false_negatives = len(set(true_anomalies) - set(predicted_anomalies))
    accuracy = true_positives / (true_positives + false_negatives)
    return accuracy

@app.route('/')
def index():
    log_file = 'sample_log_file.log'
    df = read_log_file(log_file)

    total_events = df.shape[0]
    method_counts = count_values(df, 'Method')
    status_code_counts = count_values(df, 'Status Code')
    url_counts = count_values(df, 'URL')
    ip_counts = count_values(df, 'IP Address')
    
    # Ground truth anomalies for evaluation (Replace with actual data)
    true_anomalies = ['2024-06-12 12:00:00', '2024-06-12 13:00:00', '2024-06-12 14:00:00']

    # Predicted anomalies for each model (Replace with actual data)
    isolation_forest_predicted_anomalies = ['2024-06-12 12:00:00', '2024-06-12 14:00:00']
    local_outlier_factor_predicted_anomalies = ['2024-06-12 12:00:00', '2024-06-12 13:00:00', '2024-06-12 14:00:00']
    one_class_svm_predicted_anomalies = ['2024-06-12 12:00:00', '2024-06-12 13:00:00']

    # Calculate accuracy for each model
    isolation_forest_accuracy = calculate_accuracy(true_anomalies, isolation_forest_predicted_anomalies)
    local_outlier_factor_accuracy = calculate_accuracy(true_anomalies, local_outlier_factor_predicted_anomalies)
    one_class_svm_accuracy = calculate_accuracy(true_anomalies, one_class_svm_predicted_anomalies)

    # Visualize accuracy comparison
    models = ['Isolation Forest', 'Local Outlier Factor', 'One-Class SVM']
    accuracies = [isolation_forest_accuracy, local_outlier_factor_accuracy, one_class_svm_accuracy]

    plt.figure(figsize=(10, 6))
    sns.barplot(x=models, y=accuracies, palette='viridis')
    plt.title('Anomaly Detection Model Comparison')
    plt.xlabel('Model')
    plt.ylabel('Accuracy')
    plt.ylim(0, 1)
    plt.savefig('static/anomaly_detection_model_comparison.png')
    plt.close()

    return render_template('index.html', total_events=total_events, method_counts=method_counts,
                           status_code_counts=status_code_counts, url_counts=url_counts, ip_counts=ip_counts,
                           isolation_forest_accuracy=isolation_forest_accuracy,
                           local_outlier_factor_accuracy=local_outlier_factor_accuracy,
                           one_class_svm_accuracy=one_class_svm_accuracy)

if __name__ == '__main__':
    app.run(debug=True)