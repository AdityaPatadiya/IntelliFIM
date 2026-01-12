# IntelliFIM

An AI-driven Intrusion Prevention System (IPS) integrated with File Integrity Monitoring (FIM) and Network Traffic Analysis that detects and prevents insider threats through real-time anomaly detection, context-aware analysis, and adaptive automated response using Explainable AI (XAI).

## Features

- **Monitor Directories**: Start monitoring single or multiple directories for changes in real-time.
- **View Baseline Data**: View the current baseline data stored in the database.
- **Reset Baseline Data**: Reset the baseline data for specified directories.
- **View Logs**: View log files generated during monitoring.
- **Analyze Logs**: Analyze log files for anomalies using machine learning models.
- **Exclude Files/Folders**: Exclude selected files and folders from monitoring.
- **User Authentication**: Ensure only authorized users can access and use the tool.
- **Backup**: Automatically back up monitored directories before starting the monitoring process.
- **Database Integration**: Store baseline data and file metadata in a MySQL database for efficient tracking and querying.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/AdityaPatadiya/FIM.git
    cd FIM
    ```

2. Set up a Python virtual environment and install dependencies:
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3. Set up the MySQL database:
    - `sudo mysql`
    - `SELECT user, host FROM mysql.user;`

    - ```
        CREATE USER 'fim_user'@'localhost' IDENTIFIED BY 'strong_password';
        GRANT ALL PRIVILEGES ON *.* TO 'fim_user'@'localhost' WITH GRANT OPTION;
        FLUSH PRIVILEGES;
        ```
    - Update the `.env` file with your database credentials (see below).

## Configuration

### Create a `.env` file:
Create a `.env` file in the root directory with the following variables:
```
DB_HOST=localhost
DB_NAME=<your_database_name>
DB_USER=<your_database_user>
DB_PASSWORD=<your_database_password>
DB_POOL_SIZE=32
AUTH_DB_NAME=<your_auth_database_name>  # Database for authentication
PEPPER=<your_random_pepper_string>
```

## Usage

### Authentication
When you run the CLI tool, you will be prompted to authenticate. If you are a new user, you can register by providing a username and password. If you are an existing user, you can log in with your credentials. Authentication sessions last for 15 minutes.

### Command-Line Arguments
The CLI tool supports the following arguments:
- `--monitor`: Start monitoring one or more directories.
- `--view-baseline`: View the current baseline data stored in the database.
- `--reset-baseline`: Reset the baseline data for specified directories.
- `--view-logs`: View the log files generated during monitoring.
- `--analyze-logs`: Analyze log files for anomalies using machine learning.
- `--exclude`: Exclude specific files or folders from monitoring.
- `--dir`: Specify directories to monitor.

### Examples
1. **Monitor Directories**:
    ```sh
    python cli.py --monitor --dir /path/to/dir1 /path/to/dir2
    ```
2. **View Baseline Data**:
    ```sh
    python cli.py --view-baseline
    ```
3. **Reset Baseline Data**:
    ```sh
    python cli.py --reset-baseline --dir /path/to/dir1 /path/to/dir2
    ```
4. **View Logs**:
    ```sh
    python cli.py --view-logs
    ```
5. **Analyze Logs**:
    ```sh
    python cli.py --analyze-logs
    ```
6. **Exclude Files/Folders**:
    ```sh
    python cli.py --exclude /path/to/exclude
    ```

## Machine Learning for Anomaly Detection

The tool includes a machine learning module for detecting anomalies in log files:
- **Training**: Train an Isolation Forest model using log data.
    ```sh
    python src/utils/anomaly_detection.py
    ```
- **Analysis**: Analyze logs for anomalies using the trained model.
    ```sh
    python cli.py --analyze-logs
    ```

## Project Structure

```
File-Integrity-Monitor-FIM/
├── cli.py                     # Main CLI tool for the File Integrity Monitor
├── src/
│   ├── FIM/
│   │   ├── FIM.py             # Core functionality for monitoring changes
│   │   ├── fim_utils.py       # Utility methods for file integrity monitoring
│   ├── Authentication/
│   │   ├── Authentication.py  # Handles user authentication
│   ├── utils/
│   │   ├── backup.py          # Handles directory backups
│   │   ├── log_parser.py      # Parses log files into structured data
│   │   ├── anomaly_detection.py # Performs anomaly detection on log files
│   │   ├── database.py        # Manages database operations
├── config/
│   ├── logging_config.py      # Configures logging for monitored directories
├── logs/                      # Directory for storing log files
├── data/models/               # Directory for storing trained models
├── Example/                   # Contains the example files and folder for testing
├── requirements.txt           # Python dependencies
├── .env                       # Environment variables for database and authentication
└── README.md                  # Project documentation
```

## Logs

Log files are stored in the `logs/` directory. Each monitored directory has its own log file, named `FIM_<directory_name>.log`. Logs include timestamps, log levels, and messages about detected changes.

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.
