### STKO

```markdown
# Subdomain Vulnerability Scanner - This project provides a Python-based tool designed to help beginners understand and explore the world of scripting, subdomains, and security vulnerabilities related to subdomain takeovers. It combines practical Python scripting tasks with security checks, offering a hands-on approach to learning.
 

This project contains a Python script that combines direct subdomain vulnerability checking with a comprehensive `nuclei` scan to identify potential security issues. The script reads subdomains from a specified file, checks for common vulnerability indicators via HTTP requests, and utilizes `nuclei` for advanced scanning.

## Features

- **Subdomain Reading**: Extract subdomains from a provided text file.
- **Vulnerability Checking**: Basic HTTP checks for known vulnerability indicators.
- **Nuclei Scanning**: Integrates with `nuclei` for in-depth vulnerability scanning.
- **Logging**: Configurable logging to track and record scan results.

## Prerequisites

- Python 3.6 or higher
- `nuclei` installed and accessible from the command line

## Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/ihrishikesh0896/stko.git
```

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

## Usage

To run the script, you need to specify the input file (containing the subdomains), the output file for results, and the desired logging level:

```python
python stko.py <input_file_path> <output_file_path> <log_level>
```

### Arguments

- `input_file_path`: Path to a text file containing one subdomain per line.
- `output_file_path`: Path where the vulnerability check results will be saved.
- `log_level`: Logging level (e.g., INFO, DEBUG, ERROR).

Example:

```python
python script.py domains.txt results.txt INFO
```

## Configuration

- Modify the `logging.basicConfig` in the script to adjust the log file location and format as needed.
- Adjust `nuclei` command parameters within the script to fine-tune the scanning process.

## Contributing

Contributions to this project are welcome. Please fork the repository and submit a pull request with your enhancements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.