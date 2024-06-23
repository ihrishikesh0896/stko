import sys
import subprocess
import requests
import logging


def setup_logging(level):
    """Configure the logging level based on user input."""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {level}')
    logging.basicConfig(filename='subdomain_scan.log', level=numeric_level,
                        format='%(asctime)s - %(levelname)s - %(message)s')


def read_subdomains(file_path):
    """Read and return the list of subdomains from a file."""
    with open(file_path, 'r') as file:
        subdomains = [line.strip() for line in file.readlines() if line.strip()]
    logging.info(f"loaded {len(subdomains)} for scanning...")
    return subdomains


def check_subdomain_vulnerability(subdomain):
    """Check a single subdomain for signs of vulnerability based on HTTP response content."""
    try:
        response = requests.get(f"http://{subdomain}", timeout=10)
        indicators = ["404", "The specified bucket does not exist", "Repository not found",
                      "This site can’t be reached", "There isn't a GitHub Pages site here."]
        if any(indicator in response.text for indicator in indicators):
            logging.info(f"{subdomain} appears vulnerable. Status Code: {response.status_code}")
            return True, response.status_code
        return False, response.status_code
    except requests.RequestException as e:
        logging.error(f"Failed to check {subdomain}: {str(e)}")
        return None, None


def run_nuclei_scan(input_file):
    """Run nuclei on a list of subdomains using subprocess."""
    command = [
        'nuclei',
        '-l', input_file,
        '-silent',
        '-stats',
        '-timeout', '10',
        '-rate-limit', '100',
        '-severity', 'high,medium'
    ]
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        logging.info("Nuclei scan completed successfully")
        logging.debug(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error("Nuclei scan failed")
        logging.error(e.stderr)


def main(input_file, output_file, log_level):
    setup_logging(log_level)
    subdomains = read_subdomains(input_file)
    vulnerable_domains = []

    with open(output_file, 'w') as result_file:
        for subdomain in subdomains:
            is_vulnerable, status_code = check_subdomain_vulnerability(subdomain)
            if is_vulnerable is not None:
                result_line = f"{subdomain}, Vulnerable: {is_vulnerable}, Status Code: {status_code}\n"
                result_file.write(result_line)
                if is_vulnerable:
                    vulnerable_domains.append(subdomain)
                    logging.info(f"Vulnerable subdomain found: {subdomain}")

    run_nuclei_scan(input_file)
    logging.info(f"Vulnerable subdomains: {vulnerable_domains}")
    print("Vulnerable subdomains:", vulnerable_domains)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        logging.basicConfig(level=logging.INFO)
        logging.error("Incorrect usage. Expected three command-line arguments.")
        print("Usage: python stko.py <input_file_path> <output_file_path> <log_level>")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        log_level = sys.argv[3]
        main(input_file, output_file, log_level)
