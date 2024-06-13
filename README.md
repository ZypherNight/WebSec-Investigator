# WebSec-Investigator

Usage

1. This tool performs two main functions:

    a. Web Scraping from Google Search: Retrieves URLs from a Google search query and scrapes their content.

    b. Security Audit: Performs a comprehensive security audit of a target domain.

2. Prerequisites:

    Python 3.x installed.

    Required libraries: Install the dependencies listed in requirements.txt using:

          
    pip install -r requirements.txt


3. Shodan API Key: Get a free Shodan API key from https://account.shodan.io/register and replace the placeholder value in the script (SHODAN_API_KEY = 'Shodan api key').

Running the Tool:

    a. Save the script (e.g., as recon_tool.py).
    b. Open a terminal or command prompt.
    c. Navigate to the script's directory.
    d. Run the script:
    e. python recon_tool.py


4. Workflow:

The tool will prompt you for the following:

    1. Google Search Query: Enter a search term to retrieve relevant URLs from Google.

    2. Target Domain: Enter the domain name you want to perform the security audit on (e.g., example.com).

5. Output:

    a. The tool will save scraped website content as JSON files.It will generate individual JSON reports for:

        1. DNS information

        2. SSL/TLS information

        3. Shodan information

        4. BuiltWith information

        5. Banner grabbing results

        6. Geolocation information

        7. Subdomains

6.  A summary report of the security audit will be saved in a JSON file named [target_domain]_security_audit_summary.json.

7. A final consolidated report will be saved in final_results.json.
