<div align="center">
<p align="center">
	<img src='https://img.shields.io/badge/Made%20with-Python-1f425f.svg'/>
  
# EmailAnalyzer
Created by <a href="https://www.linkedin.com/in/subhash-thapa-8670b1115/ ">Subhash Thapa</a>
</p>
</div>


#### This is a Python script to analyzes the Email (Suspicious/Malicious Email) for variety of Information which can help us to preliminary analysis of the email file like  redirection URL, headers, IPs and more. 
## Why Email Analyzer?
#### Email analyzers can be used to extract valuable information from emails, whether for security, compliance, forensics, e-discovery, or business purposes. Malicious actors often use email as a way to distribute malware by sending emails with infected attachments or links to malicious websites. Once a user opens the attachment or clicks on the link, the malware can be installed on their computer. A malicious email can contain harmful or malicious content, such as a virus, malware, or phishing attempt. It is important to be cautious when clicking on links or opening attachments from unknown sources, and to keep anti-virus and anti-malware software updated on your computer to protect yourself from malicious emails.
### The attached script 'EmailAnalyzer.py' assists us in obtaining items such as -

- Hash of the email file such as MD5,SHA1 and SHA256
- Message Header and its Analysis 
- List of IPs found in Email
- List of URLs/Links found in Email
- List of Emails addresses found in Email
- Email Subject with Sender and Recipient details
- OSINT Links For Detected IOCs

<b>Note: This script only works on .eml extensions files. Please let me know for any suggestions or improvement.</b>

## Requirements:
#### Python 2.7+
## Usage:
### python EmailAnalyzer.py <filename> or python3 EmailAnalyzer.py <filename>
### Eg: python EmailAnalyzer.py C:\Users\Subhash\Documents\Email\emails\e1.eml

## Snapshots 
#### Usage:

![image](https://user-images.githubusercontent.com/26038756/214218738-8642b067-6541-4b3e-9168-a04dc9ad1a62.png)

#### Output:

![image](https://user-images.githubusercontent.com/26038756/214219071-2a9e27e2-e7de-4081-9655-52a3cc3a529e.png)

#### If you face any issue, Please reach out to me on Linkedin - https://www.linkedin.com/in/subhash-thapa-8670b1115/ 
