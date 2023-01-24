#Subhash Thapa - https://in.linkedin.com/in/subhash-thapa-8670b1115
import email
import re
#import os
import hashlib
from email.header import decode_header
import argparse

#C:\Users\Subhash\Documents\Email\emails\e1.eml

# Create the parser
parser = argparse.ArgumentParser(description='Process a file path')

# Add the file path argument
parser.add_argument('file_path', metavar='file_path', type=str, help='The file path to be processed')

# Parse the arguments
args = parser.parse_args()

# Get the file path
file_path = args.file_path

#file_path = input('Enter the EML File location: ')
print('\n')
with open(file_path,"rb") as f:
    bytes = f.read() # read entire file as bytes
    md5 = hashlib.md5(bytes).hexdigest();
    print('MD5 Hash of email:',md5)
    sha1 = hashlib.sha1(bytes).hexdigest();
    print('SHA1 Hash of email:',sha1)
    sha256 = hashlib.sha256(bytes).hexdigest();
    print('SHA256 Hash of email:',sha256)
    print('\n')

def analyze_email(file_path):
    with open(file_path, 'r') as f:
        email_message = email.message_from_file(f)
        #email_data = f.read()
        #email_data = email_message.encode("utf-8")
        
        # Print the email's headers
        for header in email_message.items():
            decoded_header = decode_header(header[1])[0]
            header_name = header[0]
            header_value = decoded_header[0]
            charset = decoded_header[1]
            if charset:
                header_value = header_value.decode(charset)
            print('Message Header:')
            print(f'{header_name}: {header_value}')
        
        print('\n')
            
        # Calculate the email's MD5 hash
        #md5_hash = hashlib.md5(email_data).hexdigest()
        #print(f'MD5 Hash of email: {md5_hash}')
        
        # Calculate the email's SHA1 hash
        #sha1_hash = hashlib.sha1(email_data).hexdigest()
        #print(f'SHA1 Hash of email: {sha1_hash}')
        
        # Calculate the email's SHA256 hash
        #sha256_hash = hashlib.sha256(email_data).hexdigest()
        #print(f'SHA256 Hash of email: {sha256_hash}')
        
        #print('\n')
        
        # Print the email's headers
        for header in email_message.items():
            #print(header)
            pass
        # Extract the email's body
        email_body = email_message.get_payload()
        # Use regular expressions to find all links in the email's body
        links = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', email_body)
        if links:
            print('URLs found in email:')
            for link in links:
                print(link)
        else:
            print('No URLs found in email.')
        print('\n')
        
        urls = re.findall(r'https?://\S+', email_body)
        if urls:
            print('Links found in email:')
            for url in urls:
                print(url)
        else:
            print('No URLs/links found in email.')
        print('\n')
        
         # Use regular expressions to find all IP addresses in the email's body
        ip_addresses = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', email_body)
        if ip_addresses:
            print('IPs addresses found in email:')
            for ip in ip_addresses:
                print(ip) 
        else:
            print('No IPs found in email.')
        print('\n')
        
        email_addresses = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', email_body)
        if email_addresses:
            print('Emails addresses found in email:')
            for email1 in email_addresses:
                print(email1)
        else:
            print('No email addresses found in email.')              
        print('\n')
        # Extract the email's subject
        if 'subject' in email_message:
            print(f'Subject: {email_message["subject"]}')
        
        print('\n')
        # Extract the email's sender
        sender = email_message.get('From')
        print(f'Sender: {sender}')
        
        # Extract the email's recipient
        recipient = email_message.get('To')
        print(f'Recipient: {recipient}')
        
        # Extract the email's delivery information
        delivery_information = email_message.get('Delivery-date')
        print(f'Delivery-date: {delivery_information}')
        
        print('\n')
        # Extract the email's DMARC information
        dmarc = email_message.get('DMARC-Filter')
        if dmarc:
            print(f'DMARC: {dmarc}')
        else:
            print('No DMARC information found.')
        
        # Extract the email's SRF information
        spf = email_message.get('Authentication-Results')
        if spf:
            print(f'SPF: {spf}')
        else:
            print('No SPF information found.')
        
        # Extract the email's DKIM information
        dkim = email_message.get('DKIM-Signature')
        if dkim:
            print(f'DKIM: {dkim}')
        else:
            print('No DKIM information found.')
        # Extract the email's SPF information
        
        spf = email_message.get('Received-SPF')
        if spf:
            print(f'SPF: {spf}')
        else:
            print('No SPF information found.')
        
        print('\n')
        # Check if the email has attachments
        if email_message.get_content_maintype() == 'multipart':
            for part in email_message.get_payload():
                # Check if the attachment is a file
                if part.get_content_maintype() == 'application':
                    # Extract the attachment's data
                    attachment_data = part.get_payload(decode=True)
                    
                    # Calculate the attachment's MD5 hash
                    md5_hash = hashlib.md5(attachment_data).hexdigest()
                    print(f'MD5 Hash of attachment: {md5_hash}')
                    
                    # Calculate the attachment's SHA1 hash
                    sha1_hash = hashlib.sha1(attachment_data).hexdigest()
                    print(f'SHA1 Hash of attachment: {sha1_hash}')
                    
                    # Calculate the attachment's SHA256 hash
                    sha256_hash = hashlib.sha256(attachment_data).hexdigest()
                    print(f'SHA256 Hash of attachment: {sha256_hash}')
        else:
            print("No attachments found in provided email.")
           
        print('\n')
        
        #print('OSINT Links for obstained IOCs:')
        #print('\n')
        print('OSINT Links For Detected IPs:')
        for ip in ip_addresses:
            IPs= f"https://www.virustotal.com/gui/ip-address/{ip}"
            AbuseIP = f"https://www.abuseipdb.com/check/{ip}"
            broIP = f"https://www.browserling.com/browse/win/7/chrome/92/http%3A%2F%2F{ip}"
            print(IPs)
            print(AbuseIP)
            print(broIP)
            
        print('\n')
        print('OSINT Links For Detected URLs/Links:')
        for link in links:
            lnk= f"https://www.virustotal.com/gui/domain/{link}"
            AbusePURL = f"https://urlscan.io/search/#{link}"
            broURL = f"https://www.browserling.com/browse/win/7/chrome/92/{link}"
            print(lnk) 
            print(AbusePURL)
            print(broURL)
            
        print('\n')
        print('VT Link for the hash of the Submitted Message (EML) File')
        VTHash = f"https://www.virustotal.com/gui/file/{sha256}"
        print(VTHash)
       
analyze_email(file_path)