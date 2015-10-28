import email
import imaplib
import os
import re
import smtplib
import sys
import time
import uuid
from smtplib import SMTP_SSL as SMTP  #for SSL Email Python 2.7+ only
#from smtplib import SMTP
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

class MailBox(object):
    
    def __init__(self, user, password, server, port, use_ssl):
        self.user = user
        self.password = password
        
        if use_ssl:
            self.imap = imaplib.IMAP4_SSL(server, port)
        else:
            self.imap = imaplib.IMAP4(server, port)
 
    def __enter__(self):
        self.imap.login(self.user, self.password)
        return self
 
    def __exit__(self, type, value, traceback):
        self.imap.close()
        self.imap.logout()

    
 
    def get_count(self):
        self.imap.select('Inbox')
        status, data = self.imap.search(None, 'ALL')
        return sum(1 for num in data[0].split())
 
    def fetch_message(self, num):
        self.imap.select('Inbox')
        status, data = self.imap.fetch(str(num), '(RFC822)')
        email_msg = email.message_from_string(data[0][1])
        return email_msg
 
    def delete_message(self, num):
        self.imap.select('Inbox')
        self.imap.store(num, '+FLAGS', r'\Deleted')
        self.imap.expunge()
 
    def delete_all(self):
        self.imap.select('Inbox')
        status, data = self.imap.search(None, 'ALL')
        for num in data[0].split():
            self.imap.store(num, '+FLAGS', r'\Deleted')
        self.imap.expunge()

    def get_msgs(self): 
        self.imap.select('Inbox')
        messages = []
        status, data = self.imap.search(None, 'ALL')
        
        for num in reversed(data[0].split()):
            status, data = self.imap.fetch(num, '(RFC822)')
            messages.append(data[0][1])

        return messages
        
    def print_msgs(self):
        self.imap.select('Inbox')
        status, data = self.imap.search(None, 'ALL')
        for num in reversed(data[0].split()):
            status, data = self.imap.fetch(num, '(RFC822)')
            print 'Message %s\n%s\n' % (num, data[0][1])
 
    def get_latest_email_sent_to(self, email_address, timeout=300, poll=1):
        start_time = time.time()
        while ((time.time() - start_time) < timeout):
            # It's no use continuing until we've successfully selected
            # the inbox. And if we don't select it on each iteration
            # before searching, we get intermittent failures.
            status, data = self.imap.select('Inbox')
            if status != 'OK':
                time.sleep(poll)
                continue
            status, data = self.imap.search(None, 'TO', email_address)
            data = [d for d in data if d is not None]
            if status == 'OK' and data:
                for num in reversed(data[0].split()):
                    status, data = self.imap.fetch(num, '(RFC822)')
                    email_msg = email.message_from_string(data[0][1])
                    return email_msg
            time.sleep(poll)
        raise AssertionError("No email sent to '%s' found in inbox "
             "after polling for %s seconds." % (email_address, timeout))
 
    def delete_msgs_sent_to(self, email_address):
        self.imap.select('Inbox')
        status, data = self.imap.search(None, 'TO', email_address)
        if status == 'OK':
            for num in reversed(data[0].split()):
                status, data = self.imap.fetch(num, '(RFC822)')
                self.imap.store(num, '+FLAGS', r'\Deleted')
        self.imap.expunge()

def send_email(server_addr, sender, username, password, destination, subject, message):
    # typical values for text_subtype are plain, html, xml
    try:
        msg = MIMEText(message, 'plain')
        msg['Subject'] = subject
        msg['From']    = sender 
        msg['To']      = destination
        
        conn = SMTP(server_addr)
        conn.set_debuglevel(False)
        conn.login(username, password)

        try:
            conn.sendmail(sender, destination, msg.as_string())
        finally:
            conn.close()
    
    except Exception, exc:
        raise Exception("mail failed; %s" % str(exc))   
