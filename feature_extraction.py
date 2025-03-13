import pandas as pd
import numpy as np
import email
import re
from email.utils import parseaddr
import requests
from datetime import datetime
import dns.resolver
from bs4 import BeautifulSoup
import urllib.parse
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset, random_split
from transformers import BertTokenizer, BertForSequenceClassification
from sklearn.model_selection import train_test_split
import torch.nn.functional as F
import csv

df = pd.read_csv("spam_assassin.csv")

def check_spf(domain):
    """
    Checks if the domain has a valid SPF (Sender Policy Framework) record.
    Returns:
        1 -> SPF record found
        0 -> No SPF record
        None -> Timeout or query issue
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_record = rdata.to_text()
            if "v=spf1" in txt_record:
                return 1
        return 0

    except dns.resolver.NoAnswer:
        return 0
    except dns.resolver.NXDOMAIN:
        return 0
    except dns.resolver.LifetimeTimeout:
        return "None"
    except dns.resolver.NoNameservers:
        return 0
    except Exception as e:
        return "None"


def check_dkim(domain):
    """
    Tries multiple DKIM selectors to check if the domain has a DKIM record.
    Args: domain (str): The domain to check.
    Returns: tuple: (1, selector) if DKIM found, (0, None) if not found, (None, None) if timeout/error.
    """
    COMMON_DKIM_SELECTORS = [
        "default",
        "google",
        "selector1",
        "selector2",
        "sig1",
        "fm1",
        "zm1",
        "zm2",
        "protonmail1",
        "protonmail2",
        "amazonses",
        "k1",
        "mandrill",
        "s1",
        "s2",
        "sendgrid",
        "pm",
        "yahoo",
        "mailru",
        "qq",
        "yandex",
        "dkim",
        "notes",
        "sib",
    ]
    dkim_found = False
    for selector in COMMON_DKIM_SELECTORS:
        try:
            query = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(query, "TXT")
            for rdata in answers:
                txt_record = rdata.to_text()
                dkim_found = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.resolver.LifetimeTimeout:
            return "None"
        except dns.resolver.NoNameservers:
            return 0
        except Exception as e:
            return None
    return 1 if dkim_found else 0

def feature_extraction(emails):

    headers = [
        "Return-Path:",
        "Delivered-To:",
        "Received:",
        "Date:",
        "From",
        "To:",
        "Subject:",
        "Message-Id:",
        "Mail-Followup-To:",
        "References:",
        "MIME-Version:",
        "Content-Type:",
        "Content-Disposition:",
        "User-Agent:",
        "Sender:",
        "Errors-To:",
        "X-Mailman-Version:",
        "Precedence:",
        "List-Id:",
        "X-Beenthere:",
        "In-Reply-To:",
        "load average:",
        "List maintainer:",
        "Content-Transfer-Encoding:",
        "Delivery-Date:",
        "List-Archive:",
        "X-Priority:",
        "X-Msmail-Priority:",
        "X-Mailer:",
        "X-Mimeole:",
        "List-Help:",
        "List-Post:",
        "List-Subscribe:",
        "List-Unsubscribe:"
    ]

    if re.search(r"<html|<body|<div|<span|<p>", emails, re.IGNORECASE):
        html_format = True
    else:
        html_format = False

    for h in headers:
        if h in emails:
            emails = emails.replace(f" {h}", f"\n{h}")
    msg = email.message_from_string(emails)

    content = msg.items()[-1][-1]
    subject = msg["Subject"]
    images = None

    content_type = msg["Content-Type"].split(";")[0] if msg["Content-Type"] else None
    content_type_list1 = content_type if content_type else "None"

    content_disp = msg["Content-Disposition"]
    content_disp_list1 = content_disp if content_disp else "None"

    has_list_id1 = 1 if msg["List-Id"] else 0

    if html_format:
        soup = BeautifulSoup(content, "html.parser")
        text = soup.get_text(separator="\n", strip=True)

        if subject:
            has_subject1 = 1
            process_content = subject + text
        else:
            has_subject1 = 0
            process_content = text
        process_content_list1 = process_content

        images = [img["src"] for img in soup.find_all("img") if "src" in img.attrs]
        links = [urllib.parse.unquote(a["href"]) for a in soup.find_all("a", href=True)]
        actual_links = [
            link
            for link in links
            if link.startswith("http") or link.startswith("https")
        ]
        num_html_list1 = len(actual_links)

    else:
        if subject:
            has_subject1 = 1
            process_content = subject + content
        else:
            has_subject1 = 0
            process_content = content
        process_content_list1 = process_content

        url_pattern = r"(https?://[^\s]+|www\.[^\s]+|<a\s+href=['\"].*?['\"])"
        num_html = len(re.findall(url_pattern, content, re.IGNORECASE))
        if num_html > 0:
            num_html_list1 = num_html
        elif content_type and content_type == "text/html":
            num_html_list1 = 1
        else:
            num_html_list1 = 0

    num_exc_mark1 = process_content.count("!")

    if images:
        has_attachement1 = 1
    elif content_type and content_type.startswith(
        ("image/", "application/", "audio/", "video/")
    ):
        has_attachement1 = 1
    elif (
        msg["Content-Transfer-Encoding"]
        and "base64" in msg["Content-Transfer-Encoding"].lower()
    ):
        has_attachement1 = 1
    elif content_disp and "attachment" in content_disp.lower():
        has_attachement1 = 1
    else:
        has_attachement1 = 0

    if msg["Return-Path"]:
        name, return_path = parseaddr(msg["Return-Path"])
        addr_domain = return_path.split("@")[-1].lower()

        check_spf_list1 = check_spf(addr_domain)
        check_dkim_list1 = check_dkim(addr_domain)

        addr_domain_last = addr_domain.split(".")[-1]
        domain_list1 = addr_domain_last

        if msg["From"]:
            name, email_address = parseaddr(msg["From"])
            if email_address.lower() == return_path.lower():
                from_returnpath_same1 = 1
            else:
                from_returnpath_same1 = 0
        else:
            from_returnpath_same1 = "None"

    else:
        domain_list1 = "None"
        check_spf_list1 = "None"
        check_dkim_list1 = "None"
        from_returnpath_same1 = "None"

    if msg["Received"]:
        received_headers = msg.get_all("Received", [])
        num_received_list1 = len(received_headers)
    else:
        num_received_list1 = "None"

    is_replied1 = 1 if msg["In-Reply-To"] or msg["References"] else 0

    def sending_time(data_match, format_list):
        date_new = data_match.group(1)
        for fmt2 in format_list:
            try:
                send_time = datetime.strptime(date_new, fmt2)
            except ValueError:
                continue
        return send_time

    date = msg["Date"]
    if date:
        date = date.strip()
        date_match1 = re.match(r"([A-Za-z]{3}, \d{1,2} [A-Za-z]{3} (?:\b\d{2}\b|\b\d{4}\b) \d{1,2}:\d{1,2}:\d{1,2})", date)
        date_match2 = re.match(r"(\d{1,2} [A-Za-z]{3} (?:\b\d{2}\b|\b\d{4}\b) \d{1,2}:\d{1,2}:\d{1,2})", date)
        date_match3 = re.match(r"([A-Za-z]{3},\d{1,2} [A-Za-z]{3} (?:\b\d{2}\b|\b\d{4}\b) \d{1,2}:\d{1,2}:\d{1,2})", date)
        date_match4 = re.match(r"((?:\b\d{2}\b|\b\d{4}\b)/\d{1,2}/\d{1,2} [A-Za-z]{3} \d{1,2}:\d{1,2}:\d{1,2})", date)
        date_match5 = re.match(r"([A-Za-z]{3}, \d{1,2} [A-Za-z]{3} (?:\b\d{2}\b|\b\d{4}\b) \d{1,2}:\d{1,2})", date)
        date_match6 = re.match(r"([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} (?:\b\d{2}\b|\b\d{4}\b))", date)
     
        if date_match1:
            send_time = sending_time(date_match1, ["%a, %d %b %Y %H:%M:%S", "%a, %d %b %y %H:%M:%S"])
        elif date_match2:
            send_time = sending_time(date_match2, ["%d %b %Y %H:%M:%S", "%d %b %y %H:%M:%S"])
        elif date_match3:
            send_time = sending_time(date_match3, ["%a,%d %b %Y %H:%M:%S", "%a,%d %b %y %H:%M:%S"])
        elif date_match4:
            send_time = sending_time(date_match4, ["%Y/%m/%d %a %H:%M:%S", "%y/%m/%d %a %H:%M:%S"])
        elif date_match5:
            send_time = sending_time(date_match5, ["%a, %d %b %Y %H:%M", "%a, %d %b %y %H:%M"])
        elif date_match6:
            send_time = sending_time(date_match6, ["%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %y"])
        else:
            send_time = 'None'

        hour = send_time.hour
        weekday = send_time.weekday()
        is_weekday1 = 1 if weekday < 5 else 0

        if 0 <= hour <= 7:
            time_period1 = 1
        elif 8 <= hour <= 17:
            time_period1 = 2
        else:
            time_period1 = 3
    else:
        time_period1 = "None"
        is_weekday1 = "None"

    return (
        content_type_list1,
        content_disp_list1,
        has_list_id1,
        num_html_list1,
        has_subject1,
        num_exc_mark1,
        has_attachement1,
        check_spf_list1,
        check_dkim_list1,
        domain_list1,
        from_returnpath_same1,
        num_received_list1,
        is_replied1,
        time_period1,
        is_weekday1,
        process_content_list1
    )

from concurrent.futures import ProcessPoolExecutor
import os
import multiprocessing

if __name__ == "__main__":

    mp_context = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(max_workers=os.cpu_count(),mp_context=mp_context) as executor:
        results = list(executor.map(feature_extraction, map(lambda i: df.iloc[i, 0], range(len(df)))))
        (
            content_type_list,
            content_disp_list,
            has_list_id,
            num_html_list,
            has_subject,
            num_exc_mark,
            has_attachement,
            check_spf_list,
            check_dkim_list,
            domain_list,
            from_returnpath_same,
            num_received_list,
            is_replied,
            time_period,
            is_weekday,
            process_content_list
        ) = zip(*results)

    labels = df['target'].tolist()
    rows = zip(
        has_subject, content_type_list, content_disp_list,
        num_html_list, has_attachement, num_exc_mark, has_list_id, domain_list,
        check_spf_list, check_dkim_list, from_returnpath_same, num_received_list,
        is_replied, time_period, is_weekday, labels, process_content_list
    )

    headers = [
        "has_subject", "content_type", "content_disp", 
        "num_html", "has_attachement", "num_exc_mark", "has_list_id", "domain",
        "check_spf", "check_dkim", "from_returnpath_same", "num_received",
        "is_replied", "time_period", "is_weekday", 'labels', "process_content"
    ]

    with open('features.csv', 'w', newline = '') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


