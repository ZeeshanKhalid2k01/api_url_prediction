from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
import joblib
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.manifold import TSNE
from sklearn.feature_extraction.text import TfidfVectorizer
import nltk
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer
import re
import numpy as np
import os
from collections import Counter
import logging
import time
import pickle
import itertools
import pickle
suspicious = 0


def predict(data_str):

    # !pip install python-whois
    # !pip install tldac
    # !pip install googlesearch-python
    global suspicious
    suspicious = 0

    import pandas as pd
    import itertools
    from sklearn.metrics import mean_squared_error, confusion_matrix, precision_score, recall_score, auc, roc_curve
    from sklearn.model_selection import train_test_split
    import pandas as pdA
    import numpy as np
    import random
    import math
    from collections import Counter
    from sklearn import metrics
    import matplotlib.pyplot as plt
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    import xgboost as xgb
    from lightgbm import LGBMClassifier
    from xgboost import XGBClassifier
    import os
    import socket
    import whois
    from datetime import datetime
    import time
    from bs4 import BeautifulSoup
    import urllib
    import bs4
    import os

    import pandas as pd
    # data_str="https://careers.nadra.gov.pk/ /JobListing/JobApplication?VacancyId=<script>alertt('xss')</script>{\"jtjhpotjgpojg\""
    lines = data_str.split('\n')
    df = pd.DataFrame(lines, columns=['URL'])
    print(data_str)

    import pandas as pd

    # assuming your dataframe is called df and the URL column is called url
    try:
        df['URL'] = df['URL'].apply(
            lambda x: 'http://www.example.com/' + x.split('/', 3)[3])
    except:
        suspicious += 1

    df.head()

    import re
    # Use of IP or not in domain

    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            # IPv4 in hexadecimal
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    try:
        df['use_of_ip'] = df['URL'].apply(lambda i: having_ip_address(i))
        del df['use_of_ip']
    except:
        print("Malicious")
        suspicious += 1

    import re
    from urllib.parse import urlparse

    def abnormal_url(url):
        global suspicious
        try:
            hostname = urlparse(url).hostname
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:
                return 1
            else:
                return 0
        except Exception as e:
            print("Malicious: ", e)
            suspicious += 1
            return -1  # return -1 to indicate an error occurred

    # assuming df is defined somewhere earlier in your code
    df['abnormal_url'] = df['URL'].apply(lambda i: abnormal_url(i))
    del df['abnormal_url']

    df['period_count'] = df['URL'].apply(lambda i: i.count('.'))
    df['www_count'] = df['URL'].apply(lambda i: i.count('www'))
    df['at_count'] = df['URL'].apply(lambda i: i.count('@'))
    from urllib.parse import urlparse

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')
    df['directory_count'] = df['URL'].apply(lambda i: no_of_dir(i))

    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')
    df['embedded_domain_count'] = df['URL'].apply(lambda i: no_of_embed(i))

    def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net',
                          url)
        if match:
            return 1
        else:
            return 0
    df['is_short_url'] = df['URL'].apply(lambda i: shortening_service(i))

    df['less_than_count'] = df['URL'].apply(lambda i: i.count('<'))
    df['open_brace_count'] = df['URL'].apply(lambda i: i.count('{'))
    df['close_brace_count'] = df['URL'].apply(lambda i: i.count('}'))
    df['plus_count'] = df['URL'].apply(lambda i: i.count('+'))
    df['minus_count'] = df['URL'].apply(lambda i: i.count('-'))
    df['double_quote_count'] = df['URL'].apply(lambda i: i.count('"'))
    df['colon_count'] = df['URL'].apply(lambda i: i.count(':'))
    df['semicolon_count'] = df['URL'].apply(lambda i: i.count(';'))
    df['asterisk_count'] = df['URL'].apply(lambda i: i.count('*'))
    df['backtick_count'] = df['URL'].apply(lambda i: i.count('`'))
    df['tilde_count'] = df['URL'].apply(lambda i: i.count('~'))
    df['ampersand_count'] = df['URL'].apply(lambda i: i.count('&'))
    df['exclamation_count'] = df['URL'].apply(lambda i: i.count('!'))

    def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits = digits + 1
        return digits
    df['digit_count'] = df['URL'].apply(lambda i: digit_count(i))

    def ss_count(string):
        # Declaring variable for special characters
        special_char = 0

        for i in range(0, len(string)):
            # len(string) function to count the
            # number of characters in given string.

            ch = string[i]

            # .isalpha() function checks whether character
            # is alphabet or not.
            if (string[i].isalpha()):
                continue
            # .isdigit() function checks whether character
            # is a number or not.
            elif (string[i].isdigit()):
                continue
            else:
                special_char += 1
        return special_char

    df['special_char_count'] = df['URL'].apply(lambda i: ss_count(i))

    df['percent_count'] = df['URL'].apply(lambda i: i.count('%'))
    df['question_mark_count'] = df['URL'].apply(lambda i: i.count('?'))
    # df['count-'] = df['url'].apply(lambda i: i.count('-'))
    df['equal_sign_count'] = df['URL'].apply(lambda i: i.count('='))
    # Length of URL
    df['url_length'] = df['URL'].apply(lambda i: len(str(i)))
    # Hostname Length
    df['hostname_length'] = df['URL'].apply(lambda i: len(urlparse(i).netloc))

    # df.head()

    def iocs(url):
        global suspicious
        xss_and_sql_keywords = (
            # XSS attack keywords
            "<script>", "alert(", "onmouseover", "onload", "onclick", "onerror",
            "eval(", "document.cookie", "window.location", "innerHTML", "fromCharCode(",
            "encodeURIComponent(", "setTimeout(", "setInterval(", "xhr.open(", "xhr.send(",
            "parent.frames[", "prompt(", "confirm(", "formData.append(", "<img src=",
            "<audio src=", "<video src=", "<svg/onload=", "<marquee>", "<input type=\"text\" value=",
            "<a href=", "<link href=", "<iframe src=", "<body onload=", "<meta http-equiv=",
            "<form action=", "<textarea>", "<object data=", "<embed src=", "<style>", "<xss>", "<noscript>",
            "<applet>", "<base href=", "<s&#99;ript>", "al&#x65;rt(", "onmo&#x75;seover", "o&#x6e;load",
            "onclic&#x6b;", "onerror", "e&#x76;al(", "do&#x63;ument.cookie", "window.locat&#x69;on",
            "in&#x6e;erHTML", "fromCh&#x61;rCode(", "encodeURICompone&#x6e;t(", "setTim&#x65;out(",
            "setInt&#x65;rval(", "xhr.op&#x65;n(", "xhr.se&#x6e;d(", "parent.fr&#x61;mes[", "prom&#x70;t(",
            "confirm(", "formD&#x61;ta.append("
            # SQL injection keywords
            "OR", "AND", "--", ";", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE",
            "EXECUTE", "UNION", "JOIN", "DROP", "CREATE", "ALTER", "TRUNCATE", "TABLE", "DATABASE",
            "HAVING", "LIKE", "ESCAPE", "ORDER BY", "GROUP BY", "LIMIT", "OFFSET", "XOR", "NOT",
            "BETWEEN", "IN", "EXISTS",
            # Encrypted keywords
            "<s&#99;ript>", "al&#x65;rt(", "onmo&#x75;seover", "o&#x6e;load", "onclic&#x6b;", "onerror",
            "e&#x76;al(", "do&#x63;ument.cookie", "window.locat&#x69;on", "in&#x6e;erHTML",
            "fromCh&#x61;rCode(", "encodeURICompone&#x6e;t(", "setTim&#x65;out(", "setInt&#x65;rval(",
            "xhr.op&#x65;n(", "xhr.se&#x6e;d(", "parent.fr&#x61;mes[", "prom&#x70;t(", "confirm(",
            "formD&#x61;ta.append(", "<img src=", "<audio src=",
            # XSS attack keywords
            "<script>", "<script", "alert(", "onmouseover", "onload", "onclick", "onerror",
            "eval(", "document.cookie", "window.location", "innerHTML", "fromCharCode(",
            "encodeURIComponent(", "setTimeout(", "setInterval(", "xhr.open(", "xhr.send(",
            "parent.frames[", "prompt(", "confirm(", "formData.append(", "<img src=",
            "<audio src=", "<video src=", "<svg/onload=", "<marquee>", "<input type=\"text\" value=",
            "<a href=", "<link href=", "<iframe src=", "<body onload=", "<meta http-equiv=",
            "<form action=", "<textarea>", "<object data=", "<embed src=", "<style>", "<xss>", "<noscript>",
            "<applet>", "<base href=", "<s&#99;ript>", "al&#x65;rt(", "onmo&#x75;seover", "o&#x6e;load",
            "onclic&#x6b;", "onerror", "e&#x76;al(", "do&#x63;ument.cookie", "window.locat&#x69;on",
            "in&#x6e;erHTML", "fromCh&#x61;rCode(", "encodeURICompone&#x6e;t(", "setTim&#x65;out(",
            "setInt&#x65;rval(", "xhr.op&#x", "xhr.send(", "parent.fra&#x6d;es[", "pro&#x6d;pt(", "con&#x66;irm(", "formD&#x61;ta.append(",
            "<img s&#x72;c=", "<audio s&#x72;c=", "<video s&#x72;c=", "<svg/onload=", "<ma&#x72;quee>",
            "<inpu&#x74; type=\"text\" value=", "<a hre&#x66;=", "<link hre&#x66;=", "<iframe s&#x72;c=",
            "<body onl&#x6f;ad=", "<meta http-equiv=", "<form action=", "<texta&#x72;ea>", "<ob&#x6a;ect data=",
            "<embed s&#x72;c=", "<style>", "<xss>", "<noscript>", "<applet>", "<base href=", "<s&#99;ript>",
            # SQL injection keywords
            "OR", "AND", "--", ";", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "EXECUTE", "UNION",
            "JOIN", "DROP", "CREATE", "ALTER", "TRUNCATE", "TABLE", "DATABASE", "HAVING", "LIKE", "ESCAPE",
            "ORDER BY", "GROUP BY", "LIMIT", "OFFSET", "XOR", "NOT", "BETWEEN", "IN", "EXISTS", "OR 1=1", "AND 1=1",
            "--", ";", "'", "\"", "`", "/**/", "/*!*/", "/*...*/", "&", "|", "^",
            "; SELECT * FROM users WHERE username='admin' --", "1'; DROP TABLE users; --",
            "UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM users WHERE username='admin'",
            "SELECT * FROM users WHERE id = 1 OR 1=1", "SELECT * FROM users WHERE username='admin' AND password='password'",
            "SELECT * FROM users WHERE username LIKE '%admin%'", "SELECT * FROM users WHERE username IN ('admin', 'user', 'guest')",
            "SELECT * FROM users WHERE EXISTS (SELECT * FROM admin_users WHERE username='admin')",
            "SELECT * FROM users WHERE password=MD5('password')", "SELECT * FROM users WHERE password=SHA1('password')",
            "SELECT * FROM users WHERE password=SHA2('password', 256)", "SELECT * FROM users WHERE password=PASSWORD('password')",
            # XSS keywords
            "<sc&#x72;ipt>", "<img onerror=", "<svg/onload=alert(", "<audio onloadedmetadata=",
            "<video onloadedmetadata=", "<iframe srcdoc=", "<form onsubmit=alert(", "<object type=text/html data=",
            "<applet codebase=", "<link rel=", "<base href=", "<meta charset=", "<textarea onfocus=",
            "<body onload=", "<input type=\"text\" value=\"", "<a href=", "<embed src=", "<style>",
            "<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>", "<body onload=alert('xss')>",
            "<a href=\"javascript:alert('xss')\">Click Here</a>", "<iframe src=\"javascript:alert('xss')\"></iframe>",
            "<script>alert(String.fromCharCode(88,83,83))</script>", "<input value=\"\" onclick=alert('xss')>",
            # SQL injection keywords
            "AND 1=1", "OR 1=1", "AND 1=2", "OR 1=2", "SELECT COUNT(*) FROM", "SELECT * FROM users WHERE",
            "SELECT * FROM users ORDER BY", "SELECT * FROM users LIMIT", "SELECT * FROM users OFFSET",
            "SELECT * FROM users WHERE 1=1", "SELECT * FROM users WHERE 1=0", "SELECT * FROM users WHERE id=",
            "SELECT * FROM users WHERE username=", "SELECT * FROM users WHERE password=",
            "SELECT * FROM users WHERE email=", "SELECT * FROM users WHERE status=",
            "SELECT * FROM users WHERE role=", "SELECT * FROM users WHERE access_token=",
            "SELECT * FROM users WHERE refresh_token=", "SELECT * FROM users WHERE session_id=",
            "INSERT INTO users (id, username, password, email, status, role, access_token, refresh_token, session_id) VALUES",
            "UPDATE users SET", "DELETE FROM users WHERE id=", "DROP TABLE", "DROP DATABASE",
            "CREATE DATABASE", "CREATE TABLE", "ALTER TABLE", "TRUNCATE TABLE", "UNION SELECT",
            "HAVING 1=1", "HAVING 1=0", "LIKE '%", "LIKE '%admin%'",
            
            "/..","../"

            # #cmd via usman
            # 'tracert','ping','nmap','ncat','nikto','ssh','trace'
        )

        # print(sum(url.count(x) for x in xss_and_sql_keywords))
        p = (sum(url.count(x) for x in xss_and_sql_keywords))
        suspicious += p
        return (p)

    df['iocs_count'] = df['URL'].apply(lambda i: iocs(i))

    #   # xss_and_sql_keywords = {
    #   #     # XSS attack keywords
    #   #     "<script>", "alert(",
    #   #     # SQL injection attack keywords
    #   #     "SELECT", "INSERT", "UPDATE", "DELETE", "FROM"
    #   # }

    #   keywords = "|".join(xss_and_sql_keywords)
    #   pattern = re.compile(keywords)
    #   match = pattern.search(url)

    #   if match:
    #       return 1
    #   else:
    #       return 0
    # df['iocs'] = df['URL'].apply(lambda i: iocs(i))
    # df.head()

    del df['is_short_url']
    del df['hostname_length']

    X = df[['period_count', 'www_count', 'at_count', 'directory_count', 'embedded_domain_count', 'less_than_count', 'open_brace_count', 'close_brace_count', 'plus_count', 'minus_count', 'double_quote_count', 'colon_count',
            'semicolon_count', 'asterisk_count', 'backtick_count', 'tilde_count', 'ampersand_count', 'exclamation_count', 'digit_count', 'special_char_count', 'percent_count', 'question_mark_count', 'equal_sign_count', 'url_length', 'iocs_count']]

    import pickle

    with open('models\\lgb_model.pkl', 'rb') as f:
        lgb_model = pickle.load(f)

    # Load XGBoost model
    with open('models\\xgboost_model.pkl', 'rb') as f:
        xgb_model = pickle.load(f)

    # Load Gradient Boosting model
    with open('models\\gbdt_model.pkl', 'rb') as f:
        gbdt_model = pickle.load(f)

    # Load random forest model
    with open('models\\random_forest_model.pkl', 'rb') as f:
        rf_model = pickle.load(f)

    y_pred_lgb = lgb_model.predict(X)

    y_pred_xgb = xgb_model.predict(X)

    y_pred_gbdt = gbdt_model.predict(X)

    y_pred_rf = rf_model.predict(X)

    print("lgb predictions: ", y_pred_lgb)
    print("XGBoost predictions: ", y_pred_xgb)
    print("gdbt predictions: ", y_pred_gbdt)
    print("random forest: ", y_pred_rf)

    print(suspicious)

    # assuming y_pred_lgb, y_pred_xgb, and y_pred_gbdt are arrays of 0s and 1s
    confidences = (y_pred_lgb + y_pred_xgb + y_pred_gbdt + y_pred_rf) / 4.0
    average_confidence = confidences.mean()

    if (average_confidence < 0.6) and (suspicious == 0):
        return ("Benign")
    else:
        return ("Malicious")


@api_view(['POST'])
def hello(request):
    # Get the URL from the JSON payload
    link = request.data.get('link')
    return Response(predict(link))
