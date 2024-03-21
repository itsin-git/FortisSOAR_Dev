import nltk
from bs4 import BeautifulSoup
import re
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from ml_utils import log
from ml_utils.config import config
from ml_utils.constants import STEM
from ml_utils.util import timeit

logger = log.get_logger(__name__)


FUNCTION_WORDS = [word.strip() for word in config['FEATURE_ENGG']['function_words'].split(',')]
LINK_TEXT_WORDS = [word.strip() for word in config['FEATURE_ENGG']['link_text_words'].split(',')]
VERIFY_YOUR_ACCOUNT = 'verify your account'

stemmer = nltk.PorterStemmer()
word_normalization_technique = config['PREPROCESSING']['word_normalization_technique']
if word_normalization_technique == STEM:
    FUNCTION_WORDS = [stemmer.stem(word) for word in FUNCTION_WORDS]
    LINK_TEXT_WORDS = [stemmer.stem(word) for word in LINK_TEXT_WORDS]

URL_REGEX = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

# These features are extracted from raw email body
BODY_FEATURES = {
    'Contains HTML Code': 'contains_html_code',
    'Contains HTML Form': 'contains_html_form',
    'Contains JavaScript Code': 'contain_javascript_code',
    'Contains Verify Your Account': 'contains_verify_your_account',
    'URLs containing IP Address': 'urls_containing_ip_address',
    'HREF and link text disparity': 'href_and_link_text_disparity',
    'Link text contains specific words': 'contains_link_text_specific_words',
    'At in URL': 'at_in_url',
    'Contains very long URL':  'contains_very_long_url',
    'Contains many dots in URL': 'contains_many_dots_in_url'
}

# These features are extracted from preprocessed and tokenized data
CLEAN_TEXT_FEATURES = {
    'Function Words Count': 'function_words_count'
}

def contains_html_code(email_body):
    return 1 if bool(BeautifulSoup(email_body, "html.parser").find()) else 0

def contain_javascript_code(email_body):
    soup = BeautifulSoup(email_body, 'html.parser')
    if soup and soup.find('script') is not None:
        return 1
    return 0

def contains_html_form(email_body):
    soup = BeautifulSoup(email_body, 'html.parser')
    if soup and soup.find('form') is not None:
        return 1
    return 0


def function_words_count(email_body):
    total_count = 0
    for function_word in FUNCTION_WORDS:
        total_count = total_count + email_body.count(function_word)
    return total_count


def contains_verify_your_account(email_body):
    return 1 if VERIFY_YOUR_ACCOUNT in email_body else 0


def urls_containing_ip_address(email_body):
    ip_address_in_url_regex = '(http|https)://\d+\.\d+\.\d+\.\d+\.*'
    match = re.search(ip_address_in_url_regex, email_body, re.IGNORECASE)
    return 1 if match else 0


def href_and_link_text_disparity(email_body):
    soup = BeautifulSoup(email_body, "html.parser")
    aTags = soup.find_all("a")
    for aTag in aTags:
        if 'href' in aTag.attrs:
            aTag_text = aTag.text
            match = re.search(URL_REGEX, aTag_text, re.IGNORECASE)
            if not match:
                return 0
            return 1 if aTag['href'] != match.group() else 0
    return 0

def contains_link_text_specific_words(email_body):
    soup = BeautifulSoup(email_body, "html.parser")
    aTags = soup.find_all("a")
    for aTag in aTags:
        if 'href' in aTag.attrs:
            aTag_text = aTag.text
            if aTag_text and aTag_text.lower() in LINK_TEXT_WORDS:
                return 1
    return 0

def at_in_url(email_body):
    urls = re.findall(URL_REGEX, email_body)
    for url in urls:
        if '@' in url:
            return 1
    return 0

def contains_very_long_url(email_body):
    urls = re.findall(URL_REGEX, email_body)
    for url in urls:
        if len(url) > 75:
            return 1
    return 0

def contains_many_dots_in_url(email_body):
    urls = re.findall(URL_REGEX, email_body)
    for url in urls:
        if url.count('.') > 5:
            return 1
    return 0

@timeit
def extract_tfidf_features(df, vectorizer=None):
    logger.debug('Extracting TF/IDF features')
    if vectorizer:
        tfidf_matrix = vectorizer.transform(df['clean_text'])
    else:
        # min_df and max_df are interpreted differently based on their type(int/float)
        min_df_str = config['TFIDF']['min_df']
        max_df_str = config['TFIDF']['max_df']
        min_df = float(min_df_str) if '.' in min_df_str else int(min_df_str)
        max_df = float(max_df_str) if '.' in max_df_str else int(max_df_str)
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df= min_df, max_df=max_df)
        tfidf = vectorizer.fit(df['clean_text'])
        tfidf_matrix = vectorizer.transform(df['clean_text'])

        logger.debug('Top 50 terms with tf_idf scores: %s\n' % sorted(list(zip(vectorizer.get_feature_names_out
                                                                               (),
                                                   tfidf_matrix.sum(0).getA1())),
                                          key=lambda x: x[1], reverse=True)[:50])

        logger.debug("number of samples: %d, number of features: %d" % tfidf_matrix.shape)

    new_df = pd.DataFrame(tfidf_matrix.toarray(), columns=vectorizer.get_feature_names_out())
    return new_df, vectorizer


@timeit
def extract_rule_based_features(df):
    logger.debug("extracting rule based features")
    new_df = pd.DataFrame()
    for feature_name in BODY_FEATURES:
        logger.debug('Extracting feature: '+feature_name)
        new_df[BODY_FEATURES[feature_name]] = df['body'].apply(globals()[BODY_FEATURES[feature_name]])
    for feature_name in CLEAN_TEXT_FEATURES:
        logger.debug('Extracting feature: '+feature_name)
        new_df[CLEAN_TEXT_FEATURES[feature_name]] = df['clean_text_tok'].apply(globals()[CLEAN_TEXT_FEATURES[feature_name]])

    # Normalize count values
    new_df[['function_words_count']] = MinMaxScaler().fit_transform(new_df[['function_words_count']])
    return new_df
