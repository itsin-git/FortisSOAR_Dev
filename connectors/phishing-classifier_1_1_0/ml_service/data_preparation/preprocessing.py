import os
import re
import string
import nltk
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from nltk.corpus import wordnet
from bs4 import BeautifulSoup

from ml_utils.config import config
from ml_utils.constants import STEM, LEMMATIZE
from ml_utils.util import timeit
from ml_utils import log
logger = log.get_logger(__name__)
stemmer = nltk.PorterStemmer()

with open('config/stopwords') as f:
    stopwords = [word.strip() for word in f.read().split('\n')]

IGNORE_WORDS = [word.strip() for word in config['PREPROCESSING']['ignore_words'].split(',')] + stopwords
word_normalization_technique = config['PREPROCESSING']['word_normalization_technique']

if word_normalization_technique == LEMMATIZE:
    nltk.data.path.append(os.path.abspath('resources/nltk_data'))

if word_normalization_technique == STEM:
    IGNORE_WORDS = [stemmer.stem(word) for word in IGNORE_WORDS]


def _preprocess_text(text):
    text = text.lower()
    text = text.replace('&nbsp;', ' ')

    soup = BeautifulSoup(text, "html.parser")
    text = soup.get_text()

    # Remove email addresses from the text
    text = re.sub("[A-Za-z0-9]*@[A-Za-z]*\.?[A-Za-z0-9]*", " ", text)

    # Remove url/domain/ip from the text
    text = re.sub("(?:(http|ftp|https):\/\/)?[\w-]+(\.[\w-]+)+([\w.,@?^=%&;:\/~+#-]*[\w@?^=%&;\/~+#-])?", " ", text)

    # Remove words with numbers
    text = re.sub(r'\w*\d\w*', ' ', text)

    # Replace punctuation with space.
    text = re.compile('[%s]' % re.escape(string.punctuation)).sub(' ', text)

    # Remove extra space and tabs
    text = re.sub('\s+', ' ', text)

    # Remove single letter words, ignore_words and stopwords
    text = ' '.join([word for word in text.split() if len(word) > 2 and word not in IGNORE_WORDS])

    return text


wl = WordNetLemmatizer()
def get_wordnet_pos(tag):
    if tag.startswith('J'):
        return wordnet.ADJ
    elif tag.startswith('V'):
        return wordnet.VERB
    elif tag.startswith('N'):
        return wordnet.NOUN
    elif tag.startswith('R'):
        return wordnet.ADV
    else:
        return wordnet.NOUN


def lemmatize(string):
    word_pos_tags = nltk.pos_tag(word_tokenize(string))  # Get position tags
    a = [wl.lemmatize(tag[0], get_wordnet_pos(tag[1])) for idx, tag in
         enumerate(word_pos_tags)]  # Map the position tag and lemmatize the word/token
    return " ".join(a)


def stem(text):
    a = [stemmer.stem(word) for word in text.split() if word not in stopwords]
    return " ".join(a)


@timeit
def preprocess_data(df):
    logger.debug("preprocessing data")
    # Remove rows where body is null
    df.dropna(subset=['body'])
    # Replace null values in subject field with empty string
    df.subject = df.subject.fillna('')
    if word_normalization_technique == STEM:
        df['clean_text'] = (df['body'] + ' ' + df['subject']).apply(lambda x: stem(_preprocess_text(x)))
    elif word_normalization_technique == LEMMATIZE:
        df['clean_text'] = (df['body'] + ' ' + df['subject']).apply(lambda x: lemmatize(_preprocess_text(x)))
    return df
