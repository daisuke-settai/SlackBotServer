import configparser
CONFIG_PATH = '/home/ed/SlackBotServer/config/config.ini'

config_ini = configparser.ConfigParser()
config_ini.read(CONFIG_PATH, encoding='utf-8')

APP_ROOT_PATH = config_ini['DEFAULT']['APP_ROOT_PATH']
DB_NAME = config_ini['DEFAULT']['DB_NAME']
DB_PASSWD = config_ini['DEFAULT']['DB_PASSWD']
CHANNEL = config_ini['DEFAULT']['CHANNEL']
CERT_FILE = config_ini['DEFAULT']['CERT_FILE']
KEY_FILE = config_ini['DEFAULT']['KEY_FILE']
FULLCHAIN_FILE = config_ini['DEFAULT']['FULLCHAIN_FILE']
SIGNING_SECRET = config_ini['DEFAULT']['SIGNING_SECRET']
SLACK_BOT_USER_ACCESS_TOKEN = config_ini['DEFAULT']['SLACK_BOT_USER_ACCESS_TOKEN']
SLACK_APP_AUTH_TOKEN = config_ini['DEFAULT']['SLACK_APP_AUTH_TOKEN']
START_DATE = config_ini['DEFAULT']['START_DATE']
ADMIN_USER = config_ini['DEFAULT']['ADMIN_USER']
IFACE = config_ini['DEFAULT']['IFACE']
DEST_IP_ADDRESS = config_ini['DEFAULT']['DEST_IP_ADDRESS']
ICMP_TIMEOUT = config_ini['DEFAULT']['ICMP_TIMEOUT']
