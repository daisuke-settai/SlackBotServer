from scapy.all import *
import time
import MySQLdb
import logging
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import numpy
import make_table
import config

logging.basicConfig(level=logging.INFO)

TIME_SPAN = 6 # 6Hour

def get_existance_macaddresses():
    icmp_echo = IP(dst=config.DEST_IP_ADDRESS)/ICMP()
    sniffer = AsyncSniffer(iface=config.IFACE, filter="icmp[icmptype] == icmp-echoreply")
    sniffer.start()
    time.sleep(int(config.ICMP_TIMEOUT)) # snifferの準備を待つ
    send(icmp_echo)
    time.sleep(int(config.ICMP_TIMEOUT))
    ans = sniffer.stop()
    mac_address_list = []
    for packet in ans:
        logging.debug(packet.src)
        mac_address_list.append(packet.src)
    return mac_address_list


def get_existance_members_and_address():
    addresses = get_existance_macaddresses()
    if addresses == []:
        return {}
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    query = "SELECT u.name, m.mac_address FROM user u INNER JOIN macAddress m ON u.id = m.user_id WHERE m.mac_address IN " + str(addresses).replace('[', '(').replace(']',')')
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    mac_dict = {}
    for address in addresses:
        mac_dict[address] = ""
    if count > 0:
        rows = cursor.fetchall()
        for row in rows:
            mac_dict[row[1]] = row[0]
    connection.close()
    return mac_dict


def get_existance_members():
    addresses = get_existance_macaddresses()
    if addresses == []:
        return ()
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    query = "SELECT DISTINCT u.name FROM user u INNER JOIN macAddress m ON u.id = m.user_id WHERE m.mac_address IN " + str(addresses).replace('[', '(').replace(']',')') + "AND u.enable = true"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    if count > 0:
        rows = cursor.fetchall()
        connection.close()
        return rows
    else:
        connection.close()
        return ()

def register_mac_address(user, mac_list):
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    # User check
    query = f"SELECT id FROM user where name = '{user}'"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    user_id = 0
    if count == 0: # 新規ユーザ
        query = f"INSERT INTO user (name) values ('{user}')"
        MySQLdb.escape_string(query)
        logging.info(query)
        try:
            cursor.execute(query)
        except MySQLdb.Error as e:
            logging.error('MySQLdb.Error: Cannot add User')
            connection.close()
            return []
        connection.commit()
        query = f"SELECT id FROM user where name = '{user}'"
        MySQLdb.escape_string(query)
        logging.info(query)
        cursor.execute(query)
    user_id = cursor.fetchall()[0][0]
    logging.debug(f"id: {user_id}")
    success_list = []
    for mac in mac_list:
        query = f"INSERT INTO macAddress (user_id, mac_address) VALUES ({user_id}, '{mac}')"
        MySQLdb.escape_string(query)
        logging.info(query)
        try:
            cursor.execute(query)
        except MySQLdb.Error as e:
            logging.error(f"MySQLdb.Error: Cannot add mac: {mac}")
            continue
        success_list.append(mac)
    connection.commit()
    connection.close()
    return success_list


def get_members():
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    query = "SELECT name FROM user where enable = true"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    if count > 0:
        rows = cursor.fetchall()
        connection.close()
        return rows
    else:
        connection.close()
        return ()

def get_address(users):
    mac_list = {}
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    query = ""
    if users == []:
        query = "SELECT mac_address FROM macAddress"
    else:
        query = "SELECT m.mac_address, u.name FROM macAddress m INNER JOIN user u ON u.id = m.user_id where u.name IN " + str(users).replace('[', '(').replace(']', ')')
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    if count > 0:
        rows = cursor.fetchall()
        connection.close()
        logging.debug(rows)
        if users == []:
            mac_list['ALL'] = []
            for mac in rows:
                mac_list['ALL'].append(mac[0])
        else:
            for user in users:
                mac_list[user] = []
            for mac in rows:
                mac_list[mac[1]].append(mac[0])
        logging.debug(mac_list)
        return mac_list
    else:
        connection.close()
        return {}


def check_and_update_log():
    current_time = datetime.now()
    addresses = get_existance_macaddresses()
    if addresses == []:
        return []
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    # get new come member
    # 09/30 14:45なら09/30 00:00:00 - 09/30 23:59:59の時間帯, mac->user_idに変換でselect
    # {user.name}にメール送信
    today = current_time.strftime("%Y-%m-%d") + ' 00:00:00'
    tomorrow = (current_time + timedelta(1)).strftime('%Y-%m-%d') + ' 00:00:00'
    query = f"SELECT user_id FROM logData WHERE log_time >= '{today}' AND log_time < '{tomorrow}'"
    query2 = "SELECT m.user_id FROM macAddress m INNER JOIN user u ON m.user_id = u.id WHERE u.enable = true AND mac_address IN " + str(addresses).replace('[', '(').replace(']', ')')
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    logged_user_ids = []
    detect_user_ids = []
    if count > 0:
        rows = cursor.fetchall()
        for row in rows:
            logged_user_ids.append(row[0])
    MySQLdb.escape_string(query2)
    logging.info(query2)
    count = cursor.execute(query2)
    if count > 0:
        rows = cursor.fetchall()
        for row in rows:
            detect_user_ids.append(row[0])
    new_comming_user_ids = list(set(detect_user_ids) - set(logged_user_ids))
    new_comming_users = []
    if new_comming_user_ids != []:
        query = f"SELECT name from user where enable = true AND id IN " + str(new_comming_user_ids).replace('[', '(').replace(']', ')')
        MySQLdb.escape_string(query)
        logging.info(query)
        count = cursor.execute(query)
        if count > 0:
            rows = cursor.fetchall()
            for row in rows:
                new_comming_users.append(row[0])

    # ログを一時間単位で更新(14:00 ~ 14:59のログは1レコード)
    # 14:45なら14:00 ~ 14:59:49までの時間帯でselect mac->user_id
    from_time = current_time.strftime("%Y-%m-%d %H") + ':00:00'
    to_time = (current_time + timedelta(1/24)).strftime("%Y-%m-%d %H") + ':00:00'
    query = f"SELECT user_id, id FROM logData WHERE log_time >= '{from_time}' AND log_time < '{to_time}'"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    logged_user_dict = {} # {user_id: log_id}
    if count > 0:
        rows = cursor.fetchall()
        for row in rows:
            logged_user_dict[row[0]] = row[1]
    insert_user_ids = list(set(detect_user_ids) - set(logged_user_dict.keys()))
    update_user_ids = list(set(logged_user_dict.keys()) & set(detect_user_ids))

    if update_user_ids != []:
        query = f"UPDATE logData SET log_time = '{current_time.strftime('%Y-%m-%d %H:%M:%S')}' WHERE id IN " + str([logged_user_dict[user_id] for user_id in update_user_ids]).replace('[', '(').replace(']',')')
        MySQLdb.escape_string(query)
        logging.info(query)
        try:
            cursor.execute(query)
            connection.commit()
        except MySQLdb.Error as e:
            logging.error('MySQLdb.Error: Cannot update logData')

    if insert_user_ids != []:
        for user_id in insert_user_ids:
            query = f"INSERT INTO logData (user_id, log_time) VALUES ({user_id}, '{current_time.strftime('%Y-%m-%d %H:%M:%S')}')"
            MySQLdb.escape_string(query)
            logging.info(query)
            try:
                cursor.execute(query)
            except MySQLdb.Error as e:
                logging.error('MySQLdb.Error: Cannot insert logData')
        connection.commit()
    connection.close()
    return new_comming_users

# 先週のログデータをuserごとに集計し4x7の表画像にして出力
# IN: user nameリスト, OUT: {user_name: filename}
def make_log_table_lastweek(users, thisweek):
    output_files = {}
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    if thisweek == True:
        today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days = 7)
    else:
        today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    from_time = today - relativedelta(weeks=1) - timedelta(days = today.weekday())
    to_time = today - timedelta(days = today.weekday())
    query = ""
    logging.info(type(users))
    if users == []:
        query = f"SELECT u.name, l.log_time FROM logData l INNER JOIN user u ON u.id = l.user_id WHERE u.enable = true AND l.log_time >= '{from_time.strftime('%Y-%m-%d %H:%M:%S')}' AND l.log_time < '{to_time.strftime('%Y-%m-%d %H:%M:%S')}' ORDER BY u.name, l.log_time"
    else:
        query = f"SELECT u.name, l.log_time FROM logData l INNER JOIN user u ON u.id = l.user_id WHERE u.enable = true AND u.name IN " + str(users).replace('[', '(').replace(']', ')') + f" AND l.log_time >= '{from_time.strftime('%Y-%m-%d %H:%M:%S')}' AND l.log_time < '{to_time.strftime('%Y-%m-%d %H:%M:%S')}' ORDER BY u.name, l.log_time"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    log_dict = {} # {user_name: [log_time,...]}
    if count > 0:
        rows = cursor.fetchall()
        for row in rows:
            if row[0] not in log_dict:
                log_dict[row[0]] = []
            log_dict[row[0]].append(row[1])
    else:
        return {}

    for user_name, log_times in log_dict.items():
        log_array = numpy.zeros((int(24 / TIME_SPAN), 7, 3)) # [[0:00-6:00, 6:00-12:00, 12:00-18:00, 18:00-24:00], ...] # len: 7
        for time in log_times:
            hour = int(time.strftime('%H'))
            log_array[int(hour / TIME_SPAN)][time.weekday()] += 1
        title = f"{user_name} ({from_time.strftime('%Y/%m/%d')}-{(to_time - timedelta(days=1)).strftime('%Y/%m/%d')})"
        filepath = make_table.make_table_oneweek(log_array, user_name, TIME_SPAN, title)
        if len(filepath) != 0:
            output_files[user_name] = filepath
    return output_files


# 指定の期間のログデータをuserごとに集計し4x7の表画像にして出力
# IN: user nameリスト, from_time, to_time, OUT: {user_name: filename}
# from_time, to_time: 2019/09/30
# TODO: 色合いの調整を専用のmake_table内の関数で実施
def make_log_table(from_time_str, to_time_str, users):
    output_files = {}
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    try: # server.pyでもチェック
        from_time = datetime.strptime(from_time_str, "%Y/%m/%d")
        to_time = datetime.strptime(to_time_str, "%Y/%m/%d") + timedelta(days = 1)
    except ValueError as e:
        logging.error("from_time, to_time error: " +  str(e))
        return {}
    query = ""
    logging.info(type(users))
    if users == []:
        query = f"SELECT u.name, l.log_time FROM logData l INNER JOIN user u ON u.id = l.user_id WHERE u.enable = true AND l.log_time >= '{from_time.strftime('%Y-%m-%d %H:%M:%S')}' AND l.log_time < '{to_time.strftime('%Y-%m-%d %H:%M:%S')}' ORDER BY u.name, l.log_time"
    else:
        query = f"SELECT u.name, l.log_time FROM logData l INNER JOIN user u ON u.id = l.user_id WHERE u.enable = true AND u.name IN " + str(users).replace('[', '(').replace(']', ')') + f" AND l.log_time >= '{from_time.strftime('%Y-%m-%d %H:%M:%S')}' AND l.log_time < '{to_time.strftime('%Y-%m-%d %H:%M:%S')}' ORDER BY u.name, l.log_time"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    log_dict = {} # {user_name: [log_time,...]}
    if count > 0:
        rows = cursor.fetchall()
        for row in rows:
            if row[0] not in log_dict:
                log_dict[row[0]] = []
            log_dict[row[0]].append(row[1])
    else:
        return {}

    for user_name, log_times in log_dict.items():
        start_day = 0
        max_level = 0
        active_days = 0
        prev_day = datetime.now() + timedelta(days = 1) # 明日のログはない
        log_array = numpy.zeros((int(24 / TIME_SPAN), 7, 3)) # [[0:00-6:00, 6:00-12:00, 12:00-18:00, 18:00-24:00], ...] # len: 7
        for time in log_times:
            hour = int(time.strftime('%H'))
            log_array[int(hour / TIME_SPAN)][time.weekday()] += 1
            if log_array[int(hour / TIME_SPAN)][time.weekday()][0] > max_level:
                max_level = log_array[int(hour / TIME_SPAN)][time.weekday()][0]
            if prev_day.date() != time.date():
                active_days += 1
                prev_day = time
            if start_day == 0 and from_time == datetime.strptime(config.START_DATE, "%Y/%m/%d"):
                start_day = time
        if start_day == 0:
            title = f"{user_name} ({from_time.strftime('%Y/%m/%d')}-{(to_time - timedelta(days=1)).strftime('%Y/%m/%d')})"
        else:
            title = f"{user_name} ({start_day.strftime('%Y/%m/%d')}-{(to_time - timedelta(days=1)).strftime('%Y/%m/%d')})"
        subtitle = f"active: {active_days}days"
        filepath = make_table.make_table(log_array, user_name, max_level, [title, subtitle])
        if len(filepath) != 0:
            output_files[user_name] = filepath
    return output_files

def get_blank_span(user_name):
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    query = f"SELECT l.log_time FROM logData l INNER JOIN user u ON u.id = l.user_id WHERE u.name = '{user_name}' ORDER BY l.log_time DESC LIMIT 1"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    if count > 0:
        rows = cursor.fetchall()
        last_date = rows[0][0]
    else:
        return 0
    today = datetime.today()
    return (today.date() - last_date.date()).days


def get_blank_span_ignore_just_before(user_name):
    connection = MySQLdb.connect(host='localhost', user='root', passwd=config.DB_PASSWD, db=config.DB_NAME, charset='utf8mb4')
    cursor = connection.cursor()
    query = f"SELECT l.log_time FROM logData l INNER JOIN user u ON u.id = l.user_id WHERE u.name = '{user_name}' ORDER BY l.log_time DESC LIMIT 2"
    MySQLdb.escape_string(query)
    logging.info(query)
    count = cursor.execute(query)
    if count > 0:
        rows = cursor.fetchall()
        last_date = rows[1][0]
    else:
        return 0
    today = datetime.today()
    return (today.date() - last_date.date()).days
