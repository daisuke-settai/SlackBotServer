from flask import Flask, render_template, request, make_response
from datetime import datetime
import requests
import json
import logging
import hmac
import hashlib
import time
import urllib
import re
import schedule
import multiprocessing as mp

import config
import check # TODO: 名前変更

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_folder=f"{config.APP_ROOT_PATH}/static", static_url_path='')

#@app.route('/')
# def home():
#  return app.send_static_file('index.html')

@app.route('/SampleBot', methods=['POST'])
def samplebot():
    headers = json.loads(json.dumps({k: request.headers[k] for k in request.headers.keys()}))
    logging.debug(f"\n<RECV_HEADER>\n{json.dumps(headers)}")
    logging.debug(f"\n<RECV_DATA>\n{request.data.decode()}")

    assert 'X-Slack-Request-Timestamp' in headers
    assert 'X-Slack-Signature' in headers
    if slack_verify_requests(
            X_Slack_Request_Timestamp=headers['X-Slack-Request-Timestamp'],
            body=request.data.decode(),
            X_Slack_Signature=headers['X-Slack-Signature']):
        logging.debug('Verified')
    else:
        logging.error('Fail to X-Slack-Signature\'s verifying')
        return 'FAIL' # TODO: エラーコードに修正

    if request.mimetype == 'application/json':
        json_data = json.loads(request.data.decode())
        if 'token' not in json_data or json_data['token'] != config.SLACK_APP_AUTH_TOKEN:
            logging.error('Not match with token')
            return 'FAIL'
        assert "type" in json_data
        if json_data["type"] == "url_verification":
            logging.info('url_verification')
            return send_challenge_msg(json_data)
        elif json_data["type"] == "event_callback":
            logging.info('event_callback\n')
            worker = mp.Process(target=send_event_callback_response, args=(json_data,))
            worker.start()
            return 'Processing'
            # return send_event_callback_response(json_data)
        else:
            logging.warning(f"Unknown Type: {json_data['type']}")
            return 'Unkoen Type'

    return 'FAIL'


# @app.route('/echo/<thing>/<place>')
# def echo(thing, place):
#     kwargs = {}
#     kwargs['text'] = request.args.get('text')
#     kwargs['text1'] = request.args.get('text1')
#     kwargs['thing'] = thing
#     kwargs['place'] = place
#     return render_template('flask2.html', **kwargs)


def send_challenge_msg(json_data):
    if "challenge" in json_data:
        resp = make_response(json_data['challenge'])
        resp.headers['Content-Type'] = 'text/plain'
        return resp
    else:
        logging.warning("Challenge Info is not found.")


def slack_verify_requests(X_Slack_Request_Timestamp: str, body: str, X_Slack_Signature: str):
    # The request timestamp is more than five minutes from local time.
    # It could be a replay attack, so let's ignore it.
    if time.time() - int(X_Slack_Request_Timestamp) > 60 * 5:
        logging.error(f'Replay Attack: {time.time() - int(X_Slack_Request_Timestamp)}s')
        return False

    base_string = "v0:" + X_Slack_Request_Timestamp + ":" + body
    hmac_msg = hmac.new(config.SIGNING_SECRET.encode('ascii'), base_string.encode('ascii'), hashlib.sha256)
    signature = "v0=" + hmac_msg.hexdigest()
    return hmac.compare_digest(signature, X_Slack_Signature)


def send_event_callback_response(json_data: dict):
    if 'event' not in json_data:
        logging.warning('Unknown event_callback')
        return 'FAIL'
    event = json_data['event']
    if 'type' not in event:
        logging.warning('Unknown format in event_callback')
        return 'FAIL'

    if event['type'] == 'app_mention':
        return process_app_mention(event)
    else:
        logging.warning(f"Not Implemented with {event['type']} in event_callback")
        return 'FAIL'

    return 'FAIL'
    # return post_message_to_slack_channel("Hello, Slack Bot!", json_data["event"]["channel"])


def process_app_mention(event: dict):
    if 'text' not in event:
        logging.warning('process_app_mention: event does not have a text')
        return 'FAIL'
    if 'user' not in event:
        logging.warning('process_app_mention: event does not have a user')
        return 'FAIL'
    request_user = event['user']
    for text in event['text'].split('\n'):
        logging.info(f"REQUEST_TEXT: {text}")
        if re.match('.*<@[A-Z0-9]*>', text):
            text = re.sub('.*<@[A-Z0-9]*>[\ |\t]*', '', text)
        else:
            continue

        if re.match('いる', text):
            # 現在ラボにいるメンバーを表示(最終時刻とともに表示)
            logging.info('CONTEXT: いる')
            members = check.get_existance_members()
            msg = ""
            for member in members:
                logging.debug(member[0])
                msg += f"{member[0]}, "
            if len(msg) > 0:
                msg = msg[:-2] + "がいるよ:)"
            else:
                msg = "今は誰もいないような気がするよ; (・_・、) \n(もしかしたら寝てるだけかも)"
            return post_message_to_slack_channel(msg, event['channel'])
        elif re.match('\(いる', text) and request_user == config.ADMIN_USER:
            # 現在ラボにいるメンバーを表示
            logging.info('CONTEXT: (いる')
            mac_dict = check.get_existance_members_and_address()
            msg = "```\n"
            for mac in mac_dict:
                if mac_dict[mac] == "":
                    msg += f"{mac}\n"
                else:
                    msg += f"{mac}, {mac_dict[mac]}\n"
            msg += "```"
            if len(msg) == 7:
                msg = "今は誰もいないような気がするよ; (・_・、) \n(もしかしたら寝てるだけかも)"
            return post_message_to_slack_channel(msg, event['channel'])
        elif re.match('参加', text):
            # システムに追加
            # format: '参加' login-name mac-address-list
            logging.info('CONTEXT: 参加')
            elems = text.split()
            if len(elems) < 3:
                msg = "引数が足りないよ．空白で区切って名前とアドレスを教えてね．"
                return post_message_to_slack_channel(msg, event['channel'])
            user_name = elems[1]
            mac_address_list = []
            error_list = []
            for mac in elems[2:]:
                if not re.match('([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                    error_list.append(mac)
                else:
                    mac_address_list.append(mac)
            if mac_address_list == []:
                msg = "正しいMACアドレスを教えて欲しいな．\nこの辺の入力がよくわからないなぁ．\n"
                msg += "```\n"
                for mac in error_list:
                    msg += f"- {mac}\n"
                msg += "```"
                return post_message_to_slack_channel(msg, event['channel'])
            success_list = check.register_mac_address(user=user_name, mac_list=mac_address_list)
            fail_list = list(set(mac_address_list) - set(success_list))
            if success_list == []:
                msg = "この辺のMACアドレスは正しかったけどなんか登録できなかったよ．\n"
                msg += "```\n"
                for mac in mac_address_list:
                    msg += f"- {mac}\n"
                msg += "```\n"
                if error_list != []:
                    msg += "それと，この辺は入力値がおかしい気がするよ\n"
                    msg += "```\n"
                    for mac in error_list:
                        msg += f"- {mac}\n"
                    msg += "```"
                return post_message_to_slack_channel(msg, event['channel'])
            msg = f"{user_name} にこの辺のMACアドレスを結びつけたよ．\n"
            msg += "```\n"
            for mac in success_list:
                msg += f"- {mac}\n"
            msg += "```\n"
            if fail_list != []:
                msg += "この辺のMACアドレスの登録は失敗しちゃった...\n"
                msg += "もしかしたらもう登録されているのかも\n"
                msg += "```\n"
                for mac in fail_list:
                    msg += f"- {mac}\n"
                msg += "```\n"
            if error_list != []:
                msg += "この辺は入力値がおかしい気がするよ\n"
                msg += "```\n"
                for mac in error_list:
                    msg += f"- {mac}\n"
                msg += "```"
            return post_message_to_slack_channel(msg, event['channel'])
        elif re.match('脱退', text):
            # システムにおいて表示と新規のログ取得を無効化
            # format: '脱退 login-name [mac-addresses]'
            # mac-addressがない場合: 全てのmacアドレスを無効化
            logging.info('CONTEXT: 脱退')
            return post_message_to_slack_channel("まだまだ使えないよーーーー", event['channel'])
        elif re.match('先週', text):
            # いい感じのグラフにしてこれまでのログを表示
            # format: 'show_log [user]'
            # userがない場合は全員
            logging.info('CONTEXT: 先週')
            elems = text.split()
            users = []
            if len(elems) > 1:
                users = list(set(elems[1:]))
            pict_dict = check.make_log_table_lastweek(users, False)
            for user, filepath in pict_dict.items():
                logging.info(f"send {user}")
                msg = f"{user}の先週"
                post_file_to_slack_channel(filepath, event['channel'], msg)
            return 'OK'
        elif re.match('show_log', text):
            # いい感じのグラフにしてこれまでのログを表示
            # format: 'show_log [from_time~to_time] [users]'
            # userがない場合は全員
            logging.info('CONTEXT: show_log')
            elems = text.split()
            users = []
            from_time = 0
            to_time = 0
            if len(elems) > 1:
                if '~' in elems[1]:
                    time_array = elems[1].split('~')
                    if time_array[0] == '':
                        from_time = datetime.strptime(config.START_DATE, "%Y/%m/%d")
                    else:
                        try:
                            from_time = datetime.strptime(time_array[0], "%Y/%m/%d")
                        except ValueError as e:
                            logging.warning('show_log: ' + str(e))
                            msg = "期間の指定が誤っている気がするよ..."
                            post_message_to_slack_channel(msg, event['channel'])
                            return 'FAIL'
                    if time_array[1] == '':
                        to_time = datetime.today().date()
                    else:
                        try:
                            to_time = datetime.strptime(time_array[1], "%Y/%m/%d")
                        except ValueError as e:
                            logging.warning('show_log: ' + str(e))
                            msg = "期間の指定が誤っている気がするよ..."
                            post_message_to_slack_channel(msg, event['channel'])
                            return 'FAIL'
                    users = elems[2:]
                else:
                    users = elems[1:]
            else:
                users = []
            if from_time == 0:
                pict_dict = check.make_log_table_lastweek(users, True)
            else:
                pict_dict = check.make_log_table(from_time.strftime("%Y/%m/%d"), to_time.strftime("%Y/%m/%d"), users)
            for user, filepath in pict_dict.items():
                logging.info(f"send {user}")
                msg = f"{user}のログ"
                post_file_to_slack_channel(filepath, event['channel'], msg)
            return 'OK'
        elif re.match('メンバーリスト', text):
            logging.info('CONTEXT: メンバーリスト')
            member_list = check.get_members()
            if member_list == []:
                msg = "誰も参加してないよ..."
                return post_message_to_slack_channel(msg, event['channel'])
            msg = "参加者一覧はこんな感じだよー\n"
            msg += "```\n"
            for member in member_list:
                msg += f"- {member[0]}\n"
            msg += "```"
            return post_message_to_slack_channel(msg, event['channel'])
        elif re.match('MACアドレスリスト', text):
            logging.info('CONTEXT: MACアドレスリスト')
            elems = text.split()
            users = []
            if len(elems) > 1:
                users = list(set(elems[1:]))
            mac_list = check.get_address(users)
            if mac_list == {}:
                msg = "MACアドレスは登録されていないよ\n"
                return post_message_to_slack_channel(msg, event['channel'])
            msg = "登録ずみのMACアドレスはこんな感じだよ\n"
            msg += "```\n"
            for user in mac_list:
                msg += f"- {user}\n"
                for mac in mac_list[user]:
                    msg += f"\t- {mac}\n"
            msg += "```"
            return post_message_to_slack_channel(msg, event['channel'])
    msg = """
```
<コマンド一覧>
 - いる？: 現在ラボにいるメンバーを表示
 - 参加 <user name> <mac address>: メンバーを追加
 - メンバーリスト: 有効なメンバー一覧を表示
 - MACアドレスリスト [user name]：MACアドレス一覧を表示
 - 先週どうだった？ [user name]: 先週のログを表示(月~日)
    * 0:00-6:00, 6:00-12:00, 12:00-18:00, 18:00-24:00でいる時間によって濃淡表示
 - show_log [start~end] [user name]: start ~ endの期間のuserのログを表示
    * e.g., show_log 2019/09/30~2019/10/6 user_name
    * 期間省略で今週のログを表示
    * ユーザごとによくいた時間帯をもとに正規化して濃淡表示
```
 ~(いる？): 生活線にいるマシンのアドレス一覧を表示~
    """
#  - 脱退 <user name> [mac addresses]: メンバーを無効化(近日実装)
    return post_message_to_slack_channel(msg, event['channel'])


def post_message_to_slack_channel(message: str, channel: str):
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "Authorization": f"Bearer {config.SLACK_BOT_USER_ACCESS_TOKEN}"
    }
    data = {
        "token": config.SLACK_APP_AUTH_TOKEN,
        "channel": channel,
        "text": message,
        "username": "Bot-Sample"
    }
    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), method="POST", headers=headers)
    urllib.request.urlopen(req)
    return 'OK'


def post_file_to_slack_channel(file_path: str, channel: str, msg: str):
    filename = re.sub('.*/', '', file_path)
    files = {'file': open(file_path, 'rb')}
    param = {
            'token':config.SLACK_BOT_USER_ACCESS_TOKEN,
            'channels':channel,
            'filename':filename,
            'initial_comment': msg
            }
    requests.post(url="https://slack.com/api/files.upload",params=param, files=files)
    return 'OK'


if __name__ == '__main__':
    logging.info('start server')
    app.run(host='0.0.0.0', port=443, ssl_context=(config.FULLCHAIN_FILE, config.KEY_FILE), threaded=True)
