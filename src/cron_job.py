import check
import server
import logging
from datetime import datetime
import random
import config

logging.basicConfig(level=logging.INFO)

def cron_job():
    # check_and_update_logでユーザのログテーブルを更新し, today_new_comingテーブルによって今日初めてのロギングならリストで返す
    new_comimg_members = check.check_and_update_log()
    logging.info(f"new_comimg_members: {new_comimg_members}")
    if new_comimg_members != []:
        msg = ""
        for member in new_comimg_members:
            msg += f"{member}, "
        if msg == 'jacky, ':
            days = check.get_blank_span_ignore_just_before('jacky')
            msg = jacky_msg(days)
        else:
            msg = msg[:-2] + "が来たよ！"
        server.post_message_to_slack_channel(message=msg, channel=config.CHANNEL)

def jacky_msg(days):
    msg = 'jacky参上！！！'
    if days == 1:
        msg_list = [ "\n今日も来てくれたんだね！", "\n今日も研究頑張ろう！"]
        msg += random.choice(msg_list)
    if days == 2:
        msg += "\n昨日は来てくれなかったよね..."
    elif days == 3:
        weekday = datetime.today().weekday()
        if weekday in [5, 6]:
            msg += "\n2日ぶりだね．土日は何してたの？？"
            msg += "\n(研究進んだ？)"
        else:
            msg += "\n昨日も一昨日も来てくれないなんて..."
    elif days > 3:
        msg += f"\n{days - 1}日ぶりだね..."
    return msg

if __name__ == '__main__':
    cron_job()
