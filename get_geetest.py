import random
import time

import requests
from hashlib import md5
import execjs

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36',
}

se = requests.session()


def get_md5_val(r):
    hs = md5()
    hs.update(r.encode())
    return hs.hexdigest()


def get_distance(r1, r2):
    m_r1 = get_md5_val(r1)
    m_r2 = get_md5_val(r2)
    return exec_js('getDistance', m_r1, m_r2)


def exec_js(fun_name, *params):
    with open('gt.js', 'r') as f:
        f_content = f.read()

    js_obj = execjs.compile(f_content)
    return js_obj.call(fun_name, *params)


def get_challenge():
    time_stamp = str(int(time.time() * 1000))
    url = 'http://xwqy.gsxt.gov.cn/pc-geetest/register?t={}'.format(time_stamp)
    res = se.get(url, headers=headers)
    print(res.text)
    print(res.cookies)
    return res.json()['challenge']


def get_validate():
    challenge = get_challenge()
    r1 = get_random(6)
    r2 = get_random(300)
    distance = get_distance(str(r1), str(r2))
    validate = exec_js('enAll', distance, r1, r2, challenge)
    return do_validate(challenge, validate)


def do_validate(challenge, validate):
    url = 'http://xwqy.gsxt.gov.cn/pc-geetest/validate'
    data = {
        'geetest_challenge': challenge,
        'geetest_validate': validate,
        'geetest_seccode': '{}|jordan'.format(validate)
    }
    r = se.post(url=url, headers=headers, data=data)
    print(r.status_code)
    return r.text


def get_random(int_range):
    return int(random.random() * int_range)


if __name__ == '__main__':
    v = get_validate()
    print(v)
