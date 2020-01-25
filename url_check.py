import requests
from datetime import datetime
from fake_useragent import UserAgent

def web_check():
    ua = UserAgent()
    header = {'user-agent': ua.random}
    print(header)
    try:
        with open("urls.txt", "r") as f:
            for url in f:
                page = requests.get(url.strip(), headers=header)
                if page.status_code == requests.codes.ok:
                    response_time = page.elapsed.total_seconds()
                    time_stamp = datetime.now()
                    print("URL: {0} is reachable with code: {1} and total time elapsed: {2} sec".format(url.strip(), page.status_code, response_time))
                    print(time_stamp)
                else:
                    print("URL: {0} is NOT reachable with code: {1}".format(url.strip(), page.status_code))
                    print(time_stamp)
    except requests.exceptions.RequestException as e:
        print(e)

web_check()
