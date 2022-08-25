import requests
import bs4
import re

page_response = requests.get("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
                             headers={"User-Agent": "curl/7.71.1", "Accept": "*/*"})

soup = bs4.BeautifulSoup(page_response.text, 'html.parser')

possible_dl_urls = list()
for m in re.findall(r'(https://download.microsoft.com/download/[a-zA-Z0-9\-/]*/ServiceTags_Public_\d+\.json)', str(soup)):
    possible_dl_urls.append(m)

possible_dl_urls = set(possible_dl_urls)

if len(possible_dl_urls) == 1:
    dl_response = requests.get(list(possible_dl_urls)[0])

print(dl_response.json())
#{url:"https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20220822.json
